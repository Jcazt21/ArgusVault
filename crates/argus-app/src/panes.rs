//! The settings and generator panes, and switching between the right-hand panes.

use std::path::Path;

use argus_core::generator::{
    generate_passphrase, generate_password, PassphraseOptions, PasswordOptions,
};
use argus_core::{Credentials, Error, Settings, UnlockedVault};
use slint::{ComponentHandle, SharedString};
use zeroize::Zeroizing;

use crate::ui::MainWindow;
use crate::vault_view::{clear_form, refresh_list};
use crate::{copy_text, is_rekeying, pick_file, user_message, with_session, Pick, REKEY_BUSY};

/// Right-hand pane ids, as used by `pane` in `main.slint`.
const PANE_DETAIL: i32 = 0;
const PANE_EDITOR: i32 = 1;
const PANE_SETTINGS: i32 = 2;
const PANE_GENERATOR: i32 = 3;

/// Switch the right-hand pane, forgetting whatever secrets the pane being left was holding. The
/// editor survives a trip to the generator and back, because the generated password is meant for it.
pub(crate) fn leave_pane(ui: &MainWindow, to: i32) {
    let from = ui.get_pane();
    if from == PANE_EDITOR && to != PANE_EDITOR && to != PANE_GENERATOR {
        clear_form(ui);
    }
    if from == PANE_SETTINGS && to != PANE_SETTINGS {
        clear_credential_fields(ui);
    }
    if from == PANE_GENERATOR && to != PANE_GENERATOR {
        if ui.get_gen_for_form() && to != PANE_EDITOR {
            clear_form(ui);
        }
        clear_generator(ui);
    }
    ui.set_pane(to);
}

// ---------------------------------------------------------------- settings

pub(crate) fn clear_credential_fields(ui: &MainWindow) {
    ui.set_cred_current(SharedString::new());
    ui.set_cred_current_keyfile(SharedString::new());
    ui.set_cred_new(SharedString::new());
    ui.set_cred_confirm(SharedString::new());
    ui.set_cred_new_keyfile(SharedString::new());
    ui.set_settings_error(SharedString::new());
    ui.set_settings_message(SharedString::new());
    ui.set_strength_score(0);
    ui.set_strength_label(SharedString::new());
}

pub(crate) fn open_settings(ui: &MainWindow) {
    leave_pane(ui, PANE_SETTINGS);
    with_session(|s| s.editing = None);
    clear_credential_fields(ui);
    let current = with_session(|s| (s.vault.vault.settings, s.keyfile.clone()));
    if let Some((settings, keyfile)) = current {
        ui.set_settings_autolock(settings.auto_lock_secs.to_string().into());
        ui.set_settings_clipboard(settings.clipboard_clear_secs.to_string().into());
        ui.set_settings_lock_min(settings.lock_on_minimize);
        ui.set_cred_current_keyfile(keyfile.into());
        ui.set_cred_new_keyfile(ui.get_cred_current_keyfile());
    }
    ui.set_pane(PANE_SETTINGS);
}

fn parse_secs(text: &str, name: &str) -> Result<u32, String> {
    text.trim().parse::<u32>().map_err(|_| format!("{name} must be a whole number of seconds."))
}

pub(crate) fn save_settings(ui: &MainWindow) {
    ui.set_settings_message(SharedString::new());
    ui.set_settings_error(SharedString::new());
    if is_rekeying() {
        ui.set_settings_error(REKEY_BUSY.into());
        return;
    }
    let parsed = parse_secs(&ui.get_settings_autolock(), "The lock time").and_then(|auto| {
        parse_secs(&ui.get_settings_clipboard(), "The clipboard time").map(|clip| Settings {
            auto_lock_secs: auto,
            clipboard_clear_secs: clip,
            lock_on_minimize: ui.get_settings_lock_min(),
        })
    });
    let settings = match parsed {
        Ok(s) => s,
        Err(message) => return ui.set_settings_error(message.into()),
    };
    if let Err(e) = settings.validate() {
        return ui.set_settings_error(user_message(&e).into());
    }
    let result = with_session(|s| -> Result<(), Error> {
        let before = std::mem::replace(&mut s.vault.vault.settings, settings);
        if let Err(err) = s.save() {
            s.vault.vault.settings = before;
            return Err(err);
        }
        Ok(())
    });
    match result {
        Some(Ok(())) => ui.set_settings_message("Settings saved.".into()),
        Some(Err(e)) => ui.set_settings_error(user_message(&e).into()),
        None => {}
    }
}

/// Pick a keyfile for the settings form: `0` = the current keyfile, `1` = the new one.
pub(crate) fn browse_cred_keyfile(ui: &MainWindow, which: i32) {
    match pick_file(ui, Pick::Keyfile, false) {
        Ok(Some(path)) => {
            let shown: SharedString = path.to_string_lossy().as_ref().into();
            if which == 0 {
                ui.set_cred_current_keyfile(shown);
            } else {
                ui.set_cred_new_keyfile(shown);
            }
        }
        Ok(None) => {}
        Err(_) => ui.set_settings_error("Could not open the file dialog.".into()),
    }
}

fn credentials(password: Zeroizing<String>, keyfile: &str) -> Result<Credentials, Error> {
    if keyfile.trim().is_empty() {
        Ok(Credentials::new(password))
    } else {
        Credentials::with_keyfile(password, Path::new(keyfile.trim()))
    }
}

/// Change the master password and/or keyfile. The slow key derivation runs on a worker thread
/// that opens the vault file with the *current* credentials (which also verifies them) and
/// re-keys that copy; the result then replaces the in-memory vault. Edits are refused meanwhile.
pub(crate) fn change_credentials(ui: &MainWindow) {
    ui.set_settings_message(SharedString::new());
    ui.set_settings_error(SharedString::new());
    let current = Zeroizing::new(ui.get_cred_current().to_string());
    let new = Zeroizing::new(ui.get_cred_new().to_string());
    let confirm = Zeroizing::new(ui.get_cred_confirm().to_string());
    let current_keyfile = ui.get_cred_current_keyfile().to_string();
    let new_keyfile = ui.get_cred_new_keyfile().to_string();

    if current.is_empty() {
        return ui.set_settings_error("Enter the current master password.".into());
    }
    if new.as_str() != confirm.as_str() {
        return ui.set_settings_error("The two new passwords do not match.".into());
    }
    let started = with_session(|s| {
        if s.rekeying {
            return None;
        }
        s.rekeying = true;
        s.file_lock.release();
        Some((s.id, s.vault.path().to_path_buf()))
    })
    .flatten();
    let Some((session_id, path)) = started else {
        return ui.set_settings_error(REKEY_BUSY.into());
    };
    // The passwords are in the worker's hands now; do not leave them in the fields.
    ui.set_cred_current(SharedString::new());
    ui.set_cred_new(SharedString::new());
    ui.set_cred_confirm(SharedString::new());
    ui.set_strength_score(0);
    ui.set_strength_label(SharedString::new());
    ui.set_settings_busy(true);

    let weak = ui.as_weak();
    let keyfile_after = new_keyfile.trim().to_owned();
    std::thread::spawn(move || {
        let result = rekey(&path, current, &current_keyfile, new, &new_keyfile);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                finish_rekey(&ui, session_id, result, keyfile_after);
            }
        });
    });
}

fn rekey(
    path: &Path,
    current: Zeroizing<String>,
    current_keyfile: &str,
    new: Zeroizing<String>,
    new_keyfile: &str,
) -> Result<(UnlockedVault, bool), String> {
    let old_creds = credentials(current, current_keyfile).map_err(|e| user_message(&e))?;
    crate::ensure_memory_for_file(path)?;
    let mut vault = UnlockedVault::open(path, &old_creds).map_err(|e| {
        if e.is_unlock_failure() {
            "The current password or keyfile is wrong.".to_owned()
        } else {
            user_message(&e)
        }
    })?;
    drop(old_creds);
    let new_creds = credentials(new, new_keyfile).map_err(|e| user_message(&e))?;
    let calibration = crate::kdf_for_this_machine();
    vault.change_credentials(&new_creds, calibration.params).map_err(|e| user_message(&e))?;
    Ok((vault, calibration.reduced))
}

fn finish_rekey(
    ui: &MainWindow,
    session_id: u64,
    result: Result<(UnlockedVault, bool), String>,
    keyfile: String,
) {
    ui.set_settings_busy(false);
    // Only the session that started the job may take its result; a vault that was locked in the
    // meantime has already dropped everything and the new credentials simply apply at next unlock.
    let outcome = with_session(|s| {
        if s.id != session_id {
            return None;
        }
        s.rekeying = false;
        // Protect the (re-keyed) file again. If another program has it open right now, the
        // periodic check keeps trying and tells the user.
        let _ = s.file_lock.reacquire();
        Some(match result {
            Ok((vault, reduced)) => {
                s.vault = vault;
                s.keyfile = keyfile;
                Ok(reduced)
            }
            Err(message) => Err(message),
        })
    })
    .flatten();
    match outcome {
        Some(Ok(reduced)) => {
            ui.set_cred_current_keyfile(ui.get_cred_new_keyfile());
            let mut message = "Master password and keyfile changed.".to_owned();
            if reduced {
                message.push_str(
                    " This computer has little free memory, so the key protection is weaker \
                     than usual: change the password again later with more memory free.",
                );
            }
            ui.set_settings_message(message.into());
        }
        Some(Err(message)) => ui.set_settings_error(message.into()),
        None => {}
    }
}

// --------------------------------------------------------------- generator

pub(crate) fn clear_generator(ui: &MainWindow) {
    ui.set_gen_result(SharedString::new());
    ui.set_gen_entropy(SharedString::new());
    ui.set_gen_error(SharedString::new());
    ui.set_gen_for_form(false);
}

pub(crate) fn open_generator(ui: &MainWindow, for_form: bool) {
    if !for_form {
        with_session(|s| s.editing = None);
    }
    leave_pane(ui, PANE_GENERATOR);
    ui.set_status(SharedString::new());
    ui.set_gen_for_form(for_form);
    ui.set_pane(PANE_GENERATOR);
    regenerate(ui);
}

/// Roll a new value from the options currently set in the window.
pub(crate) fn regenerate(ui: &MainWindow) {
    if ui.get_pane() != PANE_GENERATOR {
        return;
    }
    let generated = if ui.get_gen_mode() == 0 {
        let opts = PasswordOptions {
            length: usize::try_from(ui.get_gen_length()).unwrap_or(24),
            lowercase: ui.get_gen_lower(),
            uppercase: ui.get_gen_upper(),
            digits: ui.get_gen_digits(),
            symbols: ui.get_gen_symbols(),
            exclude_ambiguous: ui.get_gen_ambiguous(),
        };
        if opts.lowercase || opts.uppercase || opts.digits || opts.symbols {
            generate_password(&opts).map(|p| (p, opts.entropy_bits())).map_err(|e| e.to_string())
        } else {
            Err("Turn on at least one kind of character.".to_owned())
        }
    } else {
        let opts = PassphraseOptions {
            words: usize::try_from(ui.get_gen_words()).unwrap_or(6),
            separator: ui.get_gen_separator().chars().next().unwrap_or('-'),
            capitalize: ui.get_gen_capitalize(),
            include_number: ui.get_gen_number(),
        };
        generate_passphrase(&opts).map(|p| (p, opts.entropy_bits())).map_err(|e| e.to_string())
    };
    ui.set_status(SharedString::new());
    match generated {
        Ok((value, bits)) => {
            ui.set_gen_error(SharedString::new());
            ui.set_gen_result(value.as_str().into());
            ui.set_gen_entropy(format!("About {bits:.0} bits of entropy").into());
        }
        Err(message) => {
            ui.set_gen_result(SharedString::new());
            ui.set_gen_entropy(SharedString::new());
            ui.set_gen_error(message.into());
        }
    }
}

/// Hand the generated password to the editor.
pub(crate) fn use_generated(ui: &MainWindow) {
    let value = Zeroizing::new(ui.get_gen_result().to_string());
    if value.is_empty() {
        return;
    }
    ui.set_form_password(value.as_str().into());
    leave_pane(ui, PANE_EDITOR);
    ui.set_pane(PANE_EDITOR);
}

pub(crate) fn copy_generated(ui: &MainWindow) {
    let value = Zeroizing::new(ui.get_gen_result().to_string());
    if !value.is_empty() {
        copy_text(ui, &value, "Password");
    }
}

pub(crate) fn close_generator(ui: &MainWindow) {
    let back_to = if ui.get_gen_for_form() { PANE_EDITOR } else { PANE_DETAIL };
    leave_pane(ui, back_to);
    ui.set_pane(back_to);
    if back_to == PANE_DETAIL {
        // The list keeps its selection; show it again.
        refresh_list(ui);
    }
}
