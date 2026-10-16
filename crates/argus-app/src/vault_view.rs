//! The vault view: entry list, detail pane, editor, authenticator countdown and import.

use std::time::Duration;

use argus_core::import::{self, Format};
use argus_core::search::search_kind;
use argus_core::{Entry, EntryId, EntryKind, Error};
use slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel};
use zeroize::Zeroizing;

use crate::icons;
use crate::ui::{EntryRow, MainWindow};
use crate::{copy_text, is_rekeying, pick_file, user_message, with_session, Pick, REKEY_BUSY};

/// How long a revealed password or notes stay on screen without the user doing anything.
const REVEAL_SECS: u64 = 10;

thread_local! {
    static SECRETS_TIMER: Timer = Timer::default();
}

// -------------------------------------------------------------------- list

/// Non-secret text for the second line of a list row.
fn subtitle(e: &Entry) -> String {
    match (e.kind, e.username.is_empty()) {
        (EntryKind::Server, false) => format!("{} · {}", e.host, e.username),
        (EntryKind::Server, true) => e.host.clone(),
        (EntryKind::Web, _) => e.username.clone(),
    }
}

/// The bundled brand icon for a website entry (servers keep the monitor glyph).
fn icon_of(e: &Entry) -> Option<slint::Image> {
    (e.kind == EntryKind::Web).then(|| icons::for_entry(&e.url, &e.title)).flatten()
}

/// Hide everything about the selected entry, stop its timers and forget revealed secrets.
pub(crate) fn clear_detail(ui: &MainWindow) {
    SECRETS_TIMER.with(Timer::stop);
    ui.set_selected(-1);
    ui.set_detail_title(SharedString::new());
    ui.set_detail_server(false);
    ui.set_detail_has_icon(false);
    ui.set_detail_host(SharedString::new());
    ui.set_detail_username(SharedString::new());
    ui.set_detail_url(SharedString::new());
    ui.set_detail_has_notes(false);
    ui.set_revealed(SharedString::new());
    ui.set_notes_revealed(SharedString::new());
    ui.set_confirm_delete(false);
}

/// Rebuild the list from the current query and filter, keeping the open entry open if it is
/// still listed. Never touches secret fields.
pub(crate) fn refresh_list(ui: &MainWindow) {
    let keep =
        with_session(|s| s.selected.and_then(|i| s.vault.vault.entries.get(i)).map(|e| e.id))
            .flatten();
    let rows = with_session(|s| {
        s.shown = search_kind(&s.vault.vault.entries, &s.query, s.filter);
        s.selected = None;
        let rows: Vec<EntryRow> = s
            .shown
            .iter()
            .filter_map(|&i| s.vault.vault.entries.get(i))
            .map(|e| {
                let icon = icon_of(e);
                EntryRow {
                    title: e.title.as_str().into(),
                    subtitle: subtitle(e).into(),
                    server: e.kind == EntryKind::Server,
                    has_icon: icon.is_some(),
                    icon: icon.unwrap_or_default(),
                }
            })
            .collect();
        (rows, s.vault.vault.entries.len())
    });
    clear_detail(ui);
    if let Some((rows, total)) = rows {
        let label = if rows.len() == total {
            format!("{total} entries")
        } else {
            format!("{} of {total} entries", rows.len())
        };
        ui.set_count_label(label.into());
        ui.set_entries(ModelRc::new(VecModel::from(rows)));
    }
    if let Some(id) = keep {
        select_by_id(ui, &id);
    }
}

pub(crate) fn set_filter(ui: &MainWindow, which: i32) {
    with_session(|s| {
        s.filter = match which {
            1 => Some(EntryKind::Server),
            2 => Some(EntryKind::Web),
            _ => None,
        };
    });
    ui.set_filter(which);
    refresh_list(ui);
}

fn select_by_id(ui: &MainWindow, id: &EntryId) {
    let row = with_session(|s| {
        s.shown.iter().position(|&i| s.vault.vault.entries.get(i).is_some_and(|e| &e.id == id))
    })
    .flatten();
    if let Some(row) = row.and_then(|r| i32::try_from(r).ok()) {
        on_select(ui, row);
    }
}

// ------------------------------------------------------------------ detail

/// What the detail pane shows right away (no password, notes or code).
struct Details {
    title: String,
    server: bool,
    host: String,
    username: String,
    url: String,
    has_notes: bool,
    icon: Option<slint::Image>,
}

pub(crate) fn on_select(ui: &MainWindow, row: i32) {
    let details = with_session(|s| {
        let idx = usize::try_from(row).ok().and_then(|r| s.shown.get(r).copied())?;
        let e = s.vault.vault.entries.get(idx)?;
        s.selected = Some(idx);
        Some(Details {
            title: e.title.clone(),
            server: e.kind == EntryKind::Server,
            host: e.host.clone(),
            username: e.username.clone(),
            url: e.url.clone(),
            has_notes: !e.notes.is_empty(),
            icon: icon_of(e),
        })
    })
    .flatten();
    let Some(d) = details else { return };
    SECRETS_TIMER.with(Timer::stop);
    ui.set_selected(row);
    ui.set_detail_title(d.title.into());
    ui.set_detail_server(d.server);
    ui.set_detail_has_icon(d.icon.is_some());
    ui.set_detail_icon(d.icon.unwrap_or_default());
    ui.set_detail_host(d.host.into());
    ui.set_detail_username(d.username.into());
    ui.set_detail_url(d.url.into());
    ui.set_detail_has_notes(d.has_notes);
    ui.set_revealed(SharedString::new());
    ui.set_notes_revealed(SharedString::new());
    ui.set_confirm_delete(false);
}

/// A click on a list row: show that entry, whatever pane was open.
pub(crate) fn on_select_clicked(ui: &MainWindow, row: i32) {
    crate::panes::leave_pane(ui, 0);
    with_session(|s| s.editing = None);
    on_select(ui, row);
}

/// Hide a revealed password and notes after [`REVEAL_SECS`] seconds.
fn arm_hide_timer(ui: &MainWindow) {
    let weak = ui.as_weak();
    SECRETS_TIMER.with(|t| {
        t.start(TimerMode::SingleShot, Duration::from_secs(REVEAL_SECS), move || {
            if let Some(ui) = weak.upgrade() {
                ui.set_revealed(SharedString::new());
                ui.set_notes_revealed(SharedString::new());
            }
        });
    });
}

pub(crate) fn toggle_reveal(ui: &MainWindow) {
    if !ui.get_revealed().is_empty() {
        ui.set_revealed(SharedString::new());
        return;
    }
    let password = with_session(|s| {
        let e = s.selected.and_then(|i| s.vault.vault.entries.get(i))?;
        Some(Zeroizing::new(e.password.clone()))
    })
    .flatten();
    if let Some(p) = password {
        ui.set_revealed(p.as_str().into());
        arm_hide_timer(ui);
    }
}

pub(crate) fn toggle_notes(ui: &MainWindow) {
    if !ui.get_notes_revealed().is_empty() {
        ui.set_notes_revealed(SharedString::new());
        return;
    }
    let notes = with_session(|s| {
        let e = s.selected.and_then(|i| s.vault.vault.entries.get(i))?;
        Some(Zeroizing::new(e.notes.clone()))
    })
    .flatten();
    if let Some(n) = notes {
        ui.set_notes_revealed(n.as_str().into());
        arm_hide_timer(ui);
    }
}

// --------------------------------------------------------------------- copy

/// Which field of an entry goes to the clipboard.
#[derive(Clone, Copy)]
pub(crate) enum CopyField {
    Password,
    Username,
    Host,
}

impl CopyField {
    fn name(self) -> &'static str {
        match self {
            Self::Password => "Password",
            Self::Username => "Username",
            Self::Host => "Server",
        }
    }

    fn empty_message(self) -> &'static str {
        match self {
            Self::Password => "This entry has no password.",
            Self::Username => "This entry has no username.",
            Self::Host => "This entry has no server.",
        }
    }

    fn value(self, e: &Entry) -> Zeroizing<String> {
        match self {
            Self::Password => Zeroizing::new(e.password.clone()),
            Self::Username => Zeroizing::new(e.username.clone()),
            Self::Host => Zeroizing::new(e.host.clone()),
        }
    }
}

fn copy_entry_field(ui: &MainWindow, index: Option<usize>, field: CopyField) {
    let value = with_session(|s| {
        let e = index.and_then(|i| s.vault.vault.entries.get(i))?;
        Some(field.value(e))
    })
    .flatten();
    let Some(value) = value else { return };
    if value.is_empty() {
        ui.set_status(field.empty_message().into());
    } else {
        copy_text(ui, &value, field.name());
    }
}

/// Copy a field of the entry open in the detail pane.
pub(crate) fn copy_selected(ui: &MainWindow, field: CopyField) {
    let index = with_session(|s| s.selected).flatten();
    copy_entry_field(ui, index, field);
}

/// Copy the password of a listed entry without opening it (the icon on server rows).
pub(crate) fn copy_row_password(ui: &MainWindow, row: i32) {
    let index =
        with_session(|s| usize::try_from(row).ok().and_then(|r| s.shown.get(r).copied())).flatten();
    copy_entry_field(ui, index, CopyField::Password);
}

// ------------------------------------------------------------------ editor

pub(crate) fn clear_form(ui: &MainWindow) {
    ui.set_form_editing(false);
    ui.set_form_title(SharedString::new());
    ui.set_form_target(SharedString::new());
    ui.set_form_username(SharedString::new());
    ui.set_form_password(SharedString::new());
    ui.set_form_notes(SharedString::new());
}

pub(crate) fn new_entry(ui: &MainWindow) {
    crate::panes::leave_pane(ui, 1);
    clear_form(ui);
    with_session(|s| s.editing = None);
    // Servers are the main use; follow the list filter when it narrows to websites.
    ui.set_form_server(ui.get_filter() != 2);
    ui.set_error(SharedString::new());
    ui.set_pane(1);
}

pub(crate) fn edit_selected(ui: &MainWindow) {
    let found = with_session(|s| {
        let e = s.selected.and_then(|i| s.vault.vault.entries.get(i))?;
        s.editing = Some(e.id);
        Some((
            e.kind == EntryKind::Server,
            e.title.clone(),
            if e.kind == EntryKind::Server { e.host.clone() } else { e.url.clone() },
            e.username.clone(),
            Zeroizing::new(e.password.clone()),
            Zeroizing::new(e.notes.clone()),
        ))
    })
    .flatten();
    let Some((server, title, target, username, password, notes)) = found else {
        return;
    };
    crate::panes::leave_pane(ui, 1);
    clear_form(ui);
    ui.set_form_editing(true);
    ui.set_form_server(server);
    ui.set_form_title(title.into());
    ui.set_form_target(target.into());
    ui.set_form_username(username.into());
    ui.set_form_password(password.as_str().into());
    ui.set_form_notes(notes.as_str().into());
    ui.set_error(SharedString::new());
    ui.set_pane(1);
}

pub(crate) fn cancel_form(ui: &MainWindow) {
    with_session(|s| s.editing = None);
    clear_form(ui);
    ui.set_error(SharedString::new());
    ui.set_pane(0);
}

/// The message to show if a required editor field is empty.
fn missing_field(
    server: bool,
    title: &str,
    target: &str,
    username: &str,
    password: &str,
) -> Option<&'static str> {
    if title.trim().is_empty() {
        Some("Enter a title.")
    } else if target.trim().is_empty() {
        Some(if server {
            "Enter the server name or address."
        } else {
            "Enter the website address."
        })
    } else if username.trim().is_empty() {
        Some("Enter a username.")
    } else if password.is_empty() {
        Some("Enter a password.")
    } else {
        None
    }
}

pub(crate) fn save_entry(ui: &MainWindow) {
    if is_rekeying() {
        ui.set_error(REKEY_BUSY.into());
        return;
    }
    let server = ui.get_form_server();
    let title = ui.get_form_title();
    let target = ui.get_form_target();
    let username = ui.get_form_username();
    let password = Zeroizing::new(ui.get_form_password().to_string());
    let notes = Zeroizing::new(ui.get_form_notes().to_string());
    if let Some(message) = missing_field(server, &title, &target, &username, &password) {
        ui.set_error(message.into());
        return;
    }
    let result = with_session(|s| -> Result<EntryId, Error> {
        let mut e = match s.editing.and_then(|id| s.vault.vault.get(&id).cloned()) {
            Some(existing) => existing,
            None => Entry::new(title.trim())?,
        };
        let previous = s.vault.vault.get(&e.id).cloned();
        e.kind = if server { EntryKind::Server } else { EntryKind::Web };
        title.trim().clone_into(&mut e.title);
        if server {
            target.trim().clone_into(&mut e.host);
            e.url.clear();
        } else {
            target.trim().clone_into(&mut e.url);
            e.host.clear();
        }
        username.trim().clone_into(&mut e.username);
        e.password.clone_from(&password);
        e.notes.clone_from(&notes);
        e.touch();
        let id = e.id;
        s.vault.vault.upsert(e)?;
        if let Err(err) = s.save() {
            // Keep memory and disk consistent: undo what we just did.
            match previous {
                Some(old) => {
                    let _ = s.vault.vault.upsert(old);
                }
                None => {
                    s.vault.vault.remove(&id);
                }
            }
            return Err(err);
        }
        s.editing = None;
        Ok(id)
    });
    match result {
        Some(Ok(id)) => {
            ui.set_error(SharedString::new());
            clear_form(ui);
            ui.set_pane(0);
            refresh_list(ui);
            select_by_id(ui, &id);
            ui.set_status("Saved.".into());
        }
        Some(Err(e)) => ui.set_error(user_message(&e).into()),
        None => {}
    }
}

pub(crate) fn delete_selected(ui: &MainWindow) {
    if is_rekeying() {
        ui.set_status(format!("Could not delete: {REKEY_BUSY}").into());
        return;
    }
    let result = with_session(|s| -> Result<(), Error> {
        let Some(idx) = s.selected else { return Ok(()) };
        if idx >= s.vault.vault.entries.len() {
            return Ok(());
        }
        let removed = s.vault.vault.entries.remove(idx);
        if let Err(err) = s.save() {
            s.vault.vault.entries.insert(idx, removed);
            return Err(err);
        }
        Ok(())
    });
    match result {
        Some(Ok(())) => {
            ui.set_error(SharedString::new());
            refresh_list(ui);
        }
        Some(Err(e)) => ui.set_status(format!("Could not delete: {}.", user_message(&e)).into()),
        None => {}
    }
}

// ------------------------------------------------------------------ import

/// Why an import failed, in words that fit a file rather than a password.
fn import_message(err: &Error) -> String {
    match err {
        Error::InvalidFormat => "the file is not a valid export".to_owned(),
        Error::InvalidInput(why) => (*why).to_owned(),
        other => user_message(other).trim_end_matches('.').to_owned(),
    }
}

const IMPORT_REMINDER: &str = "The file you imported holds every password in plain text. \
    Delete it now, and empty the Recycle Bin.";

pub(crate) fn import_file(ui: &MainWindow) {
    if is_rekeying() {
        ui.set_status(format!("Could not import: {REKEY_BUSY}").into());
        return;
    }
    let path = match pick_file(ui, Pick::Import, false) {
        Ok(Some(path)) => path,
        Ok(None) => return,
        Err(_) => {
            ui.set_status("Could not open the file dialog.".into());
            return;
        }
    };
    let Some(format) = Format::from_path(&path) else {
        ui.set_status(
            "Could not import: choose a .csv (KeePass) or .json (Bitwarden) file.".into(),
        );
        return;
    };
    let imported = match import::import_file(&path, format) {
        Ok(i) => i,
        Err(e) => {
            ui.set_status(format!("Could not import: {}.", import_message(&e)).into());
            return;
        }
    };
    let skipped = imported.skipped;
    let ids: Vec<EntryId> = imported.entries.iter().map(|e| e.id).collect();

    let result = with_session(|s| -> Result<(), Error> {
        for e in imported.entries {
            if let Err(err) = s.vault.vault.upsert(e) {
                for id in &ids {
                    s.vault.vault.remove(id);
                }
                return Err(err);
            }
        }
        if let Err(err) = s.save() {
            for id in &ids {
                s.vault.vault.remove(id);
            }
            return Err(err);
        }
        Ok(())
    });
    match result {
        Some(Ok(())) => {
            let count = ids.len();
            let left_out = if skipped > 0 {
                format!(" ({skipped} skipped: not logins, or unusable)")
            } else {
                String::new()
            };
            let message = format!("Imported {count} entries{left_out}. {IMPORT_REMINDER}");
            ui.set_import_notice(message.into());
            ui.set_status(SharedString::new());
            refresh_list(ui);
        }
        Some(Err(e)) => {
            ui.set_status(format!("Could not import: {}.", import_message(&e)).into());
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_fields_are_checked_in_order() {
        assert_eq!(missing_field(true, " ", "h", "u", "p"), Some("Enter a title."));
        assert_eq!(
            missing_field(true, "t", "", "u", "p"),
            Some("Enter the server name or address.")
        );
        assert_eq!(missing_field(false, "t", "", "u", "p"), Some("Enter the website address."));
        assert_eq!(missing_field(false, "t", "https://x", "", "p"), Some("Enter a username."));
        assert_eq!(missing_field(false, "t", "https://x", "u", ""), Some("Enter a password."));
        assert_eq!(missing_field(false, "t", "https://x", "u", "p"), None);
    }

    #[test]
    fn subtitle_shows_host_and_user_for_servers() {
        let mut e = Entry::new("Prod").unwrap();
        e.kind = EntryKind::Server;
        e.host = "srv-01".into();
        assert_eq!(subtitle(&e), "srv-01");
        e.username = "admin".into();
        assert_eq!(subtitle(&e), "srv-01 · admin");
        e.kind = EntryKind::Web;
        assert_eq!(subtitle(&e), "admin");
    }
}
