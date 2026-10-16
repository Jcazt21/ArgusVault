//! Headless screenshots of the interface, for looking at layout without a desktop session.
//!
//! This is a development aid, not a test of behavior: it only runs when `ARGUS_SNAPSHOT_DIR`
//! names a directory, and then writes one `.bmp` per screen there (the Slint software renderer
//! draws into memory, so no window, GPU or unlocked Windows session is needed):
//!
//! ```text
//! set ARGUS_SNAPSHOT_DIR=C:\some\folder
//! cargo test -p argus-app --locked snapshots -- --nocapture
//! ```
//!
//! Screens are filled with made-up data by setting window properties directly; no vault is
//! opened and nothing is read from or written to disk apart from the images.

use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle, ModelRc, PhysicalSize, Rgb8Pixel, SharedString, VecModel};

use crate::ui::{EntryRow, MainWindow};

struct Headless(Rc<MinimalSoftwareWindow>);

impl Platform for Headless {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.0.clone())
    }
}

/// Write the window's current contents as a 24-bit BMP.
fn snap(window: &MinimalSoftwareWindow, dir: &Path, name: &str) {
    // Let transitions (switches, hover fades) finish before drawing.
    let until = Instant::now() + Duration::from_millis(400);
    while Instant::now() < until {
        slint::platform::update_timers_and_animations();
        std::thread::sleep(Duration::from_millis(20));
    }
    let size = window.size();
    let (w, h) = (size.width as usize, size.height as usize);
    let mut pixels = vec![Rgb8Pixel::default(); w * h];
    window.request_redraw();
    window.draw_if_needed(|renderer| {
        renderer.render(&mut pixels, w);
    });

    let row_bytes = (w * 3).div_ceil(4) * 4;
    let image_bytes = row_bytes * h;
    let mut bmp = Vec::with_capacity(54 + image_bytes);
    bmp.extend_from_slice(b"BM");
    bmp.extend_from_slice(&u32::try_from(54 + image_bytes).unwrap().to_le_bytes());
    bmp.extend_from_slice(&[0; 4]);
    bmp.extend_from_slice(&54u32.to_le_bytes());
    bmp.extend_from_slice(&40u32.to_le_bytes());
    bmp.extend_from_slice(&i32::try_from(w).unwrap().to_le_bytes());
    bmp.extend_from_slice(&i32::try_from(h).unwrap().to_le_bytes());
    bmp.extend_from_slice(&1u16.to_le_bytes());
    bmp.extend_from_slice(&24u16.to_le_bytes());
    bmp.extend_from_slice(&[0; 24]);
    for y in (0..h).rev() {
        let mut written = 0;
        for p in &pixels[y * w..(y + 1) * w] {
            bmp.extend_from_slice(&[p.b, p.g, p.r]);
            written += 3;
        }
        bmp.resize(bmp.len() + (row_bytes - written), 0);
    }
    std::fs::write(dir.join(format!("{name}.bmp")), bmp).unwrap();
}

fn rows() -> ModelRc<EntryRow> {
    let row = |title: &str, subtitle: &str, server: bool, url: &str| {
        let icon = crate::icons::for_entry(url, title);
        EntryRow {
            title: title.into(),
            subtitle: subtitle.into(),
            server,
            has_icon: icon.is_some(),
            icon: icon.unwrap_or_default(),
        }
    };
    ModelRc::new(VecModel::from(vec![
        row("Domain controller", "dc-01.corp.local · CORP\\admin", true, ""),
        row("Production DB", "10.0.4.20:3390 · sa", true, ""),
        row("GitHub", "alice@example.com", false, "https://github.com"),
        row("GitLab (corp)", "ci@corp", false, "https://gitlab.corp.local"),
        row("Vault", "root", false, "http://vault.lan:8200"),
        row("Portainer", "admin", false, "https://portainer.corp.local:9443"),
        row("Work email", "alice@corp.example", false, "https://mail.google.com"),
        row("Router", "admin", false, "http://192.168.1.1"),
    ]))
}

fn vault_view(ui: &MainWindow) {
    ui.set_unlocked(true);
    ui.set_entries(rows());
    ui.set_count_label("8 entries".into());
    ui.set_pane(0);
    ui.set_selected(-1);
}

fn s(text: &str) -> SharedString {
    text.into()
}

#[test]
#[allow(clippy::too_many_lines)] // One long, flat script of screens.
fn render_screens() {
    let Some(dir) = std::env::var_os("ARGUS_SNAPSHOT_DIR") else {
        return;
    };
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).unwrap();

    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    window.set_size(PhysicalSize::new(1040, 700));
    slint::platform::set_platform(Box::new(Headless(window.clone()))).unwrap();
    let ui = MainWindow::new().unwrap();
    ui.show().unwrap();

    // Unlock screen.
    ui.set_capture_status(s(
        "Screen-capture protection is on: this window is hidden from screenshots and recordings.",
    ));
    ui.set_capture_ok(true);
    snap(&window, dir, "01_unlock");

    // Creating a vault, with a keyfile chosen and an error.
    ui.set_creating(true);
    ui.set_vault_path(s("C:\\Users\\me\\Documents\\vault.argus"));
    ui.set_keyfile_path(s("C:\\Users\\me\\Documents\\vault.argkey"));
    ui.set_password(s("correct horse battery"));
    ui.set_strength_score(3);
    ui.set_strength_label(s("Strong"));
    ui.set_error(s("The two passwords do not match."));
    snap(&window, dir, "02_create");
    ui.set_creating(false);
    ui.set_error(SharedString::new());
    ui.set_keyfile_path(SharedString::new());
    ui.set_password(SharedString::new());

    // A selected server with an authenticator.
    vault_view(&ui);
    ui.set_selected(0);
    ui.set_detail_title(s("Domain controller"));
    ui.set_detail_server(true);
    ui.set_detail_host(s("dc-01.corp.local"));
    ui.set_detail_username(s("CORP\\admin"));
    ui.set_detail_has_notes(true);
    ui.set_status(s("Password copied. Clears in 20 s."));
    snap(&window, dir, "03_server_detail");

    // A website with revealed notes.
    ui.set_selected(2);
    ui.set_detail_title(s("GitHub"));
    ui.set_detail_server(false);
    let github = crate::icons::for_entry("https://github.com", "GitHub");
    ui.set_detail_has_icon(github.is_some());
    ui.set_detail_icon(github.unwrap_or_default());
    ui.set_detail_url(s("https://github.com"));
    ui.set_detail_username(s("alice@example.com"));
    ui.set_notes_revealed(s("Recovery codes are in the safe.\nSecond line of a note."));
    ui.set_revealed(s("hunter2-correct-horse"));
    ui.set_status(SharedString::new());
    ui.set_filter(2);
    ui.set_import_notice(s("Imported 12 entries. The file you imported holds every password in plain text. Delete it now, and empty the Recycle Bin."));
    snap(&window, dir, "04_web_detail");
    ui.set_import_notice(SharedString::new());
    ui.set_notes_revealed(SharedString::new());
    ui.set_revealed(SharedString::new());
    ui.set_filter(0);

    // Editor: new server, then editing a website that has an authenticator.
    ui.set_pane(1);
    ui.set_form_server(true);
    ui.set_form_title(s("Production DB"));
    ui.set_form_target(s("10.0.4.20:3390"));
    ui.set_form_username(s("sa"));
    ui.set_form_password(s("secret-secret"));
    ui.set_error(s("Enter a password."));
    snap(&window, dir, "05_editor_server");
    ui.set_form_editing(true);
    ui.set_form_server(false);
    ui.set_error(SharedString::new());
    snap(&window, dir, "06_editor_web_edit");
    ui.set_form_editing(false);

    // Settings.
    ui.set_pane(2);
    ui.set_settings_autolock(s("300"));
    ui.set_settings_clipboard(s("20"));
    ui.set_settings_lock_min(true);
    ui.set_capture_status(s(
        "Screen-capture protection is on: this window is hidden from screenshots and recordings.",
    ));
    ui.set_cred_new_keyfile(s("C:\\Users\\me\\Documents\\vault.argkey"));
    ui.set_settings_message(s("Settings saved."));
    snap(&window, dir, "07_settings");
    ui.set_settings_message(SharedString::new());
    ui.set_cred_new_keyfile(SharedString::new());

    // Generator, both modes.
    ui.set_pane(3);
    ui.set_gen_result(s("k7#Qm2vX!pL9rT4wZe8Bn@3d"));
    ui.set_gen_entropy(s("About 155 bits of entropy"));
    ui.set_gen_for_form(true);
    snap(&window, dir, "08_generator_password");
    ui.set_gen_mode(1);
    ui.set_gen_result(s("Gadget-Pastel-Unmoved-Crop-Silk-Liftoff4"));
    ui.set_gen_entropy(s("About 85 bits of entropy"));
    snap(&window, dir, "09_generator_passphrase");

    // Empty state.
    ui.set_pane(0);
    ui.set_selected(-1);
    ui.set_entries(ModelRc::new(VecModel::from(Vec::<EntryRow>::new())));
    ui.set_count_label(s("0 entries"));
    snap(&window, dir, "10_empty");

    // Narrowest supported window.
    window.set_size(PhysicalSize::new(800, 560));
    vault_view(&ui);
    ui.set_selected(0);
    ui.set_detail_title(s("Domain controller"));
    ui.set_detail_server(true);
    ui.set_detail_host(s("dc-01.corp.local"));
    ui.set_detail_username(s("CORP\\admin"));
    snap(&window, dir, "11_min_size_detail");
}
