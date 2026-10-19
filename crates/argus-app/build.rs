// Build scripts have no caller to report to, and a failed UI compile must stop the build.
#![allow(clippy::expect_used)]

fn main() {
    slint_build::compile("ui/main.slint").expect("Slint compilation failed");

    // Embed the application icon (Explorer, taskbar, Alt-Tab) in the Windows executable.
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.compile().expect("embedding the Windows icon failed");
    }
}
