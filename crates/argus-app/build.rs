// Build scripts have no caller to report to, and a failed UI compile must stop the build.
#![allow(clippy::expect_used)]

fn main() {
    slint_build::compile("ui/main.slint").expect("Slint compilation failed");
}
