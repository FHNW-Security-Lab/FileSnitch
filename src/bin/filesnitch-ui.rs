#[cfg(feature = "ui")]
fn main() {
    filesnitch::ui::app::run_ui();
}

#[cfg(not(feature = "ui"))]
fn main() {
    eprintln!("filesnitch-ui was built without the 'ui' feature");
}
