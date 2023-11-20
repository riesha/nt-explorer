#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use nt_explorer::{process::Process, TemplateApp};
fn main() -> eframe::Result<()>
{
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).

    let native_options = eframe::NativeOptions {
        initial_window_size: Some([400.0, 300.0].into()),
        min_window_size: Some([300.0, 220.0].into()),
        ..Default::default()
    };

    eframe::run_native(
        "nt-explorer",
        native_options,
        Box::new(|cc| Box::new(TemplateApp::new(cc))),
    )
}
