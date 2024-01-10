#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use egui::ViewportBuilder;
use nt_explorer::TemplateApp;

fn main() -> eframe::Result<()> {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).

    let native_options = eframe::NativeOptions {
        viewport: ViewportBuilder::default().with_inner_size([940.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "nt-explorer",
        native_options,
        Box::new(|cc| Box::new(TemplateApp::new(cc))),
    )
}
