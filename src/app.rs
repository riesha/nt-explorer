use egui::Color32;

use crate::process::{Process, PEB};

/// We derive Deserialize/Serialize so we can persist app state on shutdown.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)] // if we add new fields, give them default values when deserializing old state
pub struct TemplateApp
{
    // Example stuff:
    label: String,

    #[serde(skip)] // This how you opt-out of serialization of a field
    process: Option<Process>,
    processlist_open: bool,
    processlist:      Vec<String>,
}

impl Default for TemplateApp
{
    fn default() -> Self
    {
        Self {
            // Example stuff:
            label:            "Hello World!".to_owned(),
            process:          None,
            processlist_open: false,
            processlist:      Vec::new(),
        }
    }
}

impl TemplateApp
{
    /// Called once before the first frame.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self
    {
        // This is also where you can customize the look and feel of egui using
        // `cc.egui_ctx.set_visuals` and `cc.egui_ctx.set_fonts`.

        // Load previous app state (if any).
        // Note that you must enable the `persistence` feature for this to work.
        if let Some(storage) = cc.storage
        {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }

        Default::default()
    }
}

impl eframe::App for TemplateApp
{
    /// Called by the frame work to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage)
    {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame)
    {
        let mut processes = egui::Window::new("process list")
            .open(&mut self.processlist_open)
            .default_size([400.0, 500.0])
            .vscroll(true);

        processes.show(ctx, |ui| {
            for proc in &self.processlist
            {
                ui.label(proc);
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("nt-explorer");

            ui.horizontal(|ui| {
                ui.label("PID: ");
                ui.text_edit_singleline(&mut self.label);
                if ui.button("open").clicked()
                {
                    if let Ok(mut proc) = Process::open(self.label.trim().parse::<u32>().unwrap())
                    {
                        proc.peb().unwrap();
                        self.process = Some(proc);
                    }
                }
            });
            if ui.button("find process").clicked()
            {
                self.processlist = Process::enum_processes().unwrap();
                self.processlist_open = true;
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.visuals_mut().code_bg_color = Color32::BLACK;
                if let Some(proc) = &self.process
                {
                    ui.label(format!(
                        "Process opened! handle -> {:#x?}",
                        proc.handle.0 as usize
                    ));

                    if let Some(peb) = &proc.peb
                    {
                        match peb
                        {
                            PEB::PEB32(peb) =>
                            {
                                ui.code(format!("{:#x?}", peb));
                            }
                            PEB::PEB64(peb) =>
                            {
                                ui.code(format!("{:#x?}", peb));
                            }
                        }
                    }
                }
            });
        });
    }
}
