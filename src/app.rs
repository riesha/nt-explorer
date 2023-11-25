use egui::{Color32, Label, RichText, TextEdit, TextStyle, ViewportBuilder, ViewportId};
use egui_extras::{Column, TableBuilder};

use crate::process::{Process, ProcessListEntry, PEB};

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)]
pub struct TemplateApp
{
    label: String,

    #[serde(skip)]
    process:          Option<Process>,
    processlist_open: bool,
    #[serde(skip)]
    processlist:      Vec<ProcessListEntry>,
    search_string:    String,
}

impl Default for TemplateApp
{
    fn default() -> Self
    {
        Self {
            label:            "0".to_owned(),
            process:          None,
            processlist_open: false,
            processlist:      Vec::new(),
            search_string:    String::new(),
        }
    }
}

impl TemplateApp
{
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self { Default::default() }
}

impl eframe::App for TemplateApp
{
    fn save(&mut self, storage: &mut dyn eframe::Storage)
    {
        //eframe::set_value(storage, eframe::APP_KEY, self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame)
    {
        if self.processlist_open
        {
            ctx.show_viewport_immediate(
                ViewportId::from_hash_of("process_list"),
                ViewportBuilder::default().with_title("process list"),
                |ctx, class| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let mut searchbar = ui.add(
                            egui::TextEdit::singleline(&mut self.search_string)
                                .hint_text("search processes"),
                        );
                        searchbar.mark_changed();
                        if searchbar.changed()
                        {
                            self.processlist.iter_mut().for_each(|x| {
                                if !x
                                    .name
                                    .to_lowercase()
                                    .contains(&self.search_string.trim().to_lowercase())
                                {
                                    x.show = false;
                                }
                                else if self.search_string.is_empty()
                                {
                                    x.show = true;
                                }
                            });
                        }
                        TableBuilder::new(ui)
                            .column(Column::auto())
                            .column(Column::remainder())
                            .column(Column::remainder())
                            .column(Column::remainder())
                            .striped(true)
                            .auto_shrink(false)
                            .header(20.0, |mut header| {
                                header.col(|ui| {});
                                header.col(|ui| {
                                    ui.strong("process name");
                                });
                                header.col(|ui| {
                                    ui.strong("process id");
                                });
                                header.col(|ui| {
                                    ui.strong("user name");
                                });
                            })
                            .body(|mut body| {
                                for proc in &self.processlist
                                {
                                    if !proc.show
                                    {
                                        continue;
                                    }
                                    body.row(30.0, |mut row| {
                                        row.col(|ui| {
                                            if ui
                                                .add(egui::Button::new("open").wrap(false))
                                                .clicked()
                                            {
                                                if let Ok(mut prc) = Process::open(proc.pid)
                                                {
                                                    prc.peb().unwrap();

                                                    self.label = proc.pid.to_string();
                                                    self.process = Some(prc);
                                                    self.processlist_open = false;
                                                }
                                            }
                                        });
                                        row.col(|ui| {
                                            ui.label(&proc.name);
                                        });
                                        row.col(|ui| {
                                            ui.label(proc.pid.to_string());
                                        });
                                        row.col(|ui| {
                                            ui.label(&proc.username);
                                        });
                                    });
                                }
                            });
                    });
                    if ctx.input(|i| i.viewport().close_requested())
                    {
                        self.processlist_open = false;
                    }
                },
            );
        }
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
                                ui.add(
                                    TextEdit::multiline(&mut format!("{:#x?}", peb))
                                        .font(TextStyle::Monospace),
                                );
                                // ui.code(format!("{:#x?}", peb));
                            }
                            PEB::PEB64(peb) =>
                            {
                                // ui.code(format!("{:#x?}", peb));
                                ui.add(
                                    TextEdit::multiline(&mut format!("{:#x?}", peb))
                                        .font(TextStyle::Monospace)
                                        .min_size([0.0, 0.0].into())
                                        .desired_rows(1)
                                        .desired_width(f32::INFINITY),
                                );
                            }
                        }
                    }
                }
            });
        });
    }
}
