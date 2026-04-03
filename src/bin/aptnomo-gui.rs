// Unlicense — cochranblock.org
// Contributors: GotEmCoach, KOVA, Claude Opus 4.6
//! aptnomo GUI — Tinder for Threats.
//! Swipe-card interface for reviewing threat detections.

#[cfg(feature = "gui")]
fn main() -> anyhow::Result<()> {
    f90_gui_main()
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("aptnomo-gui: requires --features gui");
    std::process::exit(1);
}

#[cfg(feature = "gui")]
use aptnomo::{store, types::*};

#[cfg(feature = "gui")]
use eframe::egui;

#[cfg(feature = "gui")]
use std::time::{Duration, Instant};

/// f90: GUI entry point.
#[cfg(feature = "gui")]
fn f90_gui_main() -> anyhow::Result<()> {
    let db = store::open_db()?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([420.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "aptnomo",
        options,
        Box::new(move |cc| {
            f98_apply_theme(&cc.egui_ctx);
            Ok(Box::new(AptnomoApp::new(db)))
        }),
    ).map_err(|e| anyhow::anyhow!("{}", e))
}

#[cfg(feature = "gui")]
enum Screen { Cards, Stats }

#[cfg(feature = "gui")]
struct AptnomoApp {
    db: sled::Db,
    cards: Vec<ThreatCard>,
    current: usize,
    screen: Screen,
    drag_offset: f32,
    drag_offset_y: f32,
    last_refresh: Instant,
}

#[cfg(feature = "gui")]
impl AptnomoApp {
    fn new(db: sled::Db) -> Self {
        let cards = store::pending_threats(&db).unwrap_or_default();
        Self {
            db,
            cards,
            current: 0,
            screen: Screen::Cards,
            drag_offset: 0.0,
            drag_offset_y: 0.0,
            last_refresh: Instant::now(),
        }
    }

    /// f95: Poll sled for pending threats.
    fn f95_sled_read(&mut self) {
        if self.last_refresh.elapsed() > Duration::from_secs(1) {
            self.cards = store::pending_threats(&self.db).unwrap_or_default();
            if self.current >= self.cards.len() {
                self.current = 0;
            }
            self.last_refresh = Instant::now();
        }
    }
}

#[cfg(feature = "gui")]
impl eframe::App for AptnomoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.f95_sled_read();

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(egui::Color32::from_rgb(0x0c, 0x0c, 0x12)))
            .show(ctx, |ui| {
                ui.add_space(12.0);

                // Header
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("aptnomo").color(egui::Color32::from_rgb(0xe8, 0xe8, 0xe8)).size(20.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let label = match self.screen {
                            Screen::Cards => "stats",
                            Screen::Stats => "cards",
                        };
                        if ui.button(label).clicked() {
                            self.screen = match self.screen {
                                Screen::Cards => Screen::Stats,
                                Screen::Stats => Screen::Cards,
                            };
                        }
                        ui.label(egui::RichText::new(format!("{} pending", self.cards.len()))
                            .color(egui::Color32::from_rgb(0x9c, 0xa3, 0xaf)).size(14.0));
                    });
                });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(12.0);

                match self.screen {
                    Screen::Cards => {
                        if let Some(card) = self.cards.get(self.current).cloned() {
                            let response = f91_render_card(ui, &card, self.drag_offset);
                            f92_swipe_handler(
                                &response, &self.db, &card,
                                &mut self.drag_offset, &mut self.drag_offset_y,
                                &mut self.cards, &mut self.current,
                            );
                        } else {
                            ui.add_space(200.0);
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("All clear.")
                                    .color(egui::Color32::from_rgb(0x50, 0xb4, 0x32)).size(24.0).strong());
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("No pending threats.")
                                    .color(egui::Color32::from_rgb(0x9c, 0xa3, 0xaf)).size(14.0));
                            });
                        }

                        // Swipe hints at bottom
                        ui.add_space(20.0);
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("< KILL").color(egui::Color32::from_rgb(0xc8, 0x32, 0x32)).size(12.0));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new("BASELINE >").color(egui::Color32::from_rgb(0x50, 0xb4, 0x32)).size(12.0));
                            });
                        });
                        ui.vertical_centered(|ui| {
                            ui.label(egui::RichText::new("^ QUARANTINE").color(egui::Color32::from_rgb(0xd4, 0xd4, 0x32)).size(12.0));
                        });
                    }
                    Screen::Stats => f94_stats_screen(ui, &self.db),
                }
            });

        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

/// f91: Render a single threat card. Returns the card area response for drag detection.
#[cfg(feature = "gui")]
fn f91_render_card(ui: &mut egui::Ui, card: &ThreatCard, drag_offset: f32) -> egui::Response {
    let (border, fill) = severity_colors(&card.severity);
    let icon = module_icon(&card.module);

    let frame = egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(2.0, border))
        .corner_radius(12.0)
        .inner_margin(20.0);

    ui.add_space(20.0);

    let available = ui.available_width();
    let card_width = available.min(380.0);
    let offset = drag_offset.clamp(-250.0, 250.0);

    // Swipe direction hint: tint the background
    if offset.abs() > 30.0 {
        let alpha = ((offset.abs() - 30.0) / 100.0).min(0.3);
        let hint_color = if offset > 0.0 {
            // Right = baseline (green)
            egui::Color32::from_rgba_unmultiplied(0x50, 0xb4, 0x32, (alpha * 255.0) as u8)
        } else {
            // Left = kill (red)
            egui::Color32::from_rgba_unmultiplied(0xc8, 0x32, 0x32, (alpha * 255.0) as u8)
        };
        let rect = ui.available_rect_before_wrap();
        ui.painter().rect_filled(rect, 0.0, hint_color);
    }

    // Horizontal offset via indented layout
    let margin = offset.max(0.0);
    if margin > 0.0 {
        ui.add_space(0.0); // no-op spacer for layout
    }

    let fr = ui.horizontal(|ui| {
        if margin > 0.0 {
            ui.add_space(margin);
        }
        frame.show(ui, |ui| {
            ui.set_min_width((card_width - offset.abs()).max(200.0));
            ui.set_max_width(card_width);

        // Severity badge
        let sev_text = format!("{:?}", card.severity).to_uppercase();
        ui.label(egui::RichText::new(format!("{} {} — {}", icon, sev_text, card.module.label()))
            .color(border).size(14.0).strong());

        ui.add_space(12.0);

        // Title
        ui.label(egui::RichText::new(&card.title)
            .color(egui::Color32::from_rgb(0xe8, 0xe8, 0xe8)).size(18.0).strong());

        ui.add_space(8.0);

        // Description
        ui.label(egui::RichText::new(&card.description)
            .color(egui::Color32::from_rgb(0x9c, 0xa3, 0xaf)).size(13.0));

        ui.add_space(12.0);

        // Details
        if let Some(pid) = card.pid {
            ui.label(egui::RichText::new(format!("PID: {}", pid))
                .color(egui::Color32::from_rgb(0x9c, 0xa3, 0xaf)).size(12.0));
        }
        if let Some(ref path) = card.file_path {
            ui.label(egui::RichText::new(format!("Path: {}", path))
                .color(egui::Color32::from_rgb(0x9c, 0xa3, 0xaf)).size(12.0));
        }
        if let Some(ref cmd) = card.command {
            ui.label(egui::RichText::new(format!("Cmd: {}", cmd))
                .color(egui::Color32::from_rgb(0x9c, 0xa3, 0xaf)).size(12.0));
        }

        // Auto-killed badge
        if card.status == CardStatus::AutoKilled {
            ui.add_space(8.0);
            ui.label(egui::RichText::new("AUTO-KILLED")
                .color(egui::Color32::from_rgb(0xc8, 0x32, 0x32)).size(14.0).strong());
        }
        }).response
    });

    // Make the horizontal wrapper response draggable
    fr.response.interact(egui::Sense::drag())
}

/// f92: Handle swipe gestures on the card.
#[cfg(feature = "gui")]
fn f92_swipe_handler(
    response: &egui::Response,
    db: &sled::Db,
    card: &ThreatCard,
    drag_offset: &mut f32,
    drag_offset_y: &mut f32,
    cards: &mut Vec<ThreatCard>,
    current: &mut usize,
) {
    if response.dragged() {
        let delta = response.drag_delta();
        *drag_offset += delta.x;
        *drag_offset_y += delta.y;
    }

    if response.drag_stopped() {
        if *drag_offset > 100.0 {
            // Right swipe — baseline
            let _ = store::resolve_threat(db, card.id, CardStatus::Baselined);
            f93_baseline_learn(db, card);
            cards.retain(|c| c.id != card.id);
        } else if *drag_offset < -100.0 {
            // Left swipe — kill
            if let Some(pid) = card.pid {
                if pid > 2 {
                    unsafe { libc::kill(pid as i32, libc::SIGKILL); }
                }
            }
            let _ = store::resolve_threat(db, card.id, CardStatus::Killed);
            cards.retain(|c| c.id != card.id);
        } else if *drag_offset_y < -80.0 {
            // Up swipe — quarantine
            if let Some(pid) = card.pid {
                if pid > 2 {
                    unsafe { libc::kill(pid as i32, libc::SIGSTOP); }
                }
            }
            let _ = store::resolve_threat(db, card.id, CardStatus::Quarantined);
            cards.retain(|c| c.id != card.id);
        }

        *drag_offset = 0.0;
        *drag_offset_y = 0.0;
        if *current >= cards.len() && !cards.is_empty() {
            *current = 0;
        }
    }
}

/// f93: Extract a baseline pattern from a threat card.
#[cfg(feature = "gui")]
fn f93_baseline_learn(db: &sled::Db, card: &ThreatCard) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (pattern_type, value) = match card.module {
        Module::Process => (PatternType::ProcessName, card.process_name.clone().unwrap_or_default()),
        Module::Network => (PatternType::ListenPort, card.title.clone()),
        Module::Files => (PatternType::FilePath, card.file_path.clone().unwrap_or_default()),
        Module::Cron => (PatternType::CronPattern, card.file_path.clone().unwrap_or_default()),
        Module::Ssh => (PatternType::SshKey, card.description.clone()),
        _ => (PatternType::ProcessName, card.title.clone()),
    };

    let pattern = BaselinePattern {
        module: card.module,
        pattern_type,
        value,
        learned_at: now,
        swipe_count: 1,
    };
    let _ = store::add_baseline(db, &pattern);
}

/// f94: Render the stats screen.
#[cfg(feature = "gui")]
fn f94_stats_screen(ui: &mut egui::Ui, db: &sled::Db) {
    let s = store::stats(db).unwrap_or_default();
    let muted = egui::Color32::from_rgb(0x9c, 0xa3, 0xaf);
    let text = egui::Color32::from_rgb(0xe8, 0xe8, 0xe8);

    ui.label(egui::RichText::new("THREAT OVERVIEW").color(text).size(18.0).strong());
    ui.add_space(12.0);

    egui::Grid::new("stats_grid").striped(true).show(ui, |ui| {
        let row = |ui: &mut egui::Ui, label: &str, val: usize| {
            ui.label(egui::RichText::new(label).color(muted).size(14.0));
            ui.label(egui::RichText::new(val.to_string()).color(text).size(14.0).strong());
            ui.end_row();
        };
        row(ui, "Total threats:", s.total_threats);
        row(ui, "Pending:", s.pending);
        row(ui, "Baselined:", s.baselined);
        row(ui, "Killed:", s.killed);
        row(ui, "Quarantined:", s.quarantined);
        row(ui, "Auto-killed:", s.auto_killed);
    });

    ui.add_space(20.0);
    let baselines = store::count(db, store::TREE_BASELINE).unwrap_or(0);
    ui.label(egui::RichText::new(format!("Baseline patterns learned: {}", baselines))
        .color(muted).size(13.0));
}

/// Theme: dark background, severity colors.
#[cfg(feature = "gui")]
fn f98_apply_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.override_text_color = Some(egui::Color32::from_rgb(0xe8, 0xe8, 0xe8));
    style.visuals.panel_fill = egui::Color32::from_rgb(0x0c, 0x0c, 0x12);
    style.visuals.window_fill = egui::Color32::from_rgb(0x0c, 0x0c, 0x12);
    ctx.set_style(style);
}

#[cfg(feature = "gui")]
fn severity_colors(severity: &Severity) -> (egui::Color32, egui::Color32) {
    match severity {
        Severity::Green  => (egui::Color32::from_rgb(0x50, 0xb4, 0x32), egui::Color32::from_rgb(0x2d, 0x5a, 0x2d)),
        Severity::Yellow => (egui::Color32::from_rgb(0xd4, 0xd4, 0x32), egui::Color32::from_rgb(0x5a, 0x5a, 0x2d)),
        Severity::Orange => (egui::Color32::from_rgb(0xff, 0x78, 0x14), egui::Color32::from_rgb(0x5a, 0x3a, 0x1a)),
        Severity::Red    => (egui::Color32::from_rgb(0xc8, 0x32, 0x32), egui::Color32::from_rgb(0x5a, 0x1a, 0x1a)),
    }
}

#[cfg(feature = "gui")]
fn module_icon(module: &Module) -> &'static str {
    match module {
        Module::Network => "net",
        Module::Process => "proc",
        Module::Cron => "cron",
        Module::Ssh => "ssh",
        Module::Files => "file",
        Module::Persistence => "persist",
        Module::Rootkit => "rkit",
        Module::Logs => "log",
    }
}
