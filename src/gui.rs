#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod axml_fixer;
mod compression;
mod compression_detector;
mod detector;
mod fixer;
mod zip_structures;

use eframe::egui;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

fn main() -> Result<(), eframe::Error> {
    let icon_data = load_icon();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([950.0, 700.0])
            .with_min_inner_size([800.0, 600.0])
            .with_icon(icon_data),
        ..Default::default()
    };

    eframe::run_native(
        "APK Fixer",
        options,
        Box::new(|cc| {
            // 自定义浅色主题
            let mut visuals = egui::Visuals::light();
            visuals.window_rounding = egui::Rounding::same(10.0);
            visuals.panel_fill = egui::Color32::from_rgb(248, 249, 250);
            cc.egui_ctx.set_visuals(visuals);

            Ok(Box::new(ApkFixerApp::default()))
        }),
    )
}

fn load_icon() -> std::sync::Arc<egui::IconData> {
    let icon_bytes = include_bytes!("../icon.png");
    match eframe::icon_data::from_png_bytes(icon_bytes) {
        Ok(icon) => std::sync::Arc::new(icon),
        Err(_) => std::sync::Arc::new(egui::IconData {
            rgba: vec![],
            width: 0,
            height: 0,
        }),
    }
}

#[derive(Default)]
struct ApkFixerApp {
    input_path: String,
    output_path: String,
    ratio_threshold: String,
    log_messages: Arc<Mutex<Vec<LogMessage>>>,
    is_processing: Arc<Mutex<bool>>,
    report: Arc<Mutex<Option<Report>>>,
}

#[derive(Clone)]
struct LogMessage {
    level: LogLevel,
    text: String,
}

#[derive(Clone, PartialEq)]
enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[allow(dead_code)]
struct Report {
    issues_found: usize,
    compression_fixed: usize,
    encryption_fixed: usize,
    zipbomb_removed: usize,
    original_entries: usize,
    final_entries: usize,
    original_size: usize,
    final_size: usize,
}

impl ApkFixerApp {
    fn add_log(&self, level: LogLevel, text: String) {
        let mut logs = self.log_messages.lock().unwrap();
        logs.push(LogMessage { level, text });
    }

    fn clear_log(&self) {
        let mut logs = self.log_messages.lock().unwrap();
        logs.clear();
    }

    fn detect_apk(&mut self) {
        if self.input_path.is_empty() {
            self.add_log(LogLevel::Error, "Please select an APK file first".to_string());
            return;
        }

        let input = self.input_path.clone();
        let ratio: f64 = self.ratio_threshold.parse().unwrap_or(100.0);
        let logs = self.log_messages.clone();
        let is_processing = self.is_processing.clone();
        let report = self.report.clone();

        *is_processing.lock().unwrap() = true;
        self.clear_log();

        thread::spawn(move || {
            let add_log = |level: LogLevel, text: String| {
                logs.lock().unwrap().push(LogMessage { level, text });
            };

            add_log(LogLevel::Info, format!("Reading: {}", input));

            match std::fs::read(&input) {
                Ok(data) => {
                    add_log(LogLevel::Success, format!("Read successfully ({} bytes)", data.len()));
                    add_log(LogLevel::Info, "Scanning protection features...".to_string());

                    match detector::detect_issues(&data, ratio) {
                        Ok(issues) => {
                            let total = issues.invalid_compression_methods.len()
                                + issues.fake_encryption_flags.len()
                                + issues.zipbomb_entries.len();

                            if total == 0 {
                                add_log(LogLevel::Success, "No protection features detected".to_string());
                            } else {
                                add_log(LogLevel::Warning, format!("Detected {} issues:", total));

                                if !issues.invalid_compression_methods.is_empty() {
                                    add_log(
                                        LogLevel::Warning,
                                        format!("  {} invalid compression methods", issues.invalid_compression_methods.len()),
                                    );
                                }

                                if !issues.fake_encryption_flags.is_empty() {
                                    add_log(
                                        LogLevel::Warning,
                                        format!("  {} fake encryption flags", issues.fake_encryption_flags.len()),
                                    );
                                }

                                if !issues.zipbomb_entries.is_empty() {
                                    add_log(
                                        LogLevel::Warning,
                                        format!("  {} zip bomb decoys", issues.zipbomb_entries.len()),
                                    );
                                }

                                add_log(LogLevel::Info, "Click 'Fix' button to remove all issues".to_string());
                            }

                            *report.lock().unwrap() = Some(Report {
                                issues_found: total,
                                compression_fixed: 0,
                                encryption_fixed: 0,
                                zipbomb_removed: 0,
                                original_entries: 0,
                                final_entries: 0,
                                original_size: data.len(),
                                final_size: 0,
                            });
                        }
                        Err(e) => {
                            add_log(LogLevel::Error, format!("Detection failed: {}", e));
                        }
                    }
                }
                Err(e) => {
                    add_log(LogLevel::Error, format!("Failed to read file: {}", e));
                }
            }

            *is_processing.lock().unwrap() = false;
        });
    }

    fn fix_apk(&mut self) {
        if self.input_path.is_empty() {
            self.add_log(LogLevel::Error, "Please select an APK file first".to_string());
            return;
        }

        let input = self.input_path.clone();
        let output = if self.output_path.is_empty() {
            let path = PathBuf::from(&input);
            let stem = path.file_stem().unwrap().to_string_lossy();
            let ext = path.extension().unwrap_or_default().to_string_lossy();
            let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            parent.join(format!("{}_fixed.{}", stem, ext)).to_string_lossy().to_string()
        } else {
            self.output_path.clone()
        };

        let ratio: f64 = self.ratio_threshold.parse().unwrap_or(100.0);
        let logs = self.log_messages.clone();
        let is_processing = self.is_processing.clone();
        let report = self.report.clone();

        *is_processing.lock().unwrap() = true;
        self.clear_log();

        thread::spawn(move || {
            let add_log = |level: LogLevel, text: String| {
                logs.lock().unwrap().push(LogMessage { level, text });
            };

            add_log(LogLevel::Info, format!("Reading: {}", input));

            match std::fs::read(&input) {
                Ok(data) => {
                    add_log(LogLevel::Success, format!("Read successfully ({} bytes)", data.len()));
                    add_log(LogLevel::Info, "Fixing...".to_string());

                    match fixer::fix_all(&data, ratio) {
                        Ok((fixed_data, fix_report)) => {
                            add_log(LogLevel::Success, "Fix completed!".to_string());

                            if fix_report.compression_fixed > 0 {
                                add_log(
                                    LogLevel::Success,
                                    format!("  Fixed {} invalid compression methods", fix_report.compression_fixed),
                                );
                            }

                            if fix_report.encryption_fixed > 0 {
                                add_log(
                                    LogLevel::Success,
                                    format!("  Cleared {} fake encryption flags", fix_report.encryption_fixed),
                                );
                            }


                            if fix_report.zipbomb_removed > 0 {
                                add_log(
                                    LogLevel::Success,
                                    format!("  Removed {} zip bomb decoys", fix_report.zipbomb_removed),
                                );
                            }

                            add_log(
                                LogLevel::Info,
                                format!("Entries: {} -> {}", fix_report.original_entries, fix_report.final_entries),
                            );
                            add_log(
                                LogLevel::Info,
                                format!(
                                    "Size: {} -> {} ({:.1}%)",
                                    format_size(fix_report.original_size as u64),
                                    format_size(fix_report.final_size as u64),
                                    (fix_report.final_size as f64 / fix_report.original_size as f64) * 100.0
                                ),
                            );

                            add_log(LogLevel::Info, format!("Writing: {}", output));

                            match std::fs::write(&output, &fixed_data) {
                                Ok(_) => {
                                    add_log(LogLevel::Success, format!("Fixed APK saved: {}", output));
                                }
                                Err(e) => {
                                    add_log(LogLevel::Error, format!("Failed to write file: {}", e));
                                }
                            }

                            *report.lock().unwrap() = Some(Report {
                                issues_found: fix_report.compression_fixed
                                    + fix_report.encryption_fixed
                                    + fix_report.zipbomb_removed,
                                compression_fixed: fix_report.compression_fixed,
                                encryption_fixed: fix_report.encryption_fixed,
                                zipbomb_removed: fix_report.zipbomb_removed,
                                original_entries: fix_report.original_entries,
                                final_entries: fix_report.final_entries,
                                original_size: fix_report.original_size,
                                final_size: fix_report.final_size,
                            });
                        }
                        Err(e) => {
                            add_log(LogLevel::Error, format!("Fix failed: {}", e));
                        }
                    }
                }
                Err(e) => {
                    add_log(LogLevel::Error, format!("Failed to read file: {}", e));
                }
            }

            *is_processing.lock().unwrap() = false;
        });
    }
}

impl eframe::App for ApkFixerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 顶部面板
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(15.0);
            ui.vertical_centered(|ui| {
                ui.heading(egui::RichText::new("APK Fixer").size(24.0).strong().color(egui::Color32::from_rgb(41, 128, 185)));
                ui.label(egui::RichText::new("One-Click Protection Removal Tool").size(13.0).color(egui::Color32::from_rgb(127, 140, 141)));
            });
            ui.add_space(12.0);
        });

        // 中央面板
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(15.0);

            // 文件选择卡片（紧凑版）
            egui::Frame::none()
                .fill(egui::Color32::WHITE)
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(220, 227, 230)))
                .inner_margin(15.0)
                .rounding(10.0)
                .shadow(egui::epaint::Shadow {
                    offset: egui::vec2(0.0, 1.0),
                    blur: 4.0,
                    spread: 0.0,
                    color: egui::Color32::from_rgba_premultiplied(0, 0, 0, 8),
                })
                .show(ui, |ui| {
                    // 输入文件
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("[Input]").size(13.0).strong());
                        ui.add_space(5.0);
                        let text_edit = egui::TextEdit::singleline(&mut self.input_path)
                            .desired_width(ui.available_width() - 85.0)
                            .hint_text("Select APK file")
                            .font(egui::TextStyle::Body);
                        ui.add(text_edit);

                        let browse_btn = egui::Button::new(egui::RichText::new("Browse").size(13.0))
                            .fill(egui::Color32::from_rgb(52, 152, 219))
                            .rounding(5.0)
                            .min_size(egui::vec2(75.0, 32.0));

                        if ui.add(browse_btn).clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("APK Files", &["apk"])
                                .pick_file()
                            {
                                self.input_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(10.0);

                    // 输出文件
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("[Output]").size(13.0).strong());
                        ui.add_space(5.0);
                        let text_edit = egui::TextEdit::singleline(&mut self.output_path)
                            .desired_width(ui.available_width() - 85.0)
                            .hint_text("Auto-add '_fixed' if empty")
                            .font(egui::TextStyle::Body);
                        ui.add(text_edit);

                        let save_btn = egui::Button::new(egui::RichText::new("Save As").size(13.0))
                            .fill(egui::Color32::from_rgb(149, 165, 166))
                            .rounding(5.0)
                            .min_size(egui::vec2(75.0, 32.0));

                        if ui.add(save_btn).clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("APK Files", &["apk"])
                                .save_file()
                            {
                                self.output_path = path.display().to_string();
                            }
                        }
                    });

                    ui.add_space(10.0);

                    // 高级选项
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("[Threshold]").size(13.0).strong());
                        ui.add_space(5.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut self.ratio_threshold)
                                .desired_width(80.0)
                                .font(egui::TextStyle::Body)
                        );
                        if self.ratio_threshold.is_empty() {
                            self.ratio_threshold = "100".to_string();
                        }
                        ui.label(egui::RichText::new("(ratio > threshold = zip bomb)").size(12.0).color(egui::Color32::GRAY));
                    });
                });

            ui.add_space(12.0);

            // 操作按钮
            let is_processing = *self.is_processing.lock().unwrap();

            ui.horizontal(|ui| {
                ui.add_enabled_ui(!is_processing, |ui| {
                    let detect_btn = egui::Button::new(egui::RichText::new("[ Detect ]").size(15.0))
                        .fill(egui::Color32::from_rgb(52, 152, 219))
                        .rounding(6.0)
                        .min_size(egui::vec2(130.0, 42.0));

                    if ui.add(detect_btn).clicked() {
                        self.detect_apk();
                    }

                    ui.add_space(12.0);

                    let fix_btn = egui::Button::new(egui::RichText::new("[ Fix ]").size(15.0))
                        .fill(egui::Color32::from_rgb(46, 204, 113))
                        .rounding(6.0)
                        .min_size(egui::vec2(130.0, 42.0));

                    if ui.add(fix_btn).clicked() {
                        self.fix_apk();
                    }
                });

                if is_processing {
                    ui.add_space(15.0);
                    ui.spinner();
                    ui.label(egui::RichText::new("Processing...").size(14.0).color(egui::Color32::from_rgb(52, 152, 219)));
                }
            });

            ui.add_space(15.0);

            // 日志卡片（突出显示，占据剩余空间）
            egui::Frame::none()
                .fill(egui::Color32::WHITE)
                .stroke(egui::Stroke::new(2.0, egui::Color32::from_rgb(52, 152, 219)))
                .inner_margin(12.0)
                .rounding(10.0)
                .shadow(egui::epaint::Shadow {
                    offset: egui::vec2(0.0, 2.0),
                    blur: 6.0,
                    spread: 0.0,
                    color: egui::Color32::from_rgba_premultiplied(52, 152, 219, 30),
                })
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("[ Activity Log ]").size(16.0).strong().color(egui::Color32::from_rgb(52, 152, 219)));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.button(egui::RichText::new("Clear").size(12.0)).clicked() {
                                self.clear_log();
                            }
                        });
                    });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(5.0);

                    // 使用剩余所有空间
                    let available_height = ui.available_height() - 10.0;

                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(available_height)
                        .show(ui, |ui| {
                            let logs = self.log_messages.lock().unwrap();

                            if logs.is_empty() {
                                ui.vertical_centered(|ui| {
                                    ui.add_space(available_height / 2.0 - 30.0);
                                    ui.label(egui::RichText::new("Waiting for action...").size(14.0).color(egui::Color32::GRAY).italics());
                                });
                            } else {
                                for msg in logs.iter() {
                                    let (color, bg_color, icon) = match msg.level {
                                        LogLevel::Info => (
                                            egui::Color32::from_rgb(52, 73, 94),
                                            egui::Color32::from_rgb(236, 240, 241),
                                            "[i]"
                                        ),
                                        LogLevel::Success => (
                                            egui::Color32::from_rgb(39, 174, 96),
                                            egui::Color32::from_rgb(212, 239, 223),
                                            "[+]"
                                        ),
                                        LogLevel::Warning => (
                                            egui::Color32::from_rgb(243, 156, 18),
                                            egui::Color32::from_rgb(254, 242, 224),
                                            "[!]"
                                        ),
                                        LogLevel::Error => (
                                            egui::Color32::from_rgb(231, 76, 60),
                                            egui::Color32::from_rgb(248, 215, 218),
                                            "[x]"
                                        ),
                                    };

                                    egui::Frame::none()
                                        .fill(bg_color)
                                        .inner_margin(egui::Margin::symmetric(10.0, 5.0))
                                        .rounding(5.0)
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(egui::RichText::new(icon).size(13.0).color(color).strong());
                                                ui.label(egui::RichText::new(&msg.text).size(13.0).color(color));
                                            });
                                        });

                                    ui.add_space(3.0);
                                }
                            }
                        });
                });
        });

        // 定期刷新
        ctx.request_repaint();
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
