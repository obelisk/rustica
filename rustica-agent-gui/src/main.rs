#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::path::{PathBuf};

use eframe::egui::{self, Sense};

use egui::ComboBox;

use home::home_dir;

#[derive(Debug)]
enum RusticaAgentGuiError {
    UnableToDetermineHomeDir,
    UnableToCreateDir(String),
    RequiredDirIsFile(Box<PathBuf>),
    CouldNotReadFolder(Box<PathBuf>),
}

impl std::fmt::Display for RusticaAgentGuiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            RusticaAgentGuiError::UnableToDetermineHomeDir => write!(f, "Cannot determine your home directory so I don't know where to find keys and configs"),
            RusticaAgentGuiError::UnableToCreateDir(ref e) => write!(f, "When we tried to create a directory but we got error: {e}"),
            RusticaAgentGuiError::RequiredDirIsFile(ref e) => write!(f, "There was a regular file where we needed a directory: {}", e.to_string_lossy()),
            RusticaAgentGuiError::CouldNotReadFolder(ref e) => write!(f, "We needed to read the following folder but failed: {}", e.to_string_lossy()),
        }
    }
}

impl std::error::Error for RusticaAgentGuiError {}

fn check_create_dir<'a, T>(path: T) -> Result<Vec<PathBuf>, RusticaAgentGuiError> where T: Into<&'a PathBuf> {
    let path: &PathBuf = path.into();
    match (path.exists(), path.is_dir()) {
        (false, _) => {
            std::fs::create_dir(&path).map_err(|e| RusticaAgentGuiError::UnableToCreateDir(e.to_string()))?;
            return Ok(vec![]);
        },
        (true, false) => return Err(RusticaAgentGuiError::RequiredDirIsFile(Box::new(path.to_owned()))),
        (true, true) => {
            Ok(path
                .read_dir()
                .map_err(|_| RusticaAgentGuiError::CouldNotReadFolder(Box::new(path.to_owned())))?
                .filter_map(|file| {
                    file.ok().map(|f| {
                        f.path()
                    })
                }).collect())
        },
    }
}

fn load_environments() -> Result<Vec<PathBuf>, RusticaAgentGuiError> {
    let home_dir = home_dir().ok_or(RusticaAgentGuiError::UnableToDetermineHomeDir)?;

    // Make sure the Rustica Agent home directory exists, and is alright
    let rustica_agent_home = home_dir.as_path().join(".rusticaagent");
    check_create_dir(&rustica_agent_home)?;

    // Make sure the keys directory exists and is alright
    let keys_folder = rustica_agent_home.join("keys");
    check_create_dir(&keys_folder)?;
        

    // Make sure the config directory exists and is alright
    let config_folder = rustica_agent_home.join("environments");
    Ok(check_create_dir(&config_folder)?)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Log to stdout (if you run with `RUST_LOG=debug`).
    tracing_subscriber::fmt::init();

    let environments:Vec<String> = load_environments()?.into_iter().map(|x| x.to_string_lossy().to_string()).collect();
    let selected_environment = if !environments.is_empty() { Some(0) } else { None };

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Rustica Agent",
        options,
        Box::new(move |_cc| Box::new(RusticaAgentGui {
            environments,
            selected_environment: selected_environment,
        })),
    );

    Ok(())
}

struct RusticaAgentGui {
    environments: Vec<String>,
    selected_environment: Option<usize>,
}

// Use this to load in environments on boot?
impl Default for RusticaAgentGui {
    fn default() -> Self {
        Self {
            environments: vec![],
            selected_environment: None,

        }
    }
}

impl eframe::App for RusticaAgentGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            // Heading for the application
            ui.heading("Rustica Agent");
            
            // Create the UI for selecting different environments
            ui.horizontal(|ui| {
                if let Some(mut selected_environment) = self.selected_environment {
                ComboBox::from_label("Choose an environment").show_index(
                    ui,
                    &mut selected_environment,
                    self.environments.len(),
                    |i| self.environments[i].to_owned())
                } else {
                    ui.label("There are no environments, please add one")
                };
                ui.add(egui::Separator::default());
                let response = ui.add(egui::Button::new("Import"));

                response.context_menu(|ui| {
                    ui.heading("Import Base64 Encoded Environment");

                    if ui.button("Close the menu").clicked() {
                        ui.close_menu();
                    }
                });

                
                //ui.add(egui::Label::new("Import Environment").sense(Sense::click()));
            });
            //ui.add(egui::Slider::new(&mut self.age, 0..=120).text("age"));
            if ui.button("Click each year").clicked() {
                
            }
            ui.label(format!("Hello Cross Platform Rustica Agent UI"));
        });
    }
}