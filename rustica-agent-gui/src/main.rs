#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::{collections::HashMap, path::PathBuf};

use eframe::egui::{self /*Sense*/};

use egui::ComboBox;

use home::home_dir;
use rustica_agent::{Agent, CertificateConfig, RusticaServer, Signatory};
use sshcerts::PrivateKey;
use tokio::{
    runtime::Runtime,
    sync::mpsc::{channel, Sender},
};

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

struct RusticaAgentGui {
    agent_dir: PathBuf,
    environments: Vec<PathBuf>,
    selected_environment: Option<usize>,
    runtime: Runtime,
    shutdown_rustica: Option<Sender<()>>,
    certificate_priority: bool,
}

fn check_create_dir<'a, T>(path: T) -> Result<Vec<PathBuf>, RusticaAgentGuiError>
where
    T: Into<&'a PathBuf>,
{
    let path: &PathBuf = path.into();
    match (path.exists(), path.is_dir()) {
        (false, _) => {
            std::fs::create_dir(&path)
                .map_err(|e| RusticaAgentGuiError::UnableToCreateDir(e.to_string()))?;
            return Ok(vec![]);
        }
        (true, false) => {
            return Err(RusticaAgentGuiError::RequiredDirIsFile(Box::new(
                path.to_owned(),
            )))
        }
        (true, true) => Ok(path
            .read_dir()
            .map_err(|_| RusticaAgentGuiError::CouldNotReadFolder(Box::new(path.to_owned())))?
            .filter_map(|file| file.ok().map(|f| f.path()))
            .collect()),
    }
}

fn load_environments() -> Result<RusticaAgentGui, RusticaAgentGuiError> {
    let home_dir = home_dir().ok_or(RusticaAgentGuiError::UnableToDetermineHomeDir)?;

    // Make sure the Rustica Agent home directory exists, and is alright
    let rustica_agent_home = home_dir.as_path().join(".rusticaagent");
    check_create_dir(&rustica_agent_home)?;

    // Make sure the keys directory exists and is alright
    let keys_folder = rustica_agent_home.join("keys");
    check_create_dir(&keys_folder)?;

    // Make sure the config directory exists and is alright
    let config_folder = rustica_agent_home.join("environments");
    let environments = check_create_dir(&config_folder)?;
    let selected_environment = if !environments.is_empty() {
        Some(0)
    } else {
        None
    };

    Ok(RusticaAgentGui {
        agent_dir: home_dir.join(".rusticaagent"),
        environments,
        selected_environment,
        runtime: tokio::runtime::Runtime::new().unwrap(),
        shutdown_rustica: None,
        certificate_priority: true,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Log to stdout (if you run with `RUST_LOG=debug`).
    tracing_subscriber::fmt::init();

    let agent = load_environments()?; //.into_iter().map(|x| x.to_string_lossy().to_string()).collect();

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Rustica Agent",
        options,
        Box::new(move |_cc| Box::new(agent)),
    );

    Ok(())
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
                        |i| self.environments[i].to_string_lossy().to_string(),
                    )
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
            });
            if let Some(selected_env) = self.selected_environment.as_ref() {
                let config_path = PathBuf::from(&self.environments[*selected_env]);
                let config_name = config_path.file_name().unwrap().to_os_string();

                let toggle_label = match self.certificate_priority {
                    true => "Certificate Priority Enabled",
                    false => "Certificate Priority Disabled",
                };
                ui.toggle_value(&mut self.certificate_priority, toggle_label);

                let key_path = self.agent_dir.clone().join("keys").join(config_name);
                if key_path.exists() && key_path.is_file() {
                    ui.horizontal(|ui| {
                        if ui.button("Stop").clicked() {
                        if let Some(sds) = &self.shutdown_rustica {
                            let sds = sds.to_owned();
                            self.runtime.block_on(async move {
                                sds.send(()).await.unwrap();
                            })
                        }
                    }
                        if ui.button("Start").clicked() {
                        if let Some(selected_env) = self.selected_environment.as_ref() {
                            let config = std::fs::read(&self.environments[*selected_env]).unwrap();
                            match toml::from_slice::<rustica_agent::Config>(&config) {
                                Ok(c) => {
                                    let server = RusticaServer::new(
                                        c.server.unwrap(),
                                        c.ca_pem.unwrap(),
                                        c.mtls_cert.unwrap(),
                                        c.mtls_key.unwrap(),
                                        self.runtime.handle().to_owned(),
                                    );

                                    let private_key = PrivateKey::from_path(key_path).unwrap();

                                    let pubkey = private_key.pubkey.clone();
                                    let signatory = Signatory::Direct(private_key);

                                    let handler = rustica_agent::Handler {
                                        server,
                                        cert: None,
                                        pubkey,
                                        signatory,
                                        stale_at: 0,
                                        certificate_options: CertificateConfig::from(c.options),
                                        identities: HashMap::new(),
                                        piv_identities: HashMap::new(),
                                        notification_function: None,
                                        certificate_priority: self.certificate_priority,
                                    };

                                    let socket_path =
                                        self.agent_dir.clone().join("rustica-agent.sock");

                                    if socket_path.exists() {
                                        if let Err(e) = std::fs::remove_file(&socket_path) {
                                            println!("Couldn't remove old socket file, Rustica might fail to start: {e}");
                                        }
                                    }

                                    let socket_path = socket_path.to_string_lossy().to_string();

                                    let (sds, sdr) = channel::<()>(1);
                                    self.runtime.spawn(async move {
                                        Agent::run_with_termination_channel(
                                            handler,
                                            socket_path,
                                            Some(sdr),
                                        )
                                        .await;
                                    });

                                    self.shutdown_rustica = Some(sds);
                                }
                                Err(e) => {
                                    println!("Could not parse config file: {e}")
                                }
                            };
                        }
                    }
                    });
                } else {
                    ui.label("There is no key, you'll need to generate and enroll one");
                }
            }

            ui.label(format!("Rustica Status Here"));
        });
    }
}
