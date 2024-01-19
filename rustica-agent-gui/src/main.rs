#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use std::{collections::HashMap, path::PathBuf};

use eframe::egui::{self, Grid, Sense, TextEdit, Button /*Sense*/};

use egui::ComboBox;

use home::home_dir;
use rustica_agent::{Agent, CertificateConfig, Signatory, YubikeyPIVKeyDescriptor, get_all_piv_keys, config::UpdatableConfiguration};
use rustica_agent::{ PrivateKey, Yubikey};
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

#[derive(Clone)]
struct YubikeyPIVKeyDescriptorWithUse {
    descriptor: YubikeyPIVKeyDescriptor,
    in_use: bool,
}

struct RusticaAgentGui {
    agent_dir: PathBuf,
    environments: Vec<PathBuf>,
    selected_environment: Option<usize>,
    runtime: Runtime,
    shutdown_rustica: Option<Sender<()>>,
    certificate_priority: bool,
    status: String,
    new_env_name: String,
    new_env_content: String,
    //fido_devices: Vec<FidoDeviceDescriptor>,
    //selected_fido_device: Option<usize>,
    piv_keys: HashMap<Vec<u8>, YubikeyPIVKeyDescriptorWithUse>,
    unlock_pin: String,
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

    // let fido_devices = list_fido_devices();
    // let selected_fido_device = if !fido_devices.is_empty() {
    //     Some(0)
    // } else {
    //     None
    // };

    let piv_keys = get_all_piv_keys().unwrap_or_default().into_iter().map(|x| (x.0, YubikeyPIVKeyDescriptorWithUse {
        descriptor: x.1,
        in_use: false,
    })).collect();

    Ok(RusticaAgentGui {
        agent_dir: home_dir.join(".rusticaagent"),
        environments,
        selected_environment,
        runtime: tokio::runtime::Runtime::new().unwrap(),
        shutdown_rustica: None,
        certificate_priority: true,
        status: String::new(),
        new_env_name: String::new(),
        new_env_content: String::new(),
        //fido_devices,
        //selected_fido_device,
        piv_keys,
        unlock_pin: String::new(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Log to stdout (if you run with `RUST_LOG=debug`).
    tracing_subscriber::fmt::init();

    let agent = load_environments()?; //.into_iter().map(|x| x.to_string_lossy().to_string()).collect();

    let options = eframe::NativeOptions::default();
    let _ = eframe::run_native(
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
                if let Some(selected_environment) = self.selected_environment {
                    ComboBox::from_label("Choose an environment")
                    .selected_text(format!("{}", &self.environments[selected_environment].to_string_lossy().to_string()))
                    .show_ui(ui, |ui| {
                        
                        for i in 0..self.environments.len() {
                            let value = ui.selectable_value(&mut &self.environments[i], &self.environments[selected_environment], &self.environments[i].to_string_lossy().to_string());
                            if value.clicked() {
                                self.selected_environment = Some(i);
                            }
                        }
                    });
                } else {
                    ui.label("There are no environments, please add one");
                };
                ui.add(egui::Separator::default());
                ui.vertical_centered(|ui| {
                    {
                        ui.label("Environment Name");
                        ui.text_edit_singleline(&mut self.new_env_name);
                    }
    
                    {
                        ui.label("Environment Data");
                        ui.text_edit_singleline(&mut self.new_env_content);
                    }
                    
                    if ui.button("Import").clicked() {
                        match base64::decode(&self.new_env_content) {
                            Ok(cfg) => {
                                let env_dir = self.agent_dir.join("environments");
                                let env_path = env_dir.join(&self.new_env_name);
                                if let Err(e) = std::fs::write(env_path, cfg) {
                                    self.status = format!("Could not add environemnt: {}", e);
                                } else {
                                    self.status = format!("New environment added");
                                    self.environments = check_create_dir(&env_dir).unwrap();
                                }
                            },
                            Err(_) => self.status = format!("Could not decode configuration"),
                        };
                    }
                });
            });
            ui.add(egui::Separator::default());
            if let Some(selected_env) = self.selected_environment.as_ref() {
                let config_path = PathBuf::from(&self.environments[*selected_env]);
                let config_name = config_path.file_name().unwrap().to_os_string();

                ui.horizontal(|ui| {
                    let toggle_label = match self.certificate_priority {
                        true => "Certificate Priority Enabled",
                        false => "Certificate Priority Disabled",
                    };
                    ui.toggle_value(&mut self.certificate_priority, toggle_label);
                });

                ui.horizontal(|ui| {
                    // if let Some(selected_fido_device) = self.selected_fido_device {
                    //     ComboBox::from_label("Choose a FIDO key")
                    //     .selected_text(format!("{}", &self.fido_devices[selected_fido_device].product_string.clone()))
                    //     .show_ui(ui, |ui| {
                    //         for i in 0..self.fido_devices.len() {
                    //             let value = ui.selectable_value(&mut &self.fido_devices[i], &self.fido_devices[selected_fido_device], &self.fido_devices[i].product_string.clone());
                    //             if value.clicked() {
                    //                 self.selected_fido_device = Some(i);
                    //             }
                    //         }
                    //     });
                    // } else {
                    //     ui.label("There are no connected FIDO devices");
                    // };
                    ui.add(egui::Separator::default());
                    ui.vertical_centered(|ui| {
                        ui.label("Additional Keys");
                        ui.horizontal(|ui| {
                            ui.label("Unlock Pin");
                            ui.add(TextEdit::singleline(&mut self.unlock_pin).password(true));
                        });
                        
                        Grid::new("additional_keys_list")
                            .num_columns(5)
                            .spacing([40.0, 4.0])
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label("Serial");
                                ui.label("Slot");
                                ui.label("Subject");
                                ui.label("Unlock Key");
                                ui.label("Use");
                                ui.end_row();
                                for (_, ui_key_handle) in &mut self.piv_keys {
                                    ui.label(ui_key_handle.descriptor.serial.to_string());
                                    ui.label(format!("{:?}", ui_key_handle.descriptor.slot));
                                    ui.label(format!("{}", ui_key_handle.descriptor.subject));
                                    if ui_key_handle.descriptor.pin.is_none() {
                                        if ui.button("Unlock").clicked() {
                                            let pin_bytes = self.unlock_pin.as_bytes().to_owned();
                                            let yk = Yubikey::open(ui_key_handle.descriptor.serial);
                                            if let Ok(mut yk) = yk {
                                                match yk.unlock(&pin_bytes, &hex::decode("010203040506070801020304050607080102030405060708").unwrap()) {
                                                    Ok(_) => ui_key_handle.descriptor.pin = Some(self.unlock_pin.clone()),
                                                    Err(_) => {
                                                        match yk.yk.get_pin_retries() {
                                                            Ok(retries) => self.status = format!("Unlock failed, {retries} tries remaining"),
                                                            Err(e) => self.status = format!("Could not get pin retries: {e}"),
                                                        }
                                                    }
                                                }
                                            } else {
                                                self.status = "Could not open Yubikey. Still connected?".to_owned();
                                            }
                                        }
                                    } else {
                                        ui.add(Button::new("Unlock").sense(Sense::hover()));
                                    }
                                    ui.checkbox(&mut ui_key_handle.in_use, "");
                                    ui.end_row();
                                }
                            });
                    });
                });

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
                        // match self.selected_fido_device.as_ref() {
                        //     Some(fido_device) => { 
                        //         let updatable_configuration = UpdatableConfiguration::new(&self.environments[*selected_env]);
                        //         match updatable_configuration {
                        //             Ok(updatable_configuration) => {
                        //                 let mut private_key = PrivateKey::from_path(key_path).unwrap();

                        //                 private_key.set_device_path(&self.fido_devices[*fido_device].path);

                        //                let pubkey = private_key.pubkey.clone();
                        //                let signatory = Signatory::Direct(private_key.into());

                        //                 let certificate_options = CertificateConfig::from(updatable_configuration.get_configuration().options.clone());

                        //                 let handler = rustica_agent::Handler {
                        //                     updatable_configuration: updatable_configuration.into(),
                        //                     cert: None.into(),
                        //                     pubkey,
                        //                     signatory,
                        //                     stale_at: 0.into(),
                        //                     certificate_options,
                        //                     identities:HashMap::new().into(),
                        //                     piv_identities: self.piv_keys.iter().filter_map(|x| if x.1.in_use {Some((x.0.clone(), x.1.descriptor.clone()))} else {None}).collect(),
                        //                     notification_function: None,
                        //                     certificate_priority: self.certificate_priority,
                                            
                        //                 };

                        //                 let socket_path =
                        //                     self.agent_dir.clone().join("rustica-agent.sock");

                        //                 if socket_path.exists() {
                        //                     if let Err(e) = std::fs::remove_file(&socket_path) {
                        //                         println!("Couldn't remove old socket file, Rustica might fail to start: {e}");
                        //                     }
                        //                 }

                        //                 let socket_path = socket_path.to_string_lossy().to_string();

                        //                 let (sds, sdr) = channel::<()>(1);
                        //                 self.runtime.spawn(async move {
                        //                     Agent::run_with_termination_channel(
                        //                         handler,
                        //                         socket_path,
                        //                         Some(sdr),
                        //                     )
                        //                     .await;
                        //                 });

                        //                 self.shutdown_rustica = Some(sds);
                        //             }
                        //             Err(e) => {
                        //                 println!("Could not parse config file: {e}")
                        //             }
                        //         };
                        //     }
                        //     _ => {
                        //         self.status = format!("You must have both an environment and FIDO device selected");
                        //     }
                        // }
                    }
                    });
                } else {
                    ui.label("There is no key, you'll need to generate and enroll one");
                }
            }

            ui.label(&self.status);
        });
    }
}
