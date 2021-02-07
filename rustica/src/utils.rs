use crate::error::RusticaServerError;

use ring::rand;
use rand::{SecureRandom, SystemRandom};

pub fn build_force_command(hosts: &Vec<String>) -> Result<String, RusticaServerError> {
    // Build our script that will force authorization to the particular servers
    // we have access to
    let mut file_rand = [0; 4];

    let rng = SystemRandom::new();
    if let Err(_) = rng.fill(&mut file_rand) {
        return Err(RusticaServerError::Unknown)
    }
    
    let authorized_hosts = hosts.join(",");
    let file_rand = u32::from_be_bytes(file_rand);
    let mut force_command = String::new();
    force_command.push_str(&format!("export RUSTICA_AUTHORIZED_HOSTS={};", authorized_hosts));
    force_command.push_str(&format!("export LOGIN_SCRIPT=/tmp/rustica_login_{}.sh;", file_rand));
    let script = base64::encode(include_str!("../bash/verify.sh"));
    force_command.push_str(&format!("echo \"{}\" | base64 -d > $LOGIN_SCRIPT && chmod +x $LOGIN_SCRIPT && $LOGIN_SCRIPT", script));
    Ok(force_command)
}