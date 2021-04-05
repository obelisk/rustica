use crate::error::RusticaServerError;

use ring::rand;
use rand::{SecureRandom, SystemRandom};

pub fn build_login_script(hosts: &Option<Vec<String>>, force_command: &Option<String>) -> Result<Option<String>, RusticaServerError> {
    // If no hosts are passed in then this should run on any host.
    // Thus we do not build a hostname check around the force-command.
    let hosts = match hosts {
        None => return Ok(force_command.clone()),
        Some(hosts) => hosts,
    };

    // We do want to restrict to hosts so we begin to
    // build our script that will force authorization to particular servers
    let mut file_rand = [0; 4];
    let rng = SystemRandom::new();
    if rng.fill(&mut file_rand).is_err() {
        return Err(RusticaServerError::Unknown)
    }

    // If force command is empty, we will search for the user's shell
    // falling back to /bin/bash if one cannot be found
    let force_command = match force_command {
        Some(x) => x.clone(),
        None => String::from("")
    };
    
    let authorized_hosts = hosts.join(",");
    let file_rand = u32::from_be_bytes(file_rand);
    let mut script = String::new();
    script.push_str(&format!("export FORCE_COMMAND={};", force_command));
    script.push_str(&format!("export RUSTICA_AUTHORIZED_HOSTS={};", authorized_hosts));
    script.push_str(&format!("export LOGIN_SCRIPT=/tmp/rustica_login_{}.sh;", file_rand));
    let import_script = base64::encode(include_str!("../bash/verify.sh"));
    script.push_str(&format!("echo \"{}\" | base64 -d > $LOGIN_SCRIPT && chmod +x $LOGIN_SCRIPT && $LOGIN_SCRIPT", import_script));
    Ok(Some(script))
}