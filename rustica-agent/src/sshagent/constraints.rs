use sshcerts::ssh::Reader;

use crate::sshagent::error::ParsingError;

#[derive(Debug)]
pub enum Constraint {
    Lifetime(u32),
    Confirm,
    Extension(String, Vec<u8>),
}

pub fn parse_constraints(buf: &[u8]) -> ParsingError<Vec<Constraint>> {
    let mut constraints = Vec::new();
    let mut reader = Reader::new(buf);
    let total_bytes = buf.len();
    while reader.get_offset() < total_bytes {
        let constraint_type = reader
            .read_raw_bytes(1)
            .map_err(|_| "Failed to read constraint type")?[0];
        match constraint_type {
            1 => {
                constraints.push(Constraint::Lifetime(
                    reader
                        .read_u32()
                        .map_err(|_| "Failed to read u32 for lifetime")?,
                ));
            }
            2 => constraints.push(Constraint::Confirm),
            255 => {
                let ext_name = reader
                    .read_string()
                    .map_err(|_| "Failed to read string for extension name")?;
                let ext_data = reader
                    .read_bytes()
                    .map_err(|_| "Failed to read bytes for extension data")?;
                constraints.push(Constraint::Extension(ext_name, ext_data));
            }
            _ => return Err("Unknown constraint type".into()),
        }
    }
    Ok(constraints)
}
