use std::convert::TryFrom;

use sshcerts::yubikey::piv::SlotId;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    /// The slot on the Yubikey to use for creating new client mTLS
    /// certificates
    #[serde(deserialize_with = "parse_slot")]
    slot: SlotId,
}

pub fn parse_slot<'de, D>(deserializer: D) -> Result<SlotId, D::Error>
where
    D: serde::Deserializer<'de>
{
    let slot = String::deserialize(deserializer)?;
    // If first character is R, then we need to parse the nice
    // notation
    if (slot.len() == 2 || slot.len() == 3) && slot.starts_with('R') {
        let slot_value = slot[1..].parse::<u8>();
        match slot_value {
            Ok(v) if v <= 20 => Ok(SlotId::try_from(0x81_u8 + v).unwrap()),
            _ => Err(serde::de::Error::custom("Invalid Slot")),
        }
    } else if slot.len() == 4 && slot.starts_with("0x") {
        let slot_value = hex::decode(&slot[2..]).unwrap()[0];
        Ok(SlotId::try_from(slot_value).unwrap())
    } else {
        Err(serde::de::Error::custom("Invalid Slot"))
    }
}