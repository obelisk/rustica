extern crate serde;

use self::serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use super::pubkey::PublicKey;
use std::fmt;

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a valid public key")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<PublicKey, E> {
                PublicKey::from_string(value).map_err(|e| E::custom(e.to_string()))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}
