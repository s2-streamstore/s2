use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{DeserializeOwned, Error as _, value::StrDeserializer},
};

/// A value of an enum that can gain variants after this crate version was released.
///
/// A variant that is not recognized deserializes as [`Unknown`](Self::Unknown) holding its wire
/// name, rather than failing the enclosing message, and serializes back as that name. For a
/// variant that carries data, only the name is retained.
///
/// A client can pass an unknown variant along. A service must reject it, using
/// [`known`](Self::known).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeKnown<T> {
    Known(T),
    Unknown(String),
}

impl<T: DeserializeOwned> MaybeKnown<T> {
    pub fn known(self) -> Result<T, s2_common::ValidationError> {
        match self {
            Self::Known(value) => Ok(value),
            Self::Unknown(name) => {
                deserialize_variant::<T>(&name).map_err(|err| err.message.into())
            }
        }
    }
}

impl<T> From<T> for MaybeKnown<T> {
    fn from(value: T) -> Self {
        Self::Known(value)
    }
}

impl<T: Serialize> Serialize for MaybeKnown<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Known(value) => value.serialize(serializer),
            Self::Unknown(name) => serializer.serialize_str(name),
        }
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for MaybeKnown<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        // An enum is represented as either its variant's name, or a single-entry map keyed by it.
        let variant = match &value {
            serde_json::Value::String(name) => Some(name),
            serde_json::Value::Object(map) if map.len() == 1 => map.keys().next(),
            _ => None,
        };
        if let Some(name) = variant
            && deserialize_variant::<T>(name).is_err_and(|err| err.unknown_variant)
        {
            return Ok(Self::Unknown(name.clone()));
        }
        T::deserialize(value)
            .map(Self::Known)
            .map_err(D::Error::custom)
    }
}

#[derive(Debug)]
struct VariantError {
    unknown_variant: bool,
    message: String,
}

impl std::fmt::Display for VariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VariantError {}

impl serde::de::Error for VariantError {
    fn custom<M: std::fmt::Display>(msg: M) -> Self {
        Self {
            unknown_variant: false,
            message: msg.to_string(),
        }
    }

    fn unknown_variant(variant: &str, expected: &'static [&'static str]) -> Self {
        Self {
            unknown_variant: true,
            message: serde::de::value::Error::unknown_variant(variant, expected).to_string(),
        }
    }
}

/// Deserialize `T` from just a variant name, which tells apart a name `T` does not have.
fn deserialize_variant<T: DeserializeOwned>(name: &str) -> Result<T, VariantError> {
    T::deserialize(StrDeserializer::new(name))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::v1::{access::AccessTokenInfo, config::StreamConfig};

    #[test]
    fn unknown_variants_parse_and_roundtrip_but_do_not_validate() {
        let token = json!({
            "id": "token",
            "auto_prefix_streams": false,
            "scope": {
                "basins": {"regex": "prod-.*"},
                "ops": ["read", "some-future-op"],
            },
        });
        let info: AccessTokenInfo = serde_json::from_value(token).unwrap();
        let wire = serde_json::to_value(&info).unwrap();
        assert_eq!(wire["scope"]["basins"], json!("regex"));
        assert_eq!(wire["scope"]["ops"], json!(["read", "some-future-op"]));

        let err = s2_common::access::AccessTokenScope::try_from(info.scope).unwrap_err();
        assert!(err.to_string().contains("unknown variant `regex`"), "{err}");

        // A recognized variant with a malformed payload is still an error, not an unknown.
        let config = json!({"retention_policy": {"age": "a week"}});
        assert!(serde_json::from_value::<StreamConfig>(config).is_err());
    }
}
