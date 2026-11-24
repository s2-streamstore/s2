use std::{ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

use crate::deep_size::DeepSize;

pub const MAX_FENCING_TOKEN_LENGTH: usize = 36;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("fencing token must not exceed {MAX_FENCING_TOKEN_LENGTH} bytes in length")]
pub struct FencingTokenTooLongError(pub usize);

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct FencingToken(CompactString);

impl FencingToken {
    fn validate_str(input: &str) -> Result<(), FencingTokenTooLongError> {
        if input.len() > MAX_FENCING_TOKEN_LENGTH {
            return Err(FencingTokenTooLongError(input.len()));
        }
        Ok(())
    }

    fn try_from_compact(input: CompactString) -> Result<Self, FencingTokenTooLongError> {
        Self::validate_str(&input)?;
        Ok(Self(input))
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for FencingToken {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .max_length(Some(MAX_FENCING_TOKEN_LENGTH))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for FencingToken {}

impl serde::Serialize for FencingToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for FencingToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        Self::try_from_compact(s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for FencingToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for FencingToken {
    type Error = FencingTokenTooLongError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        Self::validate_str(&input)?;
        Ok(Self(CompactString::from(input)))
    }
}

impl TryFrom<&str> for FencingToken {
    type Error = FencingTokenTooLongError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

impl FromStr for FencingToken {
    type Err = FencingTokenTooLongError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate_str(s)?;
        Ok(Self(s.to_compact_string()))
    }
}

impl From<FencingToken> for String {
    fn from(token: FencingToken) -> Self {
        token.0.into_string()
    }
}

impl AsRef<str> for FencingToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for FencingToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DeepSize for FencingToken {
    fn deep_size(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_conversions_and_serde_roundtrip() {
        let from_str = FencingToken::try_from("token-123").unwrap();
        let from_string = FencingToken::try_from("token-123".to_owned()).unwrap();
        let parsed: FencingToken = "token-123".parse().unwrap();
        assert_eq!(from_str, from_string);
        assert_eq!(from_str, parsed);
        assert_eq!(String::from(from_string), "token-123");

        let too_long = "a".repeat(MAX_FENCING_TOKEN_LENGTH + 1);
        assert_eq!(
            FencingToken::try_from(too_long.as_str()),
            Err(FencingTokenTooLongError(MAX_FENCING_TOKEN_LENGTH + 1))
        );
        assert_eq!(
            FencingToken::try_from(too_long.clone()),
            Err(FencingTokenTooLongError(MAX_FENCING_TOKEN_LENGTH + 1))
        );

        let json = serde_json::to_string(&from_str).unwrap();
        assert_eq!(json, r#""token-123""#);
        let decoded: FencingToken = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, from_str);
        assert!(serde_json::from_str::<FencingToken>(&format!(r#""{too_long}""#)).is_err());
    }
}
