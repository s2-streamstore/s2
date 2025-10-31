use std::{ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

use crate::deep_size::DeepSize;

pub const MAX_FENCING_TOKEN_LENGTH: usize = 36;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("Fencing token was longer than {MAX_FENCING_TOKEN_LENGTH} bytes in length: {0}")]
pub struct FencingTokenTooLongError(pub usize);

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct FencingToken(CompactString);

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
        FencingToken::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for FencingToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<CompactString> for FencingToken {
    type Error = FencingTokenTooLongError;

    fn try_from(input: CompactString) -> Result<Self, Self::Error> {
        if input.len() > MAX_FENCING_TOKEN_LENGTH {
            return Err(FencingTokenTooLongError(input.len()));
        }
        Ok(FencingToken(input))
    }
}

impl FromStr for FencingToken {
    type Err = FencingTokenTooLongError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_compact_string().try_into()
    }
}

impl From<FencingToken> for CompactString {
    fn from(token: FencingToken) -> Self {
        token.0
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
