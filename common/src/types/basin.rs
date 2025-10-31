use std::{marker::PhantomData, ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

use super::{
    ValidationError,
    strings::{NameProps, PrefixProps, StartAfterProps, StrProps},
};
use crate::{caps, types::resources::ListItemsRequest};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct BasinNameStr<T: StrProps>(CompactString, PhantomData<T>);

#[cfg(feature = "utoipa")]
impl<T> utoipa::PartialSchema for BasinNameStr<T>
where
    T: StrProps,
{
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .min_length((!T::IS_PREFIX).then_some(1))
            .max_length(Some(Self::MAX_LENGTH))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::ToSchema for BasinNameStr<T> where T: StrProps {}

impl<T: StrProps> serde::Serialize for BasinNameStr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, T: StrProps> serde::Deserialize<'de> for BasinNameStr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl<T: StrProps> BasinNameStr<T> {
    const MIN_LENGTH: usize = 8;
    const MAX_LENGTH: usize = caps::MAX_BASIN_NAME_LEN;
}

impl<T: StrProps> AsRef<str> for BasinNameStr<T> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: StrProps> Deref for BasinNameStr<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: StrProps> TryFrom<CompactString> for BasinNameStr<T> {
    type Error = ValidationError;

    fn try_from(name: CompactString) -> Result<Self, Self::Error> {
        if name.len() > Self::MAX_LENGTH {
            return Err(format!(
                "Basin {} must not exceed {} characters in length",
                T::FIELD_NAME,
                Self::MAX_LENGTH
            )
            .into());
        }

        if !T::IS_PREFIX && name.len() < Self::MIN_LENGTH {
            return Err(format!(
                "Basin {} should be at least {} characters in length",
                T::FIELD_NAME,
                Self::MIN_LENGTH
            )
            .into());
        }

        let mut chars = name.chars();

        let Some(first_char) = chars.next() else {
            return Ok(Self(name, PhantomData));
        };

        if !first_char.is_ascii_lowercase() && !first_char.is_ascii_digit() {
            return Err(format!(
                "Basin {} must begin with a lowercase letter or number",
                T::FIELD_NAME
            )
            .into());
        }

        if !T::IS_PREFIX
            && let Some(last_char) = chars.next_back()
            && !last_char.is_ascii_lowercase()
            && !last_char.is_ascii_digit()
        {
            return Err(format!(
                "Basin {} must end with a lowercase letter or number",
                T::FIELD_NAME
            )
            .into());
        }

        if chars.any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-') {
            return Err(format!(
                "Basin {} must comprise lowercase letters, numbers, and hyphens",
                T::FIELD_NAME
            )
            .into());
        }

        Ok(Self(name, PhantomData))
    }
}

impl<T: StrProps> FromStr for BasinNameStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_compact_string().try_into()
    }
}

impl<T: StrProps> std::fmt::Debug for BasinNameStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> std::fmt::Display for BasinNameStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> From<BasinNameStr<T>> for CompactString {
    fn from(value: BasinNameStr<T>) -> Self {
        value.0
    }
}

pub type BasinName = BasinNameStr<NameProps>;

pub type BasinNamePrefix = BasinNameStr<PrefixProps>;

impl Default for BasinNamePrefix {
    fn default() -> Self {
        BasinNameStr(CompactString::default(), PhantomData)
    }
}

impl From<BasinName> for BasinNamePrefix {
    fn from(value: BasinName) -> Self {
        Self(value.0, PhantomData)
    }
}

pub type BasinNameStartAfter = BasinNameStr<StartAfterProps>;

impl Default for BasinNameStartAfter {
    fn default() -> Self {
        BasinNameStr(CompactString::default(), PhantomData)
    }
}

pub type ListBasinsRequest = ListItemsRequest<BasinNamePrefix, BasinNameStartAfter>;

#[derive(Debug, Clone, Copy)]
pub enum BasinState {
    Active,
    Creating,
    Deleting,
}

#[derive(Debug, strum::Display, Clone, Copy, PartialEq, Eq, Default)]
pub enum BasinScope {
    #[strum(serialize = "aws:us-east-1")]
    #[default]
    AwsUsEast1,
}

#[derive(Debug, Clone)]
pub struct BasinInfo {
    pub name: BasinName,
    pub scope: BasinScope,
    pub state: BasinState,
}
