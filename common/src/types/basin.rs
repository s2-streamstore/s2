use std::{marker::PhantomData, ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

use super::{
    ValidationError,
    strings::{NameProps, PrefixProps, StartAfterProps, StrProps},
};
use crate::{caps, types::resources::ListItemsRequest};

pub static BASIN_HEADER: http::HeaderName = http::HeaderName::from_static("s2-basin");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct BasinNameStr<T: StrProps>(CompactString, PhantomData<T>);

impl<T: StrProps> BasinNameStr<T> {
    fn validate_str(name: &str) -> Result<(), ValidationError> {
        if name.len() > caps::MAX_BASIN_NAME_LEN {
            return Err(format!(
                "basin {} must not exceed {} bytes in length",
                T::FIELD_NAME,
                caps::MAX_BASIN_NAME_LEN
            )
            .into());
        }

        if !T::IS_PREFIX && name.len() < caps::MIN_BASIN_NAME_LEN {
            return Err(format!(
                "basin {} should be at least {} bytes in length",
                T::FIELD_NAME,
                caps::MIN_BASIN_NAME_LEN
            )
            .into());
        }

        let mut chars = name.chars();

        let Some(first_char) = chars.next() else {
            return Ok(());
        };

        if !first_char.is_ascii_lowercase() && !first_char.is_ascii_digit() {
            return Err(format!(
                "basin {} must begin with a lowercase letter or number",
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
                "basin {} must end with a lowercase letter or number",
                T::FIELD_NAME
            )
            .into());
        }

        if chars.any(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-') {
            return Err(format!(
                "basin {} must comprise lowercase letters, numbers, and hyphens",
                T::FIELD_NAME
            )
            .into());
        }

        Ok(())
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::PartialSchema for BasinNameStr<T>
where
    T: StrProps,
{
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .min_length((!T::IS_PREFIX).then_some(caps::MIN_BASIN_NAME_LEN))
            .max_length(Some(caps::MAX_BASIN_NAME_LEN))
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
        Self::validate_str(&name)?;
        Ok(Self(name, PhantomData))
    }
}

impl<T: StrProps> FromStr for BasinNameStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate_str(s)?;
        Ok(Self(s.to_compact_string(), PhantomData))
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

impl From<BasinName> for BasinNameStartAfter {
    fn from(value: BasinName) -> Self {
        Self(value.0, PhantomData)
    }
}

impl crate::http::ParseableHeader for BasinName {
    fn name() -> &'static http::HeaderName {
        &BASIN_HEADER
    }
}

pub type ListBasinsRequest = ListItemsRequest<BasinNamePrefix, BasinNameStartAfter>;

#[derive(Debug, Clone, Copy)]
pub enum BasinState {
    Active,
    Creating,
    Deleting,
}

#[derive(Debug, strum::Display, Clone, Copy, PartialEq, Eq)]
pub enum BasinScope {
    #[strum(serialize = "aws:us-east-1")]
    AwsUsEast1,
}

#[derive(Debug, Clone)]
pub struct BasinInfo {
    pub name: BasinName,
    pub scope: Option<BasinScope>,
    pub state: BasinState,
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::{BasinNameStr, NameProps, PrefixProps, StartAfterProps};

    #[rstest]
    #[case::min_len("abcdefgh".to_owned())]
    #[case::starts_with_digit("1abcdefg".to_owned())]
    #[case::contains_hyphen("abcd-efg".to_owned())]
    #[case::max_len("a".repeat(crate::caps::MAX_BASIN_NAME_LEN))]
    fn validate_name_ok(#[case] name: String) {
        assert_eq!(BasinNameStr::<NameProps>::validate_str(&name), Ok(()));
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_BASIN_NAME_LEN + 1))]
    #[case::too_short("abcdefg".to_owned())]
    #[case::empty("".to_owned())]
    #[case::invalid_first_char("Abcdefgh".to_owned())]
    #[case::invalid_last_char("abcdefg-".to_owned())]
    #[case::invalid_characters("abcd_efg".to_owned())]
    fn validate_name_err(#[case] name: String) {
        BasinNameStr::<NameProps>::validate_str(&name).expect_err("expected validation error");
    }

    #[rstest]
    #[case::empty("".to_owned())]
    #[case::single_char("a".to_owned())]
    #[case::trailing_hyphen("abcdefg-".to_owned())]
    #[case::max_len("a".repeat(crate::caps::MAX_BASIN_NAME_LEN))]
    fn validate_prefix_ok(#[case] prefix: String) {
        assert_eq!(BasinNameStr::<PrefixProps>::validate_str(&prefix), Ok(()));
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_BASIN_NAME_LEN + 1))]
    #[case::invalid_first_char("-abc".to_owned())]
    #[case::invalid_characters("ab_cd".to_owned())]
    fn validate_prefix_err(#[case] prefix: String) {
        BasinNameStr::<PrefixProps>::validate_str(&prefix).expect_err("expected validation error");
    }

    #[rstest]
    #[case::empty("".to_owned())]
    #[case::single_char("a".to_owned())]
    #[case::trailing_hyphen("abcdefg-".to_owned())]
    fn validate_start_after_ok(#[case] start_after: String) {
        assert_eq!(
            BasinNameStr::<StartAfterProps>::validate_str(&start_after),
            Ok(())
        );
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_BASIN_NAME_LEN + 1))]
    #[case::invalid_first_char("-abc".to_owned())]
    #[case::invalid_characters("ab_cd".to_owned())]
    fn validate_start_after_err(#[case] start_after: String) {
        BasinNameStr::<StartAfterProps>::validate_str(&start_after)
            .expect_err("expected validation error");
    }
}
