use std::{ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

use super::ValidationError;
use crate::caps;

fn validate_location_str(field_name: &str, location: &str) -> Result<(), ValidationError> {
    if location.chars().count() > caps::MAX_LOCATION_NAME_LEN {
        return Err(format!(
            "location {field_name} must be less than {} characters in length",
            caps::MAX_LOCATION_NAME_LEN + 1
        )
        .into());
    }

    if location
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != ':' && c != '-' && c != '.')
    {
        return Err(format!(
            "location {field_name} must comprise ASCII letters, numbers, colons, hyphens, and periods"
        )
        .into());
    }

    Ok(())
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct LocationName(CompactString);

impl LocationName {
    fn validate_str(location: &str) -> Result<(), ValidationError> {
        if location.is_empty() {
            return Err("location name must be at least 1 character in length".into());
        }

        validate_location_str("name", location)
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for LocationName {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .min_length(Some(1))
            .max_length(Some(caps::MAX_LOCATION_NAME_LEN))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for LocationName {}

impl serde::Serialize for LocationName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for LocationName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl AsRef<str> for LocationName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for LocationName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<CompactString> for LocationName {
    type Error = ValidationError;

    fn try_from(location: CompactString) -> Result<Self, Self::Error> {
        Self::validate_str(&location)?;
        Ok(Self(location))
    }
}

impl TryFrom<String> for LocationName {
    type Error = ValidationError;

    fn try_from(location: String) -> Result<Self, Self::Error> {
        location.to_compact_string().try_into()
    }
}

impl TryFrom<&str> for LocationName {
    type Error = ValidationError;

    fn try_from(location: &str) -> Result<Self, Self::Error> {
        location.to_compact_string().try_into()
    }
}

impl FromStr for LocationName {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl std::fmt::Debug for LocationName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for LocationName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<LocationName> for CompactString {
    fn from(value: LocationName) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct LocationInfo {
    pub name: LocationName,
    pub is_private: bool,
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::LocationName;

    #[rstest]
    #[case::single_char("a".to_owned())]
    #[case::aws_region("aws:us-east-1".to_owned())]
    #[case::uppercase_and_period("cloud:US-West-2.edge".to_owned())]
    #[case::max_len("a".repeat(crate::caps::MAX_LOCATION_NAME_LEN))]
    fn validate_name_ok(#[case] location: String) {
        assert_eq!(
            location.parse::<LocationName>().as_deref(),
            Ok(location.as_str())
        );
    }

    #[rstest]
    #[case::empty("".to_owned())]
    #[case::too_long("a".repeat(crate::caps::MAX_LOCATION_NAME_LEN + 1))]
    #[case::underscore("aws:us_east-1".to_owned())]
    #[case::slash("aws/us-east-1".to_owned())]
    #[case::space("aws:us east-1".to_owned())]
    #[case::multibyte("aws:é".to_owned())]
    fn validate_name_err(#[case] location: String) {
        location
            .parse::<LocationName>()
            .expect_err("expected validation error");
    }
}
