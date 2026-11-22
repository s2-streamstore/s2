use std::{ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

use super::ValidationError;
use crate::caps;

fn validate_location_str(field_name: &str, location: &str) -> Result<(), ValidationError> {
    if location.chars().count() > caps::MAX_LOCATION_NAME_LEN {
        return Err(format!(
            "location {field_name} must be at most {} characters in length",
            caps::MAX_LOCATION_NAME_LEN
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

    fn try_from_compact(location: CompactString) -> Result<Self, ValidationError> {
        Self::validate_str(&location)?;
        Ok(Self(location))
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
        Self::try_from_compact(s).map_err(serde::de::Error::custom)
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

impl TryFrom<String> for LocationName {
    type Error = ValidationError;

    fn try_from(location: String) -> Result<Self, Self::Error> {
        Self::validate_str(&location)?;
        Ok(Self(CompactString::from(location)))
    }
}

impl TryFrom<&str> for LocationName {
    type Error = ValidationError;

    fn try_from(location: &str) -> Result<Self, Self::Error> {
        location.parse()
    }
}

impl FromStr for LocationName {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate_str(s)?;
        Ok(Self(s.to_compact_string()))
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

impl From<LocationName> for String {
    fn from(value: LocationName) -> Self {
        value.0.into_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsPrivateNet {
    pub service_name: String,
    pub private_dns_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateNet {
    Aws(AwsPrivateNet),
}

#[derive(Debug, Clone)]
pub struct LocationInfo {
    pub name: LocationName,
    pub is_private: bool,
    pub storage_classes: Vec<String>,
    pub default_storage_class: String,
    pub private_net: Option<PrivateNet>,
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
    #[case::nul("aws:us\0east-1".to_owned())]
    fn validate_name_err(#[case] location: String) {
        location
            .parse::<LocationName>()
            .expect_err("expected validation error");
    }

    #[test]
    fn string_conversions_and_serde_roundtrip() {
        let from_str = LocationName::try_from("aws:us-east-1").unwrap();
        let from_string = LocationName::try_from("aws:us-east-1".to_owned()).unwrap();
        assert_eq!(from_str, from_string);
        assert_eq!(String::from(from_string), "aws:us-east-1");

        let json = serde_json::to_string(&from_str).unwrap();
        assert_eq!(json, r#""aws:us-east-1""#);
        let decoded: LocationName = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, from_str);
        assert!(serde_json::from_str::<LocationName>(r#""""#).is_err());
    }
}
