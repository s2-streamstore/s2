use compact_str::CompactString;

use super::{ValidationError, strings::impl_validated_str};
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
}

impl_validated_str!(LocationName);

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
