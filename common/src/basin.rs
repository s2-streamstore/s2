use std::marker::PhantomData;

use compact_str::CompactString;
use jiff::Timestamp;

use super::{
    ValidationError,
    location::LocationName,
    strings::{NameProps, PrefixProps, StartAfterProps, StrProps, impl_validated_str},
};
use crate::{caps, resources::ListItemsRequest};

pub static BASIN_HEADER: http::HeaderName = http::HeaderName::from_static("s2-basin");

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct BasinNameStr<T: StrProps>(CompactString, PhantomData<T>);

impl<T: StrProps> BasinNameStr<T> {
    /// What `validate_str` accepts, apart from length.
    #[cfg(feature = "utoipa")]
    const PATTERN: &str = if T::IS_PREFIX {
        "^([a-z0-9][a-z0-9-]*)?$"
    } else {
        "^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"
    };

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

impl_validated_str!(BasinNameStr<T: StrProps>);

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
            .pattern(Some(Self::PATTERN))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::ToSchema for BasinNameStr<T>
where
    T: StrProps,
{
    fn name() -> std::borrow::Cow<'static, str> {
        if T::IS_PREFIX {
            std::borrow::Cow::Borrowed("BasinNamePrefixStr")
        } else {
            std::borrow::Cow::Borrowed("BasinNameStr")
        }
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

#[derive(Debug, Clone)]
pub struct BasinInfo {
    pub name: BasinName,
    pub location: Option<LocationName>,
    pub created_at: Timestamp,
    pub deleted_at: Option<Timestamp>,
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
    #[case::nul("abcd\0efg".to_owned())]
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
    #[case::nul("ab\0cd".to_owned())]
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
    #[case::nul("ab\0cd".to_owned())]
    fn validate_start_after_err(#[case] start_after: String) {
        BasinNameStr::<StartAfterProps>::validate_str(&start_after)
            .expect_err("expected validation error");
    }

    #[test]
    fn string_conversions_and_serde_roundtrip() {
        let from_str = super::BasinName::try_from("my-basin").unwrap();
        let from_string = super::BasinName::try_from("my-basin".to_owned()).unwrap();
        assert_eq!(from_str, from_string);
        assert_eq!(String::from(from_string), "my-basin");

        let json = serde_json::to_string(&from_str).unwrap();
        assert_eq!(json, r#""my-basin""#);
        let decoded: super::BasinName = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, from_str);
        assert!(serde_json::from_str::<super::BasinName>(r#""bad""#).is_err());
    }
}
