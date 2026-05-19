use std::{marker::PhantomData, ops::Deref, str::FromStr};

use compact_str::{CompactString, ToCompactString};

use super::{
    ValidationError,
    strings::{PrefixProps, StartAfterProps, StrProps},
};
use crate::{caps, types::resources::ListItemsRequest};

fn validate_scope_str(field_name: &str, scope: &str) -> Result<(), ValidationError> {
    if scope.chars().count() > caps::MAX_SCOPE_NAME_LEN {
        return Err(format!(
            "scope {field_name} must be less than {} characters in length",
            caps::MAX_SCOPE_NAME_LEN + 1
        )
        .into());
    }

    if scope
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && c != ':' && c != '-' && c != '.')
    {
        return Err(format!(
            "scope {field_name} must comprise ASCII letters, numbers, colons, hyphens, and periods"
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
pub struct ScopeName(CompactString);

impl ScopeName {
    fn validate_str(scope: &str) -> Result<(), ValidationError> {
        validate_scope_str("name", scope)
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::PartialSchema for ScopeName {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .max_length(Some(caps::MAX_SCOPE_NAME_LEN))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl utoipa::ToSchema for ScopeName {}

impl serde::Serialize for ScopeName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ScopeName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl AsRef<str> for ScopeName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for ScopeName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<CompactString> for ScopeName {
    type Error = ValidationError;

    fn try_from(scope: CompactString) -> Result<Self, Self::Error> {
        Self::validate_str(&scope)?;
        Ok(Self(scope))
    }
}

impl TryFrom<String> for ScopeName {
    type Error = ValidationError;

    fn try_from(scope: String) -> Result<Self, Self::Error> {
        scope.to_compact_string().try_into()
    }
}

impl TryFrom<&str> for ScopeName {
    type Error = ValidationError;

    fn try_from(scope: &str) -> Result<Self, Self::Error> {
        scope.to_compact_string().try_into()
    }
}

impl FromStr for ScopeName {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl std::fmt::Debug for ScopeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for ScopeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<ScopeName> for CompactString {
    fn from(value: ScopeName) -> Self {
        value.0
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "rkyv",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct ScopeNameStr<T: StrProps>(CompactString, PhantomData<T>);

impl<T: StrProps> ScopeNameStr<T> {
    fn validate_str(scope: &str) -> Result<(), ValidationError> {
        validate_scope_str(T::FIELD_NAME, scope)
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::PartialSchema for ScopeNameStr<T>
where
    T: StrProps,
{
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::Object::builder()
            .schema_type(utoipa::openapi::Type::String)
            .max_length(Some(caps::MAX_SCOPE_NAME_LEN))
            .into()
    }
}

#[cfg(feature = "utoipa")]
impl<T> utoipa::ToSchema for ScopeNameStr<T> where T: StrProps {}

impl<T: StrProps> serde::Serialize for ScopeNameStr<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, T: StrProps> serde::Deserialize<'de> for ScopeNameStr<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = CompactString::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl<T: StrProps> AsRef<str> for ScopeNameStr<T> {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<T: StrProps> Deref for ScopeNameStr<T> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: StrProps> TryFrom<CompactString> for ScopeNameStr<T> {
    type Error = ValidationError;

    fn try_from(scope: CompactString) -> Result<Self, Self::Error> {
        Self::validate_str(&scope)?;
        Ok(Self(scope, PhantomData))
    }
}

impl<T: StrProps> TryFrom<String> for ScopeNameStr<T> {
    type Error = ValidationError;

    fn try_from(scope: String) -> Result<Self, Self::Error> {
        scope.to_compact_string().try_into()
    }
}

impl<T: StrProps> TryFrom<&str> for ScopeNameStr<T> {
    type Error = ValidationError;

    fn try_from(scope: &str) -> Result<Self, Self::Error> {
        scope.to_compact_string().try_into()
    }
}

impl<T: StrProps> FromStr for ScopeNameStr<T> {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl<T: StrProps> std::fmt::Debug for ScopeNameStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> std::fmt::Display for ScopeNameStr<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<T: StrProps> From<ScopeNameStr<T>> for CompactString {
    fn from(value: ScopeNameStr<T>) -> Self {
        value.0
    }
}

pub type ScopeNamePrefix = ScopeNameStr<PrefixProps>;

impl Default for ScopeNamePrefix {
    fn default() -> Self {
        ScopeNameStr(CompactString::default(), PhantomData)
    }
}

impl From<ScopeName> for ScopeNamePrefix {
    fn from(value: ScopeName) -> Self {
        Self(value.0, PhantomData)
    }
}

pub type ScopeNameStartAfter = ScopeNameStr<StartAfterProps>;

impl Default for ScopeNameStartAfter {
    fn default() -> Self {
        ScopeNameStr(CompactString::default(), PhantomData)
    }
}

impl From<ScopeName> for ScopeNameStartAfter {
    fn from(value: ScopeName) -> Self {
        Self(value.0, PhantomData)
    }
}

pub type ListScopesRequest = ListItemsRequest<ScopeNamePrefix, ScopeNameStartAfter>;

#[derive(Debug, Clone)]
pub struct ScopeInfo {
    pub name: ScopeName,
    pub is_public: bool,
    pub description: Option<String>,
}

#[cfg(test)]
mod test {
    use rstest::rstest;

    use super::{ScopeName, ScopeNamePrefix, ScopeNameStartAfter, ScopeNameStr};
    use crate::types::strings::{PrefixProps, StartAfterProps};

    #[rstest]
    #[case::empty("")]
    #[case::aws_region("aws:us-east-1")]
    #[case::uppercase_and_period("cloud:US-West-2.edge")]
    #[case::max_len("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    fn validate_name_ok(#[case] scope: &str) {
        assert_eq!(scope.parse::<ScopeName>().as_deref(), Ok(scope));
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_SCOPE_NAME_LEN + 1))]
    #[case::underscore("aws:us_east-1".to_owned())]
    #[case::slash("aws/us-east-1".to_owned())]
    #[case::space("aws:us east-1".to_owned())]
    #[case::multibyte("aws:é".to_owned())]
    fn validate_name_err(#[case] scope: String) {
        scope
            .parse::<ScopeName>()
            .expect_err("expected validation error");
    }

    #[rstest]
    #[case::empty("")]
    #[case::aws_region("aws:us-east-1")]
    #[case::uppercase_and_period("cloud:US-West-2.edge")]
    #[case::max_len("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    fn validate_prefix_ok(#[case] prefix: &str) {
        assert_eq!(
            prefix.parse::<ScopeNameStr<PrefixProps>>().as_deref(),
            Ok(prefix)
        );
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_SCOPE_NAME_LEN + 1))]
    #[case::underscore("aws:us_east-1".to_owned())]
    #[case::slash("aws/us-east-1".to_owned())]
    #[case::space("aws:us east-1".to_owned())]
    #[case::multibyte("aws:é".to_owned())]
    fn validate_prefix_err(#[case] prefix: String) {
        prefix
            .parse::<ScopeNameStr<PrefixProps>>()
            .expect_err("expected validation error");
    }

    #[rstest]
    #[case::empty("")]
    #[case::aws_region("aws:us-east-1")]
    #[case::uppercase_and_period("cloud:US-West-2.edge")]
    #[case::max_len("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    fn validate_start_after_ok(#[case] start_after: &str) {
        assert_eq!(
            start_after
                .parse::<ScopeNameStr<StartAfterProps>>()
                .as_deref(),
            Ok(start_after)
        );
    }

    #[rstest]
    #[case::too_long("a".repeat(crate::caps::MAX_SCOPE_NAME_LEN + 1))]
    #[case::underscore("aws:us_east-1".to_owned())]
    #[case::slash("aws/us-east-1".to_owned())]
    #[case::space("aws:us east-1".to_owned())]
    #[case::multibyte("aws:é".to_owned())]
    fn validate_start_after_err(#[case] start_after: String) {
        start_after
            .parse::<ScopeNameStr<StartAfterProps>>()
            .expect_err("expected validation error");
    }

    #[rstest]
    #[case::name("aws:us-east-1".parse::<ScopeName>().unwrap())]
    fn list_key_conversions(#[case] scope: ScopeName) {
        assert_eq!(
            ScopeNamePrefix::from(scope.clone()).as_ref(),
            "aws:us-east-1"
        );
        assert_eq!(ScopeNameStartAfter::from(scope).as_ref(), "aws:us-east-1");
    }
}
