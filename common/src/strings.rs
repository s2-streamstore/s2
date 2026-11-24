pub trait StrProps: std::fmt::Debug + Clone {
    const IS_PREFIX: bool;
    const FIELD_NAME: &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameProps;

impl StrProps for NameProps {
    const IS_PREFIX: bool = false;
    const FIELD_NAME: &'static str = "name";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdProps;

impl StrProps for IdProps {
    const IS_PREFIX: bool = false;
    const FIELD_NAME: &'static str = "id";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixProps;

impl StrProps for PrefixProps {
    const IS_PREFIX: bool = true;
    const FIELD_NAME: &'static str = "prefix";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StartAfterProps;

impl StrProps for StartAfterProps {
    const IS_PREFIX: bool = true;
    const FIELD_NAME: &'static str = "start-after";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlugProps;

impl StrProps for SlugProps {
    const IS_PREFIX: bool = false;
    const FIELD_NAME: &'static str = "slug";
}

/// Implement the shared trait suite for a validated `CompactString` newtype.
///
/// Requires `Self::validate_str(&str) -> Result<(), ValidationError>` on the target type.
macro_rules! impl_validated_str {
    ($name:ident < $t:ident : StrProps >) => {
        impl<$t: $crate::strings::StrProps> $name<$t> {
            fn try_from_compact(
                value: ::compact_str::CompactString,
            ) -> Result<Self, $crate::ValidationError> {
                Self::validate_str(&value)?;
                Ok(Self(value, ::std::marker::PhantomData))
            }
        }

        impl<$t: $crate::strings::StrProps> ::serde::Serialize for $name<$t> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de, $t: $crate::strings::StrProps> ::serde::Deserialize<'de> for $name<$t> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let s = ::compact_str::CompactString::deserialize(deserializer)?;
                Self::try_from_compact(s).map_err(::serde::de::Error::custom)
            }
        }

        impl<$t: $crate::strings::StrProps> ::std::convert::AsRef<str> for $name<$t> {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl<$t: $crate::strings::StrProps> ::std::ops::Deref for $name<$t> {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<$t: $crate::strings::StrProps> ::std::convert::TryFrom<String> for $name<$t> {
            type Error = $crate::ValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::validate_str(&value)?;
                Ok(Self(
                    ::compact_str::CompactString::from(value),
                    ::std::marker::PhantomData,
                ))
            }
        }

        impl<$t: $crate::strings::StrProps> ::std::convert::TryFrom<&str> for $name<$t> {
            type Error = $crate::ValidationError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl<$t: $crate::strings::StrProps> ::std::str::FromStr for $name<$t> {
            type Err = $crate::ValidationError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use ::compact_str::ToCompactString as _;
                Self::validate_str(s)?;
                Ok(Self(s.to_compact_string(), ::std::marker::PhantomData))
            }
        }

        impl<$t: $crate::strings::StrProps> ::std::fmt::Debug for $name<$t> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<$t: $crate::strings::StrProps> ::std::fmt::Display for $name<$t> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<$t: $crate::strings::StrProps> From<$name<$t>> for String {
            fn from(value: $name<$t>) -> Self {
                value.0.into_string()
            }
        }
    };
    ($name:ident) => {
        impl $name {
            fn try_from_compact(
                value: ::compact_str::CompactString,
            ) -> Result<Self, $crate::ValidationError> {
                Self::validate_str(&value)?;
                Ok(Self(value))
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let s = ::compact_str::CompactString::deserialize(deserializer)?;
                Self::try_from_compact(s).map_err(::serde::de::Error::custom)
            }
        }

        impl ::std::convert::AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl ::std::ops::Deref for $name {
            type Target = str;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl ::std::convert::TryFrom<String> for $name {
            type Error = $crate::ValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::validate_str(&value)?;
                Ok(Self(::compact_str::CompactString::from(value)))
            }
        }

        impl ::std::convert::TryFrom<&str> for $name {
            type Error = $crate::ValidationError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                value.parse()
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::ValidationError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                use ::compact_str::ToCompactString as _;
                Self::validate_str(s)?;
                Ok(Self(s.to_compact_string()))
            }
        }

        impl ::std::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0.into_string()
            }
        }
    };
}

pub(crate) use impl_validated_str;
