use serde::{Deserialize, Serialize};

/// The [`Maybe`] type represents an optional that might or might not be specified.
///
/// An [`Option`] is deserialized as [`None`] if either the value is not specified or the value is
/// `null`. [`Maybe`] allows us to distinguish between the two.
///
/// # Examples
///
/// ```
/// use s2_common::maybe::Maybe;
///
/// #[derive(Debug, PartialEq, Eq, serde::Deserialize)]
/// pub struct MyStruct {
///     #[serde(default)]
///     pub field: Maybe<Option<u32>>,
/// }
///
/// assert_eq!(
///     MyStruct { field: Maybe::Unspecified },
///     serde_json::from_str("{}").unwrap(),
/// );
///
/// assert_eq!(
///     MyStruct { field: Maybe::Specified(None) },
///     serde_json::from_str(r#"{ "field": null }"#).unwrap(),
/// );
///
/// assert_eq!(
///     MyStruct { field: Maybe::Specified(Some(10)) },
///     serde_json::from_str(r#"{ "field": 10 }"#).unwrap(),
/// );
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Maybe<T> {
    #[default]
    Unspecified,
    Specified(T),
}

impl<T> Maybe<T> {
    pub fn is_unspecified(&self) -> bool {
        matches!(self, Self::Unspecified)
    }

    pub fn map<U, F>(self, f: F) -> Maybe<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Self::Unspecified => Maybe::Unspecified,
            Self::Specified(x) => Maybe::Specified(f(x)),
        }
    }

    pub fn unwrap_or_default(self) -> T
    where
        T: Default,
    {
        match self {
            Self::Unspecified => T::default(),
            Self::Specified(x) => x,
        }
    }
}

impl<T> Maybe<Option<T>> {
    pub fn map_opt<U, F>(self, f: F) -> Maybe<Option<U>>
    where
        F: FnOnce(T) -> U,
    {
        self.map(|opt| opt.map(f))
    }

    pub fn try_map_opt<U, E, F>(self, f: F) -> Result<Maybe<Option<U>>, E>
    where
        F: FnOnce(T) -> Result<U, E>,
    {
        match self {
            Maybe::Unspecified => Ok(Maybe::Unspecified),
            Maybe::Specified(opt) => match opt {
                Some(value) => f(value).map(|converted| Maybe::Specified(Some(converted))),
                None => Ok(Maybe::Specified(None)),
            },
        }
    }

    pub fn opt_or_default_mut(&mut self) -> &mut T
    where
        T: Default,
    {
        match self {
            Maybe::Unspecified | Maybe::Specified(None) => {
                *self = Self::Specified(Some(T::default()));
                match self {
                    Self::Specified(Some(x)) => x,
                    _ => unreachable!(),
                }
            }
            Maybe::Specified(Some(x)) => x,
        }
    }
}

impl<T> From<T> for Maybe<T> {
    fn from(value: T) -> Self {
        Self::Specified(value)
    }
}

impl<T: Serialize> Serialize for Maybe<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Unspecified => serializer.serialize_none(),
            Self::Specified(v) => v.serialize(serializer),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Maybe<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = T::deserialize(deserializer)?;
        Ok(v.into())
    }
}
