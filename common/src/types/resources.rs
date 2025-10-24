use std::{num::NonZeroUsize, ops::Deref};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub values: Vec<T>,
    pub has_more: bool,
}

impl<T> Page<T> {
    pub fn new_empty() -> Self {
        Self {
            values: Vec::new(),
            has_more: false,
        }
    }

    pub fn new(values: impl Into<Vec<T>>, has_more: bool) -> Self {
        Self {
            values: values.into(),
            has_more,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ListLimit(NonZeroUsize);

impl ListLimit {
    const MAX: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

    pub fn get(&self) -> NonZeroUsize {
        self.0
    }

    pub fn as_usize(&self) -> usize {
        self.0.get()
    }
}

impl Default for ListLimit {
    fn default() -> Self {
        Self(Self::MAX)
    }
}

impl From<usize> for ListLimit {
    fn from(value: usize) -> Self {
        Self(NonZeroUsize::new(value).unwrap_or(Self::MAX).min(Self::MAX))
    }
}

impl From<ListLimit> for usize {
    fn from(value: ListLimit) -> Self {
        value.as_usize()
    }
}

#[derive(Debug, Clone)]
pub struct ListItemsRequestParts<P, S> {
    pub prefix: P,
    pub start_after: S,
    pub limit: ListLimit,
}

#[derive(Debug, Clone)]
pub struct ListItemsRequest<P, S>(ListItemsRequestParts<P, S>);

impl<P, S> ListItemsRequest<P, S> {
    pub fn parts(&self) -> &ListItemsRequestParts<P, S> {
        &self.0
    }
}

impl<P, S> From<ListItemsRequest<P, S>> for ListItemsRequestParts<P, S> {
    fn from(ListItemsRequest(parts): ListItemsRequest<P, S>) -> Self {
        parts
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("`start_after` must be greater than or equal to the `prefix`")]
pub struct StartAfterLessThanPrefixError;

impl<P, S> TryFrom<ListItemsRequestParts<P, S>> for ListItemsRequest<P, S>
where
    P: Deref<Target = str>,
    S: Deref<Target = str>,
{
    type Error = StartAfterLessThanPrefixError;

    fn try_from(parts: ListItemsRequestParts<P, S>) -> Result<Self, Self::Error> {
        let start_after: &str = &parts.start_after;
        let prefix: &str = &parts.prefix;

        if !start_after.is_empty() && !prefix.is_empty() && start_after < prefix {
            return Err(StartAfterLessThanPrefixError);
        }

        Ok(Self(parts))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum CreateMode {
    CreateOnly,
    #[default]
    CreateOrReconfigure,
}
