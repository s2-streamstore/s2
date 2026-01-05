use std::{fmt::Display, str::FromStr};

pub trait ExtractableHeader: FromStr
where
    Self::Err: Display,
{
    fn name() -> &'static http::HeaderName;
}
