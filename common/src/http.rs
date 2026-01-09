/// An HTTP header that can be parsed from a UTF8 string value.
pub trait ParseableHeader: std::str::FromStr
where
    Self::Err: std::fmt::Display,
{
    fn name() -> &'static http::HeaderName;
}

#[cfg(feature = "axum")]
pub mod extract {
    use axum::{
        extract::{FromRequestParts, OptionalFromRequestParts},
        response::{IntoResponse, Response},
    };

    #[derive(Debug, thiserror::Error)]
    pub enum HeaderRejection {
        #[error("Missing header `{0}`")]
        MissingHeader(&'static http::HeaderName),
        #[error("Invalid header `{0}`: not UTF-8")]
        InvalidUtf8(&'static http::HeaderName),
        #[error("Invalid header `{0}`: {1}")]
        InvalidHeaderValue(&'static http::HeaderName, String),
    }

    impl IntoResponse for HeaderRejection {
        fn into_response(self) -> Response {
            (http::StatusCode::BAD_REQUEST, self.to_string()).into_response()
        }
    }

    pub fn parse_header<T>(headers: &http::HeaderMap) -> Result<T, HeaderRejection>
    where
        T: super::ParseableHeader,
        T::Err: std::fmt::Display,
    {
        let name = T::name();
        let Some(value) = headers.get(name) else {
            return Err(HeaderRejection::MissingHeader(name));
        };
        let value_str = value
            .to_str()
            .map_err(|_| HeaderRejection::InvalidUtf8(name))?;
        let parsed = value_str
            .parse::<T>()
            .map_err(|e| HeaderRejection::InvalidHeaderValue(name, e.to_string()))?;
        Ok(parsed)
    }

    #[derive(Debug, Clone)]
    pub struct Header<T>(pub T);

    impl<S, T> FromRequestParts<S> for Header<T>
    where
        S: Send + Sync,
        T: super::ParseableHeader,
        T::Err: std::fmt::Display,
    {
        type Rejection = HeaderRejection;

        async fn from_request_parts(
            parts: &mut http::request::Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            parse_header(&parts.headers).map(Self)
        }
    }

    impl<S, T> OptionalFromRequestParts<S> for Header<T>
    where
        S: Send + Sync,
        T: super::ParseableHeader,
        T::Err: std::fmt::Display,
    {
        type Rejection = HeaderRejection;

        async fn from_request_parts(
            parts: &mut http::request::Parts,
            _state: &S,
        ) -> Result<Option<Self>, Self::Rejection> {
            match parse_header(&parts.headers) {
                Ok(value) => Ok(Some(Header(value))),
                Err(HeaderRejection::MissingHeader(_)) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    /// Workaround for https://github.com/tokio-rs/axum/issues/3623
    pub struct HeaderOpt<T>(pub Option<T>);

    impl<S, T> FromRequestParts<S> for HeaderOpt<T>
    where
        S: Send + Sync,
        T: super::ParseableHeader,
        T::Err: std::fmt::Display,
    {
        type Rejection = HeaderRejection;

        async fn from_request_parts(
            parts: &mut http::request::Parts,
            _state: &S,
        ) -> Result<Self, Self::Rejection> {
            match parse_header(&parts.headers) {
                Ok(value) => Ok(Self(Some(value))),
                Err(HeaderRejection::MissingHeader(_)) => Ok(Self(None)),
                Err(e) => Err(e),
            }
        }
    }
}
