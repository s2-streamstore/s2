//! S2 Lite server implementation.

pub mod backend;
pub mod handlers;
pub mod init;
pub mod metrics;
pub mod server;
pub mod stream_id;

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header::ACCEPT_ENCODING};
    use s2_api::v1::stream::s2s::CompressionAlgorithm;

    #[test]
    fn lite_build_enables_s2s_gzip_and_zstd() {
        let mut headers = HeaderMap::new();

        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        assert_eq!(
            CompressionAlgorithm::from_accept_encoding(&headers),
            CompressionAlgorithm::Gzip
        );

        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("zstd"));
        assert_eq!(
            CompressionAlgorithm::from_accept_encoding(&headers),
            CompressionAlgorithm::Zstd
        );
    }
}
