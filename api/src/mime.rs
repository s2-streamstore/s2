use mime::Mime;

#[derive(Debug, Clone, Copy)]
pub enum JsonOrProto {
    Json,
    Proto,
}

impl JsonOrProto {
    pub fn from_mime(mime: &Mime) -> Option<Self> {
        if is_json(mime) {
            Some(JsonOrProto::Json)
        } else if is_protobuf(mime) {
            Some(JsonOrProto::Proto)
        } else {
            None
        }
    }
}

/// MIME type parsed from `Content-Type` header.
pub fn content_type(headers: &http::HeaderMap) -> Option<Mime> {
    headers.get(http::header::CONTENT_TYPE).and_then(parse)
}

/// First MIME type present in the `Accept` header.
pub fn accept(headers: &http::HeaderMap) -> Option<Mime> {
    headers.get(http::header::ACCEPT).and_then(parse)
}

/// Parse the **first** MIME type from a header value.
pub fn parse(header: &http::HeaderValue) -> Option<Mime> {
    header.to_str().ok()?.split(',').next()?.trim().parse().ok()
}

pub fn is_json(mime: &mime::Mime) -> bool {
    mime.type_() == mime::APPLICATION
        && (mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON))
}

pub fn is_protobuf(mime: &mime::Mime) -> bool {
    mime.type_() == mime::APPLICATION && {
        let s = mime.subtype().as_str();
        s.eq_ignore_ascii_case("protobuf") || s.eq_ignore_ascii_case("x-protobuf")
    }
}

pub fn is_s2s_proto(mime: &Mime) -> bool {
    mime.type_().as_str().eq_ignore_ascii_case("s2s")
        && mime.subtype().as_str().eq_ignore_ascii_case("proto")
}

pub fn is_event_stream(mime: &mime::Mime) -> bool {
    mime.type_() == mime::TEXT && mime.subtype() == mime::EVENT_STREAM
}

#[cfg(test)]
mod tests {
    use mime::Mime;
    use rstest::rstest;

    #[rstest]
    #[case("application/json", Some("application/json"))]
    #[case("  application/json  , application/protobuf", Some("application/json"))]
    #[case(
        "application/json; charset=utf-8",
        Some("application/json;charset=utf-8")
    )]
    #[case("", None)]
    #[case("not/a/mime, application/json", None)]
    fn parse(#[case] header: &'static str, #[case] expected: Option<&'static str>) {
        let header = http::HeaderValue::from_static(header);
        let expected = expected.map(|s| s.parse::<Mime>().unwrap());
        assert_eq!(super::parse(&header), expected);
    }

    #[test]
    fn parse_returns_none_for_non_utf8_header_values() {
        let header = http::HeaderValue::from_bytes(b"\xFF\xFF").unwrap();
        assert_eq!(super::parse(&header), None);
    }
}
