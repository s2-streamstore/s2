use s2_common::{
    bash::Bash,
    types::{basin::BasinName, stream::StreamName},
};

pub(super) fn stream_id_aad(basin: &BasinName, stream: &StreamName) -> [u8; 32] {
    Bash::delimited(&[basin.as_ref().as_bytes(), stream.as_ref().as_bytes()], 0).into()
}
