use axum::{
    body::Body,
    extract::{Path, Query, State},
    response::Response,
};
use s2_api::v1::{self as v1t, extractors::RequiredHeader};
use s2_common::types::{basin::BasinName, stream::StreamName};

use crate::backend::Backend;

pub async fn append(
    RequiredHeader(_basin): RequiredHeader<BasinName>,
    Path(_stream): Path<StreamName>,
    State(_backend): State<Backend>,
    _body: Body,
) -> Response {
    todo!()
}

pub async fn read(
    RequiredHeader(_basin): RequiredHeader<BasinName>,
    Path(_stream): Path<StreamName>,
    Query(_start): Query<v1t::stream::ReadStart>,
    Query(_end): Query<v1t::stream::ReadEnd>,
    State(_backend): State<Backend>,
) -> Response {
    todo!()
}

pub async fn check_tail(
    RequiredHeader(_basin): RequiredHeader<BasinName>,
    Path(_stream): Path<StreamName>,
    State(_backend): State<Backend>,
) -> Response {
    todo!()
}
