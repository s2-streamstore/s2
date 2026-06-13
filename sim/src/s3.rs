//! Mock S3 service, run as a turmoil host.
//!
//! The S3 wire protocol (routing, XML, header parsing) is handled by the
//! `s3s` crate; this module implements the [`s3s::S3`] trait over an
//! in-memory map, covering the subset of operations slatedb's `object_store`
//! S3 client uses. Unimplemented operations default to a `NotImplemented`
//! error, which surfaces loudly if slatedb starts relying on something new
//! (likely candidates: multipart uploads for large SSTs, CopyObject,
//! batch DeleteObjects).
//!
//! No auth is configured, so requests are accepted without signature checks.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::SystemTime,
};

use bytes::Bytes;
use futures::StreamExt as _;
use s3s::{
    S3, S3Request, S3Response, S3Result,
    dto::{self, ETag, ETagCondition, Timestamp},
    s3_error,
    service::S3ServiceBuilder,
};

pub const HOST: &str = "s3";
pub const PORT: u16 = 9000;
pub const BUCKET: &str = "sim-bucket";
pub const ACCESS_KEY: &str = "sim-access-key";
pub const SECRET_KEY: &str = "sim-secret-key";

pub fn endpoint() -> String {
    format!("http://{HOST}:{PORT}")
}

pub async fn serve() -> turmoil::Result {
    let mut builder = S3ServiceBuilder::new(InMemoryS3::default());
    // s3s rejects signed requests outright if no auth provider is configured,
    // and the object_store client always signs.
    builder.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
    let service = builder.build();
    crate::net::serve_hyper(PORT, service).await
}

#[derive(Debug, Clone, Default)]
struct InMemoryS3 {
    objects: Arc<Mutex<BTreeMap<String, StoredObject>>>,
}

#[derive(Debug, Clone)]
struct StoredObject {
    data: Bytes,
    etag: ETag,
    last_modified: Timestamp,
    /// User metadata (`x-amz-meta-*`). Load-bearing: slatedb stamps each write
    /// with a `slatedbputid` ULID and, after a put whose response was lost,
    /// re-reads the object to check whether that write was in fact its own
    /// (vs. a competing writer). Dropping metadata makes slatedb misread its
    /// own retried write as a fence and shut down permanently.
    metadata: Option<dto::Metadata>,
}

impl StoredObject {
    fn new(data: Bytes, metadata: Option<dto::Metadata>) -> Self {
        Self {
            etag: ETag::Strong(blake3::hash(&data).to_hex().to_string()),
            // SystemTime is shadowed by mad-turmoil, so this is simulated
            // (deterministic) time.
            last_modified: SystemTime::now().into(),
            data,
            metadata,
        }
    }
}

fn check_bucket(bucket: &str) -> S3Result<()> {
    if bucket == BUCKET {
        Ok(())
    } else {
        Err(s3_error!(
            NoSuchBucket,
            "only bucket {BUCKET:?} exists in the simulation"
        ))
    }
}

/// Whether a parsed `If-Match`/`If-None-Match` condition matches the current
/// state of the object. s3s parses the headers; enforcement is ours.
fn condition_matches(cond: &ETagCondition, existing: Option<&StoredObject>) -> bool {
    match (cond, existing) {
        (_, None) => false,
        (ETagCondition::Any, Some(_)) => true,
        (ETagCondition::ETag(etag), Some(object)) => etag.value() == object.etag.value(),
    }
}

async fn collect_body(body: Option<dto::StreamingBlob>) -> S3Result<Bytes> {
    let Some(mut blob) = body else {
        return Ok(Bytes::new());
    };
    let mut buf = Vec::new();
    while let Some(chunk) = blob.next().await {
        let chunk = chunk.map_err(|err| s3_error!(InternalError, "failed to read body: {err}"))?;
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.into())
}

#[async_trait::async_trait]
impl S3 for InMemoryS3 {
    async fn put_object(
        &self,
        req: S3Request<dto::PutObjectInput>,
    ) -> S3Result<S3Response<dto::PutObjectOutput>> {
        let input = req.input;
        check_bucket(&input.bucket)?;
        let data = collect_body(input.body).await?;

        let mut objects = self.objects.lock().expect("mutex poisoned");
        let existing = objects.get(&input.key);
        // `If-None-Match: *` is slatedb's put-if-absent (manifest fencing);
        // `If-Match: <etag>` is its CAS update.
        if let Some(cond) = &input.if_none_match
            && condition_matches(cond, existing)
        {
            return Err(s3_error!(PreconditionFailed));
        }
        if let Some(cond) = &input.if_match
            && !condition_matches(cond, existing)
        {
            return Err(s3_error!(PreconditionFailed));
        }

        let size = data.len() as i64;
        let object = StoredObject::new(data, input.metadata);
        let etag = object.etag.clone();
        objects.insert(input.key, object);

        Ok(S3Response::new(dto::PutObjectOutput {
            e_tag: Some(etag),
            size: Some(size),
            ..Default::default()
        }))
    }

    async fn get_object(
        &self,
        req: S3Request<dto::GetObjectInput>,
    ) -> S3Result<S3Response<dto::GetObjectOutput>> {
        let input = req.input;
        check_bucket(&input.bucket)?;
        if input.if_match.is_some()
            || input.if_none_match.is_some()
            || input.if_modified_since.is_some()
            || input.if_unmodified_since.is_some()
        {
            return Err(s3_error!(NotImplemented, "conditional GET not implemented"));
        }

        let objects = self.objects.lock().expect("mutex poisoned");
        let Some(object) = objects.get(&input.key) else {
            return Err(s3_error!(NoSuchKey));
        };

        let total = object.data.len() as u64;
        let (data, content_range) = match input.range {
            None => (object.data.clone(), None),
            Some(range) => {
                let last_valid = total.saturating_sub(1);
                let (first, last) = match range {
                    dto::Range::Int { first, last } => {
                        (first, last.unwrap_or(last_valid).min(last_valid))
                    }
                    dto::Range::Suffix { length } => (total.saturating_sub(length), last_valid),
                };
                if first >= total || first > last {
                    return Err(s3_error!(InvalidRange, "range {range:?} of {total} bytes"));
                }
                let data = object.data.slice(first as usize..=last as usize);
                (data, Some(format!("bytes {first}-{last}/{total}")))
            }
        };

        Ok(S3Response::new(dto::GetObjectOutput {
            content_length: Some(data.len() as i64),
            content_range,
            body: Some(dto::StreamingBlob::from(s3s::Body::from(data))),
            e_tag: Some(object.etag.clone()),
            last_modified: Some(object.last_modified.clone()),
            accept_ranges: Some("bytes".to_owned()),
            metadata: object.metadata.clone(),
            ..Default::default()
        }))
    }

    async fn head_object(
        &self,
        req: S3Request<dto::HeadObjectInput>,
    ) -> S3Result<S3Response<dto::HeadObjectOutput>> {
        let input = req.input;
        check_bucket(&input.bucket)?;

        let objects = self.objects.lock().expect("mutex poisoned");
        let Some(object) = objects.get(&input.key) else {
            return Err(s3_error!(NoSuchKey));
        };

        Ok(S3Response::new(dto::HeadObjectOutput {
            content_length: Some(object.data.len() as i64),
            e_tag: Some(object.etag.clone()),
            last_modified: Some(object.last_modified.clone()),
            accept_ranges: Some("bytes".to_owned()),
            metadata: object.metadata.clone(),
            ..Default::default()
        }))
    }

    async fn delete_object(
        &self,
        req: S3Request<dto::DeleteObjectInput>,
    ) -> S3Result<S3Response<dto::DeleteObjectOutput>> {
        let input = req.input;
        check_bucket(&input.bucket)?;
        // S3 deletes are idempotent: deleting a missing key succeeds.
        self.objects
            .lock()
            .expect("mutex poisoned")
            .remove(&input.key);
        Ok(S3Response::new(dto::DeleteObjectOutput::default()))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<dto::ListObjectsV2Input>,
    ) -> S3Result<S3Response<dto::ListObjectsV2Output>> {
        let input = req.input;
        check_bucket(&input.bucket)?;

        let prefix = input.prefix.clone().unwrap_or_default();
        let max_keys = input.max_keys.unwrap_or(1000).clamp(1, 1000) as usize;
        // Our continuation token is the last underlying key consumed by the
        // previous page; both it and start-after mean "resume strictly after".
        let after = match (input.continuation_token.clone(), input.start_after.clone()) {
            (Some(token), Some(start_after)) => Some(token.max(start_after)),
            (token, start_after) => token.or(start_after),
        };

        let objects = self.objects.lock().expect("mutex poisoned");
        let mut contents = Vec::new();
        let mut common_prefixes: Vec<dto::CommonPrefix> = Vec::new();
        let mut is_truncated = false;
        let mut next_continuation_token = None;
        // The greatest key consumed into the response so far; becomes the
        // continuation token if we truncate.
        let mut last_consumed: Option<String> = None;

        let mut iter = objects.range(prefix.clone()..).peekable();
        while let Some((key, object)) = iter.next() {
            if !key.starts_with(&prefix) {
                break;
            }
            if let Some(after) = &after
                && key <= after
            {
                continue;
            }
            if contents.len() + common_prefixes.len() >= max_keys {
                is_truncated = true;
                next_continuation_token = last_consumed.clone();
                break;
            }

            let rollup = input.delimiter.as_ref().and_then(|delimiter| {
                let rest = &key[prefix.len()..];
                rest.find(delimiter.as_str())
                    .map(|idx| format!("{prefix}{}{delimiter}", &rest[..idx]))
            });
            match rollup {
                Some(group) => {
                    // Consume the whole group so the continuation token can
                    // remain a plain key.
                    last_consumed = Some(key.clone());
                    while let Some((key, _)) = iter.peek() {
                        if !key.starts_with(&group) {
                            break;
                        }
                        last_consumed = Some((*key).clone());
                        iter.next();
                    }
                    common_prefixes.push(dto::CommonPrefix {
                        prefix: Some(group),
                    });
                }
                None => {
                    last_consumed = Some(key.clone());
                    contents.push(dto::Object {
                        key: Some(key.clone()),
                        size: Some(object.data.len() as i64),
                        e_tag: Some(object.etag.clone()),
                        last_modified: Some(object.last_modified.clone()),
                        ..Default::default()
                    });
                }
            }
        }

        let key_count = (contents.len() + common_prefixes.len()) as i32;
        Ok(S3Response::new(dto::ListObjectsV2Output {
            name: Some(input.bucket),
            prefix: input.prefix,
            delimiter: input.delimiter,
            start_after: input.start_after,
            continuation_token: input.continuation_token,
            max_keys: Some(max_keys as i32),
            key_count: Some(key_count),
            contents: Some(contents),
            common_prefixes: Some(common_prefixes),
            is_truncated: Some(is_truncated),
            next_continuation_token,
            ..Default::default()
        }))
    }
}
