use std::{str::FromStr, time::Duration};

use s2_common::{http::ParseableHeader, types};
use serde::Serialize;

use super::ReadBatch;

static LAST_EVENT_ID_HEADER: http::HeaderName = http::HeaderName::from_static("last-event-id");

#[derive(Debug, Clone, Copy)]
pub struct LastEventId {
    pub seq_num: u64,
    pub count: usize,
    pub bytes: usize,
}

impl ParseableHeader for LastEventId {
    fn name() -> &'static http::HeaderName {
        &LAST_EVENT_ID_HEADER
    }
}

impl Serialize for LastEventId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl std::fmt::Display for LastEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            seq_num,
            count,
            bytes,
        } = self;
        write!(f, "{seq_num},{count},{bytes}")
    }
}

impl FromStr for LastEventId {
    type Err = types::ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut iter = s.splitn(3, ",");

        fn get_next<T>(
            iter: &mut std::str::SplitN<&str>,
            field: &str,
        ) -> Result<T, types::ValidationError>
        where
            T: FromStr,
            <T as FromStr>::Err: std::fmt::Display,
        {
            let item = iter
                .next()
                .ok_or_else(|| format!("missing {field} in Last-Event-Id"))?;
            item.parse()
                .map_err(|e| format!("invalid {field} in Last-Event-ID: {e}").into())
        }

        let seq_num = get_next(&mut iter, "seq_num")?;
        let count = get_next(&mut iter, "count")?;
        let bytes = get_next(&mut iter, "bytes")?;

        Ok(Self {
            seq_num,
            count,
            bytes,
        })
    }
}

macro_rules! event {
    ($name:ident, $val:expr) => {
        #[derive(Serialize)]
        #[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $name,
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                $val
            }
        }
    };
}

event!(Batch, "batch");
event!(Error, "error");
event!(Ping, "ping");

#[derive(Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(untagged)]
pub enum ReadEvent {
    #[cfg_attr(feature = "utoipa", schema(title = "batch"))]
    Batch {
        #[cfg_attr(feature = "utoipa", schema(inline))]
        event: Batch,
        data: ReadBatch,
        #[cfg_attr(feature = "utoipa", schema(value_type = String, pattern = "^[0-9]+,[0-9]+,[0-9]+$"))]
        id: LastEventId,
    },
    #[cfg_attr(feature = "utoipa", schema(title = "error"))]
    Error {
        #[cfg_attr(feature = "utoipa", schema(inline))]
        event: Error,
        data: String,
    },
    #[cfg_attr(feature = "utoipa", schema(title = "ping"))]
    Ping {
        #[cfg_attr(feature = "utoipa", schema(inline))]
        event: Ping,
        data: PingEventData,
    },
    #[cfg_attr(feature = "utoipa", schema(title = "done"))]
    #[serde(skip)]
    Done {
        #[cfg_attr(feature = "utoipa", schema(value_type = String, pattern = r"^\[DONE\]$"))]
        data: DoneEventData,
    },
}

fn elapsed_since_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("healthy clock")
}

#[cfg(feature = "axum")]
pub fn read_batch_event(
    format: crate::data::Format,
    batch: &types::stream::ReadBatch,
    id: LastEventId,
) -> Result<axum::response::sse::Event, axum::Error> {
    axum::response::sse::Event::default()
        .event(Batch::Batch)
        .id(id.to_string())
        .json_data(super::json::serialize_read_batch(format, batch))
}

#[cfg(feature = "axum")]
pub fn error_event(data: String) -> Result<axum::response::sse::Event, axum::Error> {
    Ok(axum::response::sse::Event::default()
        .event(Error::Error)
        .data(data))
}

#[cfg(feature = "axum")]
pub fn ping_event() -> Result<axum::response::sse::Event, axum::Error> {
    axum::response::sse::Event::default()
        .event(Ping::Ping)
        .json_data(PingEventData {
            timestamp: elapsed_since_epoch().as_millis() as u64,
        })
}

#[cfg(feature = "axum")]
pub fn done_event() -> Result<axum::response::sse::Event, axum::Error> {
    Ok(axum::response::sse::Event::default().data(DoneEventData))
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename = "[DONE]")]
pub struct DoneEventData;

impl AsRef<str> for DoneEventData {
    fn as_ref(&self) -> &str {
        "[DONE]"
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PingEventData {
    pub timestamp: u64,
}
