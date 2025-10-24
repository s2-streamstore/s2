use std::{str::FromStr, time::Duration};

use s2_common::types;
use serde::Serialize;
use utoipa::ToSchema;

use super::ReadBatch;

#[derive(Debug, Clone, Copy)]
pub struct LastEventId {
    pub seq_num: u64,
    pub count: usize,
    pub bytes: usize,
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
                .ok_or_else(|| format!("Missing {field} in Last-Event-Id"))?;
            item.parse()
                .map_err(|e| format!("Invalid {field} in Last-Event-ID: {e}").into())
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
        #[derive(Serialize, ToSchema)]
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

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum ReadEvent {
    #[schema(title = "batch")]
    Batch {
        #[schema(inline)]
        event: Batch,
        data: ReadBatch,
        #[schema(value_type = String, pattern = "^[0-9]+,[0-9]+,[0-9]+$")]
        id: LastEventId,
    },
    #[schema(title = "error")]
    Error {
        #[schema(inline)]
        event: Error,
        data: String,
    },
    #[schema(title = "ping")]
    Ping {
        #[schema(inline)]
        event: Ping,
        data: PingEventData,
    },
    #[schema(title = "done")]
    #[serde(skip)]
    Done {
        #[schema(value_type = String, pattern = r"^\[DONE\]$")]
        data: DoneEventData,
    },
}

fn elapsed_since_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
}

impl ReadEvent {
    pub fn batch(data: ReadBatch, id: LastEventId) -> Self {
        Self::Batch {
            event: Batch::Batch,
            data,
            id,
        }
    }

    pub fn error(data: String) -> Self {
        Self::Error {
            event: Error::Error,
            data,
        }
    }

    pub fn ping() -> Self {
        Self::Ping {
            event: Ping::Ping,
            data: PingEventData {
                timestamp: elapsed_since_epoch().as_millis() as u64,
            },
        }
    }

    pub fn done() -> Self {
        Self::Done {
            data: DoneEventData,
        }
    }
}

#[derive(Debug, Clone, ToSchema, Serialize)]
#[serde(rename = "[DONE]")]
pub struct DoneEventData;

impl AsRef<str> for DoneEventData {
    fn as_ref(&self) -> &str {
        "[DONE]"
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, ToSchema, Serialize)]
pub struct PingEventData {
    pub timestamp: u64,
}
