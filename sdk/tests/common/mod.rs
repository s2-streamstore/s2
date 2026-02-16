#![allow(dead_code)]
use std::{
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use s2_sdk::types::{
    BasinName, Compression, CreateBasinInput, CreateStreamInput, DeleteBasinInput,
    DeleteStreamInput, S2Config, S2Endpoints, StreamName, ValidationError,
};
use test_context::AsyncTestContext;

pub struct SharedS2Basin(Arc<S2Basin>);

impl Deref for SharedS2Basin {
    type Target = S2Basin;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsyncTestContext for SharedS2Basin {
    async fn setup() -> Self {
        let mut guard = SHARED_BASIN.lock().await;
        SHARED_BASIN_USERS.fetch_add(1, Ordering::SeqCst);
        let basin = if let Some(basin) = guard.as_ref() {
            basin.clone()
        } else {
            let config = default_s2_config().expect("valid S2 config");
            let s2 = s2_sdk::S2::new(config.clone()).expect("valid S2");
            let basin_name = unique_basin_name();
            s2.create_basin(CreateBasinInput::new(basin_name.clone()))
                .await
                .expect("valid BasinInfo");
            let basin = s2.basin(basin_name.clone());
            let basin = Arc::new(S2Basin {
                s2,
                basin,
                basin_name,
            });
            *guard = Some(basin.clone());
            basin
        };
        SharedS2Basin(basin)
    }

    async fn teardown(self) {
        let mut guard = SHARED_BASIN.lock().await;
        if SHARED_BASIN_USERS.fetch_sub(1, Ordering::SeqCst) == 1
            && let Some(basin) = guard.take()
        {
            let _ = basin
                .s2
                .delete_basin(DeleteBasinInput::new(basin.basin_name.clone()))
                .await;
        }
    }
}

#[derive(Clone)]
pub struct S2Basin {
    s2: s2_sdk::S2,
    basin: s2_sdk::S2Basin,
    basin_name: BasinName,
}

impl Deref for S2Basin {
    type Target = s2_sdk::S2Basin;

    fn deref(&self) -> &Self::Target {
        &self.basin
    }
}

impl S2Basin {
    pub fn basin_name(&self) -> &BasinName {
        &self.basin_name
    }
}

impl AsyncTestContext for S2Basin {
    async fn setup() -> Self {
        let config = default_s2_config().expect("valid S2 config");
        let s2 = s2_sdk::S2::new(config.clone()).expect("valid S2");
        let basin_name = unique_basin_name();
        s2.create_basin(CreateBasinInput::new(basin_name.clone()))
            .await
            .expect("successful creation");
        let basin = s2.basin(basin_name.clone());
        S2Basin {
            s2,
            basin,
            basin_name,
        }
    }

    async fn teardown(self) -> () {
        self.s2
            .delete_basin(DeleteBasinInput::new(self.basin_name.clone()))
            .await
            .expect("successful deletion")
    }
}

pub struct S2Stream {
    basin: SharedS2Basin,
    stream: s2_sdk::S2Stream,
    stream_name: StreamName,
}

impl Deref for S2Stream {
    type Target = s2_sdk::S2Stream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl S2Stream {
    pub fn basin_name(&self) -> &BasinName {
        self.basin.basin_name()
    }

    pub fn stream_name(&self) -> &StreamName {
        &self.stream_name
    }
}

impl AsyncTestContext for S2Stream {
    async fn setup() -> Self {
        let basin = SharedS2Basin::setup().await;

        let stream_name = unique_stream_name();
        basin
            .create_stream(CreateStreamInput::new(stream_name.clone()))
            .await
            .expect("stream creation failed");
        let stream = basin.stream(stream_name.clone());
        Self {
            basin,
            stream,
            stream_name,
        }
    }

    async fn teardown(self) {
        // Just a best effort op to ensure basin teardown always happens.
        let _ = self
            .basin
            .delete_stream(DeleteStreamInput::new(self.stream_name))
            .await;
        self.basin.teardown().await;
    }
}

pub fn unique_stream_name() -> StreamName {
    use std::sync::LazyLock;
    static PREFIX: LazyLock<String> =
        LazyLock::new(|| uuid::Uuid::new_v4().simple().to_string()[..8].to_string());
    let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("stream-{}-{:04}", *PREFIX, counter)
        .parse()
        .expect("valid stream name")
}

static SHARED_BASIN: tokio::sync::Mutex<Option<Arc<S2Basin>>> = tokio::sync::Mutex::const_new(None);
static SHARED_BASIN_USERS: AtomicU32 = AtomicU32::new(0);

static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

fn default_s2_config() -> Result<S2Config, ValidationError> {
    s2_config(Compression::None)
}

pub fn s2_config(compression: Compression) -> Result<S2Config, ValidationError> {
    let access_token =
        std::env::var("S2_ACCESS_TOKEN").map_err(|_| "S2_ACCESS_TOKEN env var not set")?;
    let mut config = S2Config::new(access_token);
    if std::env::var("S2_ACCOUNT_ENDPOINT").is_ok() && std::env::var("S2_BASIN_ENDPOINT").is_ok() {
        config = config.with_endpoints(S2Endpoints::from_env()?)
    }
    if std::env::var("S2_SSL_NO_VERIFY").is_ok() {
        config = config.with_insecure_skip_cert_verification(true);
    }
    config = config.with_compression(compression);
    Ok(config)
}

pub fn s2() -> s2_sdk::S2 {
    let config = default_s2_config().expect("valid S2 config");
    s2_sdk::S2::new(config).expect("valid S2")
}

pub fn unique_basin_name() -> BasinName {
    use std::sync::LazyLock;
    static PREFIX: LazyLock<String> =
        LazyLock::new(|| uuid::Uuid::new_v4().simple().to_string()[..8].to_string());
    let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("basin-{}-{:04}", *PREFIX, counter)
        .parse()
        .expect("valid basin name")
}

pub fn uuid() -> String {
    format!("{}", uuid::Uuid::new_v4().simple())
}
