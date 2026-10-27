use std::future::Future;

use slatedb::{Error, WriteHandle};

/// Finish a fixture write and assert that remote reads can observe it.
pub(super) trait DbWriteTestExt:
    Future<Output = Result<WriteHandle, Error>> + Sized
{
    async fn assert_durable(self) {
        self.await
            .expect("fixture write should succeed")
            .await_durable()
            .await
            .expect("fixture write should become durable");
    }
}

impl<F: Future<Output = Result<WriteHandle, Error>>> DbWriteTestExt for F {}

/// Provision a real stream for lifecycle tests, including its ID mapping and tail.
pub(super) async fn create_stream(
    backend: &super::Backend,
    config: s2_common::config::OptionalStreamConfig,
) -> (s2_common::basin::BasinName, s2_common::stream::StreamName) {
    use s2_common::{config::BasinConfig, resources::ProvisionMode};
    let basin: s2_common::basin::BasinName = "test-basin".parse().unwrap();
    let stream: s2_common::stream::StreamName = "test-stream".parse().unwrap();
    backend
        .provision_basin(basin.clone(), BasinConfig::default(), ProvisionMode::Ensure)
        .await
        .unwrap();
    backend
        .provision_stream(
            basin.clone(),
            stream.clone(),
            config,
            ProvisionMode::CreateOnly {
                request_token: None,
            },
        )
        .await
        .unwrap();
    (basin, stream)
}
