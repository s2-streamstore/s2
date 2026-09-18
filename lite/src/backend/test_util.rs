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
