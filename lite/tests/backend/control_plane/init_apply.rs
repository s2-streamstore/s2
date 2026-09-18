use std::time::Duration;

use s2_common::{basin::ListBasinsRequest, config::RetentionPolicy};
use s2_lite::backend::error::GetBasinConfigError;
use s2_resource_spec::Resources;

use super::common::*;

fn spec_from(json: &str) -> Resources {
    serde_json::from_str(json).expect("valid spec JSON")
}

#[tokio::test]
async fn init_apply_rejects_subsecond_retention_and_persists_nothing() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("init-subsec-basin");
    let json = format!(
        r#"{{"basins":[{{"name":"{b}","config":{{"default_stream_config":{{"retention_policy":"500ms"}}}}}}]}}"#,
        b = basin_name.as_ref()
    );

    let err = s2_lite::init::apply(&backend, spec_from(&json))
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("retention age must be a whole number of seconds"),
        "expected sub-second rejection, got: {err}"
    );

    assert!(
        matches!(
            backend.get_basin_config(basin_name.clone()).await,
            Err(GetBasinConfigError::BasinNotFound(_))
        ),
        "no basin meta should be persisted after a rejected apply"
    );

    let page = backend
        .list_basins(ListBasinsRequest::default())
        .await
        .expect("list_basins must not surface a deserialization error after rejected apply");
    assert!(
        page.values.is_empty(),
        "no basin meta should be persisted after rejected apply"
    );
}

#[tokio::test]
async fn init_apply_persists_whole_second_and_infinite_retention() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("init-valid-basin");
    let stream_name = test_stream_name("init-valid-stream");
    let json = format!(
        r#"{{"basins":[{{"name":"{b}","config":{{"default_stream_config":{{"retention_policy":"3600s"}}}},"streams":[{{"name":"{s}","config":{{"retention_policy":"infinite"}}}}]}}]}}"#,
        b = basin_name.as_ref(),
        s = stream_name.as_ref()
    );

    s2_lite::init::apply(&backend, spec_from(&json))
        .await
        .expect("valid spec with whole-second and infinite retention should apply");

    let basin_cfg = backend
        .get_basin_config(basin_name.clone())
        .await
        .expect("basin config must be readable after applying a valid spec");
    assert_eq!(
        basin_cfg.default_stream_config.retention_policy,
        Some(RetentionPolicy::Age(Duration::from_secs(3600)))
    );

    let stream_cfg = backend
        .get_stream_config(basin_name, stream_name)
        .await
        .expect("stream config must be readable after applying a valid spec");
    assert!(matches!(
        stream_cfg.retention_policy,
        RetentionPolicy::Infinite()
    ));
}

#[tokio::test]
async fn init_apply_after_rejected_subsecond_still_provisions_valid_basin() {
    let backend = create_backend().await;
    let basin_name = test_basin_name("init-recover");

    let bad_json = format!(
        r#"{{"basins":[{{"name":"{b}","config":{{"default_stream_config":{{"retention_policy":"500ms"}}}}}}]}}"#,
        b = basin_name.as_ref()
    );
    let good_json = format!(
        r#"{{"basins":[{{"name":"{b}","config":{{"default_stream_config":{{"retention_policy":"3600s"}}}}}}]}}"#,
        b = basin_name.as_ref()
    );

    let _ = s2_lite::init::apply(&backend, spec_from(&bad_json))
        .await
        .unwrap_err();
    s2_lite::init::apply(&backend, spec_from(&good_json))
        .await
        .expect("valid apply after a rejected sub-second apply must succeed");

    let basin_cfg = backend
        .get_basin_config(basin_name)
        .await
        .expect("basin config must be readable after recovery apply");
    assert_eq!(
        basin_cfg.default_stream_config.retention_policy,
        Some(RetentionPolicy::Age(Duration::from_secs(3600)))
    );
}
