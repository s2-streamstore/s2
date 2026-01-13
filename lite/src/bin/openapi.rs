use s2_api::{
    data::Format,
    v1::metrics::{AccountMetricSet, BasinMetricSet, StreamMetricSet},
};
use s2_lite::handlers::v1::{
    basins::{
        __path_create, __path_create_or_reconfigure, __path_delete, __path_get_config, __path_list,
        __path_reconfigure,
    },
    metrics::{__path_account_metrics, __path_basin_metrics, __path_stream_metrics},
    paths::{self, endpoints},
    records::{__path_append, __path_check_tail, __path_read},
    streams::{
        __path_create as __path_create_stream,
        __path_create_or_reconfigure as __path_create_or_reconfigure_stream,
        __path_delete as __path_delete_stream, __path_get_config as __path_get_config_stream,
        __path_list as __path_list_streams, __path_reconfigure as __path_reconfigure_stream,
    },
    tokens::{__path_issue, __path_list as __path_list_tokens, __path_revoke},
};
use utoipa::{
    Modify, OpenApi,
    openapi::{
        path::Operation,
        security::{Http, HttpAuthScheme, SecurityScheme},
    },
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "S2 API",
        description = "Serverless API for streaming data backed by object storage.",
        version = "1.0.0",
        license(
            name = "Apache 2.0"
        ),
        terms_of_service = "https://s2.dev/terms",
        contact(
            email = "hi@s2.dev"
        )
    ),
    servers(
        (url = endpoints::ACCOUNT)
    ),
    modifiers(&SecurityAddon, &PathLevelServersAddon),
    security(
        ("access_token" = [])
    ),
    tags(
        (name = paths::metrics::TAG, description = paths::metrics::DESCRIPTION),
        (name = paths::basins::TAG, description = paths::basins::DESCRIPTION),
        (name = paths::tokens::TAG, description = paths::tokens::DESCRIPTION),
        (name = paths::streams::TAG, description = paths::streams::DESCRIPTION),
        (name = paths::streams::records::TAG, description = paths::streams::records::DESCRIPTION),
    ),
    paths(
        // Basin ops
        list,
        create_or_reconfigure,
        create,
        delete,
        get_config,
        reconfigure,
        // Token ops
        issue,
        revoke,
        list_tokens,
        // Stream ops
        list_streams,
        create_or_reconfigure_stream,
        create_stream,
        delete_stream,
        get_config_stream,
        reconfigure_stream,
        // Record ops
        check_tail,
        append,
        read,
        // Metrics ops
        account_metrics,
        basin_metrics,
        stream_metrics,
    ),
    components(schemas(Format, AccountMetricSet, BasinMetricSet, StreamMetricSet))
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "access_token",
                SecurityScheme::Http(
                    Http::builder()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(concat!(
                            "Bearer authentication header of the form `Bearer <token>`, ",
                            "where `<token>` is your access token."
                        )))
                        .build(),
                ),
            )
        }
    }
}

struct PathLevelServersAddon;

impl PathLevelServersAddon {
    fn get_operations_mut(path_item: &mut utoipa::openapi::PathItem) -> Vec<&mut Operation> {
        [
            path_item.get.as_mut(),
            path_item.put.as_mut(),
            path_item.post.as_mut(),
            path_item.delete.as_mut(),
            path_item.options.as_mut(),
            path_item.head.as_mut(),
            path_item.patch.as_mut(),
            path_item.trace.as_mut(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

impl Modify for PathLevelServersAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        for path_item in openapi.paths.paths.values_mut() {
            let operations = Self::get_operations_mut(path_item);

            if operations.is_empty() {
                continue;
            }

            let all_servers: Vec<_> = operations.iter().map(|op| op.servers.as_ref()).collect();

            let first_servers = all_servers.first().copied().flatten();
            let all_same = all_servers
                .iter()
                .all(|s| s.as_ref() == first_servers.as_ref());

            if all_same && let Some(servers) = first_servers.cloned() {
                path_item.servers = Some(servers);

                for op in Self::get_operations_mut(path_item) {
                    op.servers = None;
                }
            }
        }
    }
}

fn main() -> eyre::Result<()> {
    let json = ApiDoc::openapi().to_pretty_json()?;
    println!("{json}");
    Ok(())
}
