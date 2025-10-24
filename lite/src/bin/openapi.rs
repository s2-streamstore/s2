use clap::Parser;
use utoipa::OpenApi;

mod v1 {
    use handlers::v1::{
        account::{
            __path_account_metrics, __path_basin_metrics, __path_create_basin,
            __path_create_or_reconfigure_basin, __path_delete_basin, __path_get_basin_config,
            __path_issue_access_token, __path_list_access_tokens, __path_list_basins,
            __path_reconfigure_basin, __path_revoke_access_token, __path_stream_metrics,
        },
        basin::{
            __path_create_or_reconfigure_stream, __path_create_stream, __path_delete_stream,
            __path_get_stream_config, __path_list_streams, __path_reconfigure_stream,
        },
        endpoints, paths,
        stream::{__path_append, __path_check_tail, __path_read},
        types::{AccountMetricSet, BasinMetricSet, S2Format, StreamMetricSet},
    };
    use utoipa::{
        Modify, OpenApi,
        openapi::security::{Http, HttpAuthScheme, SecurityScheme},
    };

    #[derive(OpenApi)]
    #[openapi(
        info(
            title = "s2.dev API",
            description = "Serverless API for streaming data backed by object storage.",
            version = "1.0.0",
            license(
                name = "MIT"
            ),
            terms_of_service = "https://s2.dev/terms",
            contact(
                email = "hi@s2.dev"
            )
        ),
        modifiers(&SecurityAddon),
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
            list_basins,
            create_or_reconfigure_basin,
            create_basin,
            delete_basin,
            get_basin_config,
            reconfigure_basin,
            issue_access_token,
            revoke_access_token,
            list_access_tokens,
            list_streams,
            create_or_reconfigure_stream,
            create_stream,
            delete_stream,
            get_stream_config,
            reconfigure_stream,
            check_tail,
            append,
            read,
            account_metrics,
            basin_metrics,
            stream_metrics
        ),
        components(schemas(S2Format, AccountMetricSet, BasinMetricSet, StreamMetricSet))
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
}

#[derive(Parser)]
#[command(author, about, long_about = None, disable_version_flag = true)]
struct Cli {
    #[arg(value_enum)]
    version: ApiVersion,
}

#[derive(clap::ValueEnum, Clone)]
enum ApiVersion {
    V1,
}

fn main() -> eyre::Result<()> {
    let cli = Cli::parse();

    let json = match cli.version {
        ApiVersion::V1 => v1::ApiDoc::openapi().to_pretty_json()?,
    };

    println!("{json}");
    Ok(())
}
