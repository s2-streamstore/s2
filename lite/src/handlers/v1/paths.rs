pub mod basins {
    pub const TAG: &str = "basins";
    pub const DESCRIPTION: &str = "Manage basins";

    pub const LIST: &str = "/basins";
    pub const CREATE: &str = "/basins";
    pub const CREATE_OR_RECONFIGURE: &str = "/basins/{basin}";
    pub const DELETE: &str = "/basins/{basin}";
    pub const GET_CONFIG: &str = "/basins/{basin}";
    pub const RECONFIGURE: &str = "/basins/{basin}";
    pub const METRICS: &str = "/basins/metrics";
}

pub mod metrics {
    pub const TAG: &str = "metrics";
    pub const DESCRIPTION: &str = "Usage metrics and data.";

    pub const ACCOUNT: &str = "/metrics";
    pub const BASIN: &str = "/metrics/{basin}";
    pub const STREAM: &str = "/metrics/{basin}/{stream}";
}

pub mod access_tokens {
    pub const TAG: &str = "access-tokens";
    pub const DESCRIPTION: &str = "Manage access tokens";

    pub const LIST: &str = "/access-tokens";
    pub const ISSUE: &str = "/access-tokens";
    pub const REVOKE: &str = "/access-tokens/{id}";
}

pub mod streams {
    pub const TAG: &str = "streams";
    pub const DESCRIPTION: &str = "Manage streams";

    pub const LIST: &str = "/streams";
    pub const CREATE: &str = "/streams";
    pub const CREATE_OR_RECONFIGURE: &str = "/streams/{stream}";
    pub const DELETE: &str = "/streams/{stream}";
    pub const GET_CONFIG: &str = "/streams/{stream}";
    pub const RECONFIGURE: &str = "/streams/{stream}";

    pub mod records {
        pub const TAG: &str = "records";
        pub const DESCRIPTION: &str = "Manage records";

        pub const CHECK_TAIL: &str = "/streams/{stream}/records/tail";
        pub const READ: &str = "/streams/{stream}/records";
        pub const APPEND: &str = "/streams/{stream}/records";
    }
}

pub mod cloud_endpoints {
    pub const ACCOUNT: &str = "https://aws.s2.dev/v1";
    pub const BASIN: &str = "https://{basin}.b.aws.s2.dev/v1";
}
