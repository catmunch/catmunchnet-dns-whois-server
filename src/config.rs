use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Clone, Debug)]
pub struct Config {
    /// Git repository store path
    #[clap(long, short = 'p', default_value = "registry", env = "GIT_PATH")]
    pub git_path: String,

    /// Git repository branch name
    #[clap(long, short = 'b', default_value = "main", env = "GIT_BRANCH")]
    pub git_branch: String,

    /// Git repository URL
    #[clap(long, short = 'u', env = "GIT_REPO")]
    pub git_repo: String,

    /// DNS listen addresses
    #[clap(long, short = 'd', env = "DNS_ADDR")]
    pub dns: Vec<SocketAddr>,

    /// WHOIS listen addresses
    #[clap(long, short = 'w', env = "WHOIS_ADDR")]
    pub whois: Vec<SocketAddr>,

    /// Update interval (in seconds)
    #[clap(long, short = 'i', default_value = "300", env = "INTERVAL")]
    pub interval: u64,

    /// K8S Node Name
    #[clap(long, default_value = "Default Node", env = "K8S_NODE_NAME")]
    pub node_name: String,
}
