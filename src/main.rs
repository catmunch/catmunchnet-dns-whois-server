use crate::datasource::git::GitDataSource;
use crate::datasource::DataSource;
use crate::service::dns::run_dns_server;
use crate::service::whois::run_whois_server;
use crate::store::memory::MemoryStore;
use crate::store::Store;
use clap::Parser;
use config::Config;
use log::info;
use std::io::Error;
use std::time::Duration;
use tokio::time::sleep;

mod config;
mod datasource;
mod resource;
mod service;
mod store;
mod util;

#[tokio::main]
async fn main() -> Result<(), Error> {
    info!("test");
    env_logger::init();
    let config = Config::parse();
    let mut source: Box<dyn DataSource> = Box::new(GitDataSource::new(config.clone()));
    source.update();
    let mut store: Box<dyn Store> = Box::new(MemoryStore::new());
    store.set(&source.get_resources());
    let mut services = vec![];
    let config_copy = config.clone();
    let store_copy = store.clone();
    services.push(tokio::spawn(async move {
        run_dns_server(&config_copy, store_copy)
            .await
            .expect("Unable to start DNS server!");
    }));
    let config_copy = config.clone();
    let store_copy = store.clone();
    services.push(tokio::spawn(async move {
        run_whois_server(&config_copy, store_copy)
            .await
            .expect("Unable to start WHOIS server!");
    }));
    services.push(tokio::spawn(async move {
        loop {
            info!("Checking update...");
            if source.update() {
                info!("Updating...");
                store.set(&source.get_resources());
                info!("Updated.");
            } else {
                info!("No update available.");
            }
            sleep(Duration::from_secs(config.interval)).await;
        }
    }));
    futures_util::future::join_all(services).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::inetnum::Inetnum;
    use crate::resource::Resource;
    use crate::store::Store;
    use crate::util::cidr::Ipv4CidrWrapper;
    use cidr::Ipv4Cidr;
    use std::str::FromStr;
    #[test]
    fn test_mem_store() {
        let mut store = store::memory::MemoryStore::new();
        store.set(&Vec::from([
            Resource::Inetnum(Inetnum {
                cidr: Ipv4CidrWrapper(Ipv4Cidr::from_str("10.1.0.0/16").unwrap()),
                description: None,
                ns: Vec::new(),
            }),
            Resource::Inetnum(Inetnum {
                cidr: Ipv4CidrWrapper(Ipv4Cidr::from_str("10.2.0.0/16").unwrap()),
                description: None,
                ns: Vec::new(),
            }),
        ]));
        let x = store.get_inetnum_prefixes(Ipv4Cidr::from_str("10.1.2.3/32").unwrap());
        assert_eq!(x.0.len(), 1);
        assert_eq!(x.1.len(), 0);
        assert_eq!(
            x.0.get(0).unwrap().cidr,
            Ipv4CidrWrapper(Ipv4Cidr::from_str("10.1.0.0/16").unwrap())
        )
    }
}
