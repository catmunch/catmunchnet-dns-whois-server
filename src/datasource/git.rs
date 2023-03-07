use crate::config::Config;
use crate::datasource::DataSource;
use crate::resource::autnum::Autnum;
use crate::resource::domain::Domain;
use crate::resource::inet6num::Inet6num;
use crate::resource::inetnum::Inetnum;
use crate::resource::route::Route;
use crate::resource::route6::Route6;
use crate::resource::Resource;
use git2::Repository;
use log::{info, warn};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub struct GitDataSource {
    git_path: String,
    git_branch: String,
    git_repo: String,
}
impl DataSource for GitDataSource {
    fn update(&mut self) -> bool {
        if !Path::new(&self.git_path).exists() {
            info!("Cannot find registry, cloning from git");
            Repository::clone(&self.git_repo, &self.git_path).expect("Failed to clone git repo!");
            true
        } else {
            let repo =
                Repository::open(&self.git_path).expect("git_path exists but is not a git repo");
            let mut remote = repo
                .remote_anonymous(&self.git_repo)
                .expect("Invalid git repo url!");
            if remote.fetch(&[&self.git_branch], None, None).is_err() {
                warn!("Unable to fetch from remote!");
                false
            } else {
                let fetch_head = repo
                    .find_reference("FETCH_HEAD")
                    .expect("Cannot get FETCH_HEAD");
                let ref_name = format!("refs/heads/{}", &self.git_branch);
                let mut reference = repo
                    .find_reference(&ref_name)
                    .expect("Cannot find git branch!");
                if reference.target() == fetch_head.target() {
                    return false;
                }
                reference
                    .set_target(
                        fetch_head
                            .target()
                            .expect("Cannot get the Oid of FETCH_HEAD"),
                        "",
                    )
                    .expect("Unable to set target");
                repo.set_head(&ref_name).unwrap();
                repo.checkout_head(Some(git2::build::CheckoutBuilder::default().force()))
                    .unwrap();
                true
            }
        }
    }
    fn get_resources(&self) -> Vec<Resource> {
        let mut resources: Vec<Resource> = Vec::new();
        let git_path = Path::new(&self.git_path);
        let autnum_path = git_path.join("autnum");
        for entry in fs::read_dir(autnum_path).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_str().unwrap().starts_with(".") {
                continue;
            }
            let file = File::open(&path)
                .expect(&format!("Unable to open file {}", &path.to_str().unwrap()));
            let autnum: Autnum = serde_yaml::from_reader(BufReader::new(file))
                .expect(&format!("Unable to parse {}", path.to_str().unwrap()));
            resources.push(Resource::Autnum(autnum));
        }
        let domain_path = git_path.join("domain");
        for entry in fs::read_dir(domain_path).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_str().unwrap().starts_with(".") {
                continue;
            }
            let file = File::open(&path)
                .expect(&format!("Unable to open file {}", path.to_str().unwrap()));
            let domain: Domain = serde_yaml::from_reader(BufReader::new(file))
                .expect(&format!("Unable to parse {}", path.to_str().unwrap()));
            resources.push(Resource::Domain(domain));
        }
        let inetnum_path = git_path.join("inetnum");
        for entry in fs::read_dir(inetnum_path).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_str().unwrap().starts_with(".") {
                continue;
            }
            let file = File::open(&path)
                .expect(&format!("Unable to open file {}", path.to_str().unwrap()));
            let inetnum: Inetnum = serde_yaml::from_reader(BufReader::new(file))
                .expect(&format!("Unable to parse {}", path.to_str().unwrap()));
            resources.push(Resource::Inetnum(inetnum));
        }
        let inet6num_path = git_path.join("inet6num");
        for entry in fs::read_dir(inet6num_path).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_str().unwrap().starts_with(".") {
                continue;
            }
            let file = File::open(&path)
                .expect(&format!("Unable to open file {}", path.to_str().unwrap()));
            let inet6num: Inet6num = serde_yaml::from_reader(BufReader::new(file))
                .expect(&format!("Unable to parse {}", path.to_str().unwrap()));
            resources.push(Resource::Inet6num(inet6num));
        }
        let route_path = git_path.join("route");
        for entry in fs::read_dir(route_path).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_str().unwrap().starts_with(".") {
                continue;
            }
            let file = File::open(&path)
                .expect(&format!("Unable to open file {}", path.to_str().unwrap()));
            let route: Route = serde_yaml::from_reader(BufReader::new(file))
                .expect(&format!("Unable to parse {}", path.to_str().unwrap()));
            resources.push(Resource::Route(route));
        }
        let route6_path = git_path.join("route6");
        for entry in fs::read_dir(route6_path).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().unwrap().to_str().unwrap().starts_with(".") {
                continue;
            }
            let file = File::open(&path)
                .expect(&format!("Unable to open file {}", path.to_str().unwrap()));
            let route6: Route6 = serde_yaml::from_reader(BufReader::new(file))
                .expect(&format!("Unable to parse {}", path.to_str().unwrap()));
            resources.push(Resource::Route6(route6));
        }
        resources
    }
}
impl GitDataSource {
    pub fn new(config: Config) -> Self {
        Self {
            git_path: config.git_path,
            git_branch: config.git_branch,
            git_repo: config.git_repo,
        }
    }
}
