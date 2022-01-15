use futures::prelude::*;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    api::{Api, ListParams, ResourceExt},
    runtime::{utils::try_flatten_applied, utils::try_flatten_touched, watcher, reflector},
    Client,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::env::set_var("RUST_LOG", "info,kube=debug");
    env_logger::init();
    let client = Client::try_default().await?;
    let api = Api::<Pod>::all(client);

    let store_w = reflector::store::Writer::default();
    let _store = store_w.as_reader();
    let mut reflector = reflector(store_w, watcher(api, ListParams::default())).boxed();

    // let mut rf = try_flatten_touched(reflector).boxed();
    // while let Some(event) = rf.try_next().await? {
    //     log::info!("Touched {}/{}", event.namespace().unwrap_or("".to_string()), event.name());
    //     let pods: Vec<_> = store.state().iter().map(ResourceExt::name).collect();
    //     log::info!("Pods {:?}", pods);
    // }

    while let Some(event) = reflector.try_next().await? {
        match event {
            watcher::Event::Deleted(_) => log::info!("DELETED: {:?}", event),
            _ => {},
        }
    }

    Ok(())
}
