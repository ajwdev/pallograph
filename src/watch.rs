// Copyright (c) 2026 Andrew Williams
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Keep the engine current with a live cluster (`--watch`).
//!
//! One kube watcher per resource in `edb::CLUSTER_RESOURCES` turns watch
//! events into [`Change`]s. A batching thread gathers them for a short
//! window and hands each batch to [`Engine::apply_changes`], so the facts
//! loaded from the cluster (EDB) are maintained incrementally: on the DD
//! backend a batch is one commit. Nothing here talks to the engine except
//! through `apply_changes`, the same call any other feeder would use.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, unbounded};
use futures::StreamExt;
use kube::api::{DynamicObject, ListParams};
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event, watcher};
use kube::{Api, Client};

use crate::edb::{ObjectKey, cluster_resources, is_not_served, object_key, single_object_facts};
use crate::engine::{ApplySummary, Change, Engine};

/// How long the batcher keeps gathering changes after the first one of a
/// batch arrives.
const BATCH_WINDOW: Duration = Duration::from_millis(250);
/// The most changes one batch holds before it is applied.
const BATCH_MAX: usize = 1000;

/// What the batcher hears from a resource's watch.
enum Message {
    Changes(Vec<Change>),
    /// The resource finished a (re)list; every object it holds has been sent.
    Listed,
}

/// One resource's objects, tracked across relists. A watch that falls too
/// far behind starts over with a fresh list, and the API server sends no
/// delete for objects removed in the meantime: anything known before the
/// relist but missing from it is gone.
struct ResourceSync {
    /// The (apiVersion, kind) the resource's objects load as. Watch events
    /// leave them off each object, as lists do.
    api_version: String,
    kind: String,
    known: HashSet<ObjectKey>,
    /// Keys seen since the current relist began, until it ends.
    relisting: Option<HashSet<ObjectKey>>,
}

impl ResourceSync {
    fn new(api_version: &str, kind: &str) -> Self {
        ResourceSync {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            known: HashSet::new(),
            relisting: None,
        }
    }

    /// The engine changes one watch event makes, and whether it ended a
    /// (re)list.
    fn on_event(&mut self, event: Event<DynamicObject>) -> (Vec<Change>, bool) {
        let type_hint = Some((self.api_version.as_str(), self.kind.as_str()));
        match event {
            Event::Apply(obj) => {
                let object = single_object_facts(&obj, type_hint);
                self.known.insert(object.key.clone());
                (vec![Change::Upsert(object)], false)
            }
            Event::Delete(obj) => {
                let key = object_key(&obj, type_hint);
                self.known.remove(&key);
                (vec![Change::Retract(key)], false)
            }
            Event::Init => {
                self.relisting = Some(HashSet::new());
                (Vec::new(), false)
            }
            Event::InitApply(obj) => {
                let object = single_object_facts(&obj, type_hint);
                self.relisting
                    .get_or_insert_default()
                    .insert(object.key.clone());
                (vec![Change::Upsert(object)], false)
            }
            Event::InitDone => {
                let listed = self.relisting.take().unwrap_or_default();
                let gone = self
                    .known
                    .difference(&listed)
                    .cloned()
                    .map(Change::Retract)
                    .collect();
                self.known = listed;
                (gone, true)
            }
        }
    }
}

/// What the watcher has applied since the REPL last asked, for its
/// "live: ..." line.
#[derive(Default)]
pub struct WatchStatus {
    applied: Mutex<ApplySummary>,
}

impl WatchStatus {
    fn record(&self, summary: ApplySummary) {
        let mut applied = self.applied.lock().expect("watch status lock poisoned");
        applied.added += summary.added;
        applied.updated += summary.updated;
        applied.retracted += summary.retracted;
        applied.removed_absent += summary.removed_absent;
    }

    /// The changes applied since the last call, resetting the count.
    pub fn take(&self) -> ApplySummary {
        std::mem::take(&mut *self.applied.lock().expect("watch status lock poisoned"))
    }
}

/// Start watching the cluster behind `client` and feeding `engine`.
/// Returns once every resource the cluster serves has been listed and its
/// objects applied. The watches then keep the engine current in the
/// background for as long as the tokio runtime runs.
pub async fn start(client: Client, engine: Arc<Mutex<Engine>>) -> Result<Arc<WatchStatus>> {
    let (sender, receiver) = unbounded();
    let mut resources = 0;
    for resource in cluster_resources() {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
        // Probe first: a watch on an API the cluster doesn't serve would
        // retry forever and the initial sync would never finish.
        match api.list(&ListParams::default().limit(1)).await {
            Ok(_) => {}
            Err(e) if is_not_served(&e) => {
                eprintln!(
                    "    {}: {} not served, skipping",
                    resource.kind, resource.api_version
                );
                continue;
            }
            Err(e) => return Err(e).with_context(|| format!("listing {}", resource.kind)),
        }
        resources += 1;
        let sync = ResourceSync::new(&resource.api_version, &resource.kind);
        tokio::spawn(watch_resource(api, sync, sender.clone()));
    }
    drop(sender);

    let status = Arc::new(WatchStatus::default());
    let (listed_sender, listed) = tokio::sync::oneshot::channel();
    let batcher_status = Arc::clone(&status);
    std::thread::spawn(move || {
        apply_batches(receiver, engine, batcher_status, resources, listed_sender)
    });
    if resources > 0 {
        listed
            .await
            .context("cluster watch stopped before the initial list finished")?;
    }
    Ok(status)
}

/// Run one resource's watch, sending its changes to the batcher. Errors
/// are reported and retried with backoff; the watch only ends when the
/// batcher is gone.
async fn watch_resource(api: Api<DynamicObject>, mut sync: ResourceSync, sender: Sender<Message>) {
    let mut stream = watcher(api, watcher::Config::default())
        .default_backoff()
        .boxed();
    while let Some(event) = stream.next().await {
        match event {
            Ok(event) => {
                let (changes, listed) = sync.on_event(event);
                if !changes.is_empty() && sender.send(Message::Changes(changes)).is_err() {
                    return;
                }
                if listed && sender.send(Message::Listed).is_err() {
                    return;
                }
            }
            Err(e) => eprintln!("watch {}: {e}", sync.kind),
        }
    }
}

/// Gather changes into batches and apply each under the engine lock.
/// `listed` fires once all `resources` have finished their first list and
/// those objects are in the engine.
fn apply_batches(
    receiver: Receiver<Message>,
    engine: Arc<Mutex<Engine>>,
    status: Arc<WatchStatus>,
    resources: usize,
    listed: tokio::sync::oneshot::Sender<()>,
) {
    let mut unlisted = resources;
    let mut listed = Some(listed);
    while let Ok(first) = receiver.recv() {
        let mut changes = Vec::new();
        let mut gather = |message: Message, changes: &mut Vec<Change>| match message {
            Message::Changes(batch) => changes.extend(batch),
            Message::Listed => unlisted = unlisted.saturating_sub(1),
        };
        gather(first, &mut changes);
        let deadline = Instant::now() + BATCH_WINDOW;
        while changes.len() < BATCH_MAX {
            match receiver.recv_deadline(deadline) {
                Ok(message) => gather(message, &mut changes),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
            }
        }
        if !changes.is_empty() {
            // Record while still holding the engine, so a command that sees
            // the new version also sees what changed.
            let mut engine = engine.lock().expect("engine lock poisoned");
            status.record(engine.apply_changes(changes));
        }
        if unlisted == 0
            && let Some(listed) = listed.take()
        {
            // The initial list is the starting state, not news.
            status.take();
            let _ = listed.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::api::ObjectMeta;

    fn role(name: &str) -> DynamicObject {
        DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("default".to_string()),
                ..ObjectMeta::default()
            },
            data: serde_json::json!({"rules": []}),
        }
    }

    fn key(name: &str) -> ObjectKey {
        ObjectKey::new("rbac.authorization.k8s.io/v1", "Role", "default", name)
    }

    /// The keys each change names: `+` for an upsert, `-` for a retract.
    fn named(changes: &[Change]) -> Vec<String> {
        let mut names: Vec<String> = changes
            .iter()
            .map(|change| match change {
                Change::Upsert(object) => format!("+{}", object.key.name),
                Change::Retract(key) => format!("-{}", key.name),
            })
            .collect();
        names.sort();
        names
    }

    fn sync() -> ResourceSync {
        ResourceSync::new("rbac.authorization.k8s.io/v1", "Role")
    }

    #[test]
    fn events_map_to_upserts_and_retracts() {
        let mut sync = sync();
        let (changes, listed) = sync.on_event(Event::Apply(role("a")));
        assert_eq!(named(&changes), ["+a"]);
        assert!(!listed);
        let Change::Upsert(object) = &changes[0] else {
            unreachable!()
        };
        assert_eq!(object.key, key("a"), "loads under the resource's type");

        let (changes, _) = sync.on_event(Event::Delete(role("a")));
        assert_eq!(named(&changes), ["-a"]);
        assert!(sync.known.is_empty());
    }

    /// A relist upserts what it lists and, when it ends, retracts what was
    /// known before but not listed again.
    #[test]
    fn relist_retracts_objects_gone_while_away() {
        let mut sync = sync();
        for name in ["a", "b"] {
            sync.on_event(Event::Apply(role(name)));
        }

        assert!(sync.on_event(Event::Init).0.is_empty());
        let (changes, listed) = sync.on_event(Event::InitApply(role("b")));
        assert_eq!(named(&changes), ["+b"]);
        assert!(!listed);
        sync.on_event(Event::InitApply(role("c")));
        let (changes, listed) = sync.on_event(Event::InitDone);
        assert_eq!(named(&changes), ["-a"]);
        assert!(listed);
        assert_eq!(sync.known, HashSet::from([key("b"), key("c")]));
    }

    /// The first list starts from nothing, so it retracts nothing.
    #[test]
    fn first_list_retracts_nothing() {
        let mut sync = sync();
        sync.on_event(Event::Init);
        sync.on_event(Event::InitApply(role("a")));
        let (changes, listed) = sync.on_event(Event::InitDone);
        assert!(changes.is_empty());
        assert!(listed);
    }
}
