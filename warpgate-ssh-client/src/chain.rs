use std::collections::HashSet;

use anyhow::{Context, bail};
use russh::ChannelStream;
use russh::client::Msg;
use uuid::Uuid;
use warpgate_common::{SshTunnelOptions, TargetOptions, TargetSSHOptions};
use warpgate_core::{ConfigProvider, Services};

use crate::auth::{connect_and_authenticate, connect_stream_and_authenticate};

/// Follows `jump_host` links from `start`, returning the ordered target ids
/// of the chain (the target itself first, then each successive jump host).
///
/// `lookup` resolves a target id: `Some(Some(jump))` — an SSH target that
/// jumps through `jump`; `Some(None)` — an SSH target with no jump host,
/// ending the chain; `None` — the id does not resolve to an SSH target. An
/// unresolvable id, or one that repeats (a cycle), fails resolution.
///
/// Mirrors `warpgate-protocol-ssh`'s own `resolve_chain_ids` exactly (kept as
/// a separate, lightweight copy rather than a shared dependency — see the
/// crate-level docs for why) since a `connect_via` tunnel through a
/// jump-chained SSH target should behave exactly like an interactive session
/// through it would.
fn resolve_chain_ids(
    start: Uuid,
    lookup: impl Fn(Uuid) -> Option<Option<Uuid>>,
) -> anyhow::Result<Vec<Uuid>> {
    let mut ids = vec![];
    let mut visited = HashSet::new();
    let mut current = Some(start);
    while let Some(id) = current {
        if !visited.insert(id) {
            bail!("SSH jump host chain contains a cycle at target {id}");
        }
        let Some(jump_host) = lookup(id) else {
            bail!("target {id} does not resolve to an SSH target");
        };
        ids.push(id);
        current = jump_host;
    }
    Ok(ids)
}

/// Resolves the full ordered SSH jump chain for `start`: the outermost jump
/// host first, `start` itself last - the shape [`dial`] needs to connect hop
/// by hop.
async fn resolve_chain(services: &Services, start: Uuid) -> anyhow::Result<Vec<TargetSSHOptions>> {
    let targets = services
        .config_provider
        .list_targets()
        .await
        .context("listing targets to resolve the SSH tunnel's jump chain")?;

    let ids = resolve_chain_ids(start, |id| {
        targets.iter().find(|t| t.id == id).and_then(|t| match &t.options {
            TargetOptions::Ssh(opts) => Some(opts.jump_host),
            _ => None,
        })
    })?;

    let mut chain = Vec::with_capacity(ids.len());
    for id in ids {
        let Some(target) = targets.iter().find(|t| t.id == id) else {
            bail!("target {id} does not resolve to an SSH target");
        };
        let TargetOptions::Ssh(options) = &target.options else {
            bail!("target {id} does not resolve to an SSH target");
        };
        chain.push(options.clone());
    }
    chain.reverse();
    Ok(chain)
}

/// Opens a `direct-tcpip` channel to `tunnel.host:tunnel.port` through the
/// `Ssh`-kind target it references (and that target's own jump chain, if
/// any), returning a plain byte stream spliced onto the channel's data.
pub async fn dial(services: &Services, tunnel: &SshTunnelOptions) -> anyhow::Result<ChannelStream<Msg>> {
    let chain = resolve_chain(services, tunnel.ssh_target_id).await?;
    let mut iter = chain.into_iter();
    let first = iter
        .next()
        .context("SSH tunnel target does not resolve to any SSH hop")?;

    let mut session = connect_and_authenticate(services, &first).await?;

    for hop in iter {
        let channel = session
            .channel_open_direct_tcpip(hop.host.clone(), u32::from(hop.port), "localhost", 0)
            .await
            .with_context(|| {
                format!(
                    "opening a direct-tcpip channel to jump host {}:{}",
                    hop.host, hop.port
                )
            })?;
        session = connect_stream_and_authenticate(services, &hop, channel.into_stream()).await?;
    }

    let channel = session
        .channel_open_direct_tcpip(tunnel.host.clone(), u32::from(tunnel.port), "localhost", 0)
        .await
        .with_context(|| format!("opening a tunnel to {}:{}", tunnel.host, tunnel.port))?;

    Ok(channel.into_stream())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn resolve_chain_ids_returns_ordered_chain() {
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        // a -> b -> c -> (end)
        let jumps: HashMap<Uuid, Option<Uuid>> =
            HashMap::from([(a, Some(b)), (b, Some(c)), (c, None)]);
        let ids = resolve_chain_ids(a, |id| jumps.get(&id).copied()).unwrap();
        assert_eq!(ids, vec![a, b, c]);
    }

    #[test]
    fn resolve_chain_ids_detects_cycle() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let jumps: HashMap<Uuid, Option<Uuid>> = HashMap::from([(a, Some(b)), (b, Some(a))]);
        assert!(resolve_chain_ids(a, |id| jumps.get(&id).copied()).is_err());
    }

    #[test]
    fn resolve_chain_ids_rejects_unresolvable_jump_host() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        // `a` jumps through `b`, but `b` resolves to no SSH target.
        let jumps: HashMap<Uuid, Option<Uuid>> = HashMap::from([(a, Some(b))]);
        assert!(resolve_chain_ids(a, |id| jumps.get(&id).copied()).is_err());
    }
}
