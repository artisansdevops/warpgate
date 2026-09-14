mod auth;
mod chain;
pub mod config;
mod handler;
pub mod keys;
pub mod known_hosts;

use russh::ChannelStream;
use russh::client::Msg;
use warpgate_common::SshTunnelOptions;
use warpgate_core::Services;

/// Opens a `direct-tcpip` tunnel to `tunnel.host:tunnel.port` through the SSH
/// target it references, for a `connect_via` dial. See [`chain::dial`].
pub async fn dial_tunnel(
    services: &Services,
    tunnel: &SshTunnelOptions,
) -> anyhow::Result<ChannelStream<Msg>> {
    chain::dial(services, tunnel).await
}
