use std::sync::Arc;

use bytes::Bytes;
use futures::FutureExt;
use futures::future::BoxFuture;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
use warpgate_common::{TargetOptions, TargetTcpOptions};
use warpgate_core::{ConfigProvider, Services};
use warpgate_tunnel_client::BoxedStream;
use warpgate_tls::{ClientTlsStream, MaybeTlsStream, TlsMode, configure_tls_connector};

/// Relays raw TCP for protocols with no dedicated Warpgate support. Unlike
/// every other protocol server, this has no single listen address to bind:
/// each `Tcp` target carries its own (see `TargetTcpOptions::listen_address`/
/// `listen_port`), since raw TCP has no in-band way to select a target the
/// way other protocols' auth handshakes do.
///
/// That also means there is no Warpgate user identity to establish for a
/// connection - `Tcp` targets are not gated by Warpgate's per-user RBAC or
/// ticket policies (unlike every other target type) and don't appear in the
/// session audit log. Access control is whatever reaches the listen address;
/// operators should restrict that with network controls (firewall, VPN,
/// binding to a private interface) the way they would for a raw `socat` or
/// `iptables` port-forward.
pub struct TcpProtocolServer;

impl TcpProtocolServer {
    /// Binds one listener per currently-configured `Tcp` target and returns
    /// their accept loops. Since each target owns its own listener (rather
    /// than sharing one like every other protocol), targets added or edited
    /// after this call requires a Warpgate restart to take effect.
    pub async fn bind_all(services: &Services) -> anyhow::Result<Vec<BoxFuture<'static, anyhow::Result<()>>>> {
        let targets = services.config_provider.list_targets().await?;

        let mut accept_loops = Vec::new();
        for target in targets {
            let TargetOptions::Tcp(options) = target.options else {
                continue;
            };

            let bind_address = format!("{}:{}", options.listen_address, options.listen_port);
            let listener = match TcpListener::bind(&bind_address).await {
                Ok(listener) => listener,
                Err(error) => {
                    error!(target = %target.name, %bind_address, %error, "Failed to bind TCP target listener");
                    continue;
                }
            };
            info!(target = %target.name, %bind_address, "TCP target listening");

            accept_loops.push(accept_loop(target.name, listener, options, services.clone()).boxed());
        }

        Ok(accept_loops)
    }
}

async fn accept_loop(
    target_name: String,
    listener: TcpListener,
    options: TargetTcpOptions,
    services: Services,
) -> anyhow::Result<()> {
    let options = Arc::new(options);
    loop {
        let (stream, remote_address) = match listener.accept().await {
            Ok(x) => x,
            Err(error) => {
                warn!(target = %target_name, %error, "Failed to accept a TCP connection");
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let target_name = target_name.clone();
        let options = options.clone();
        let services = services.clone();
        tokio::spawn(async move {
            if let Err(error) = relay_one(&options, stream, &services).await {
                warn!(target = %target_name, %remote_address, %error, "TCP relay session failed");
            } else {
                info!(target = %target_name, %remote_address, "TCP relay session ended");
            }
        });
    }
}

async fn relay_one(
    options: &TargetTcpOptions,
    mut client_stream: TcpStream,
    services: &Services,
) -> anyhow::Result<()> {
    let transport = warpgate_tunnel_client::dial_target(
        &options.host,
        options.port,
        options.connect_via.as_ref(),
        // No Warpgate user is ever established for a `Tcp` target (see the
        // module-level docs), so impersonation-on-tunnel isn't available here.
        services,
        None,
    )
    .await?;

    let mut backend_stream = MaybeTlsStream::<BoxedStream, ClientTlsStream<BoxedStream>>::new(transport);

    if options.tls.mode != TlsMode::Disabled {
        let accept_invalid_certs = !options.tls.verify;
        let accept_invalid_hostname = false;
        let client_config =
            Arc::new(configure_tls_connector(accept_invalid_certs, accept_invalid_hostname, None).await?);
        let domain = options
            .host
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid TLS server name: {}", options.host))?;
        backend_stream = backend_stream
            .upgrade((domain, client_config), Bytes::new())
            .await?;
    }

    tokio::io::copy_bidirectional(&mut client_stream, &mut backend_stream).await?;
    Ok(())
}
