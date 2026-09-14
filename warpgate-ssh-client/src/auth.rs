use std::sync::Arc;

use anyhow::{Context, bail};
use russh::client::Handle;
use russh::keys::PrivateKeyWithHashAlg;
use tokio::io::{AsyncRead, AsyncWrite};
use warpgate_common::{SSHTargetAuth, TargetSSHOptions, WarpgateError};
use warpgate_core::Services;

use crate::handler::TunnelHandler;
use crate::keys::load_client_keys;

/// Connects directly (over TCP) to `ssh_options` and authenticates.
pub async fn connect_and_authenticate(
    services: &Services,
    ssh_options: &TargetSSHOptions,
) -> anyhow::Result<Handle<TunnelHandler>> {
    let config = crate::config::build_ssh_config(services, ssh_options).await;
    let handler = TunnelHandler {
        host: ssh_options.host.clone(),
        port: ssh_options.port,
        services: services.clone(),
    };
    let mut session = russh::client::connect(
        config,
        (ssh_options.host.as_str(), ssh_options.port),
        handler,
    )
    .await
    .with_context(|| format!("connecting to {}:{}", ssh_options.host, ssh_options.port))?;
    authenticate(&mut session, ssh_options, services).await?;
    Ok(session)
}

/// Connects to `ssh_options` over an already-open stream (a `direct-tcpip`
/// channel from the previous jump hop) and authenticates.
pub async fn connect_stream_and_authenticate<S>(
    services: &Services,
    ssh_options: &TargetSSHOptions,
    stream: S,
) -> anyhow::Result<Handle<TunnelHandler>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = crate::config::build_ssh_config(services, ssh_options).await;
    let handler = TunnelHandler {
        host: ssh_options.host.clone(),
        port: ssh_options.port,
        services: services.clone(),
    };
    let mut session = russh::client::connect_stream(config, stream, handler)
        .await
        .with_context(|| {
            format!(
                "connecting to {}:{} through the previous hop",
                ssh_options.host, ssh_options.port
            )
        })?;
    authenticate(&mut session, ssh_options, services).await?;
    Ok(session)
}

async fn authenticate(
    session: &mut Handle<TunnelHandler>,
    ssh_options: &TargetSSHOptions,
    services: &Services,
) -> anyhow::Result<()> {
    match &ssh_options.auth {
        SSHTargetAuth::Password(auth) => {
            let password = auth.password.reveal().map_err(WarpgateError::from)?;
            let result = session
                .authenticate_password(ssh_options.username.clone(), password.expose_secret())
                .await?;
            if !result.success() {
                bail!(
                    "password authentication to {}:{} was rejected",
                    ssh_options.host,
                    ssh_options.port
                );
            }
        }
        SSHTargetAuth::PublicKey(auth) => {
            let best_hash = session.best_supported_rsa_hash().await?.flatten();
            let keys = load_client_keys(&services.db, auth.key_id).await?;
            if keys.is_empty() {
                bail!("no SSH client keys are configured");
            }
            let mut authenticated = false;
            for key in keys {
                let key = Arc::new(key);
                let result = session
                    .authenticate_publickey(
                        ssh_options.username.clone(),
                        PrivateKeyWithHashAlg::new(key, best_hash),
                    )
                    .await?;
                if result.success() {
                    authenticated = true;
                    break;
                }
            }
            if !authenticated {
                bail!(
                    "public key authentication to {}:{} was rejected",
                    ssh_options.host,
                    ssh_options.port
                );
            }
        }
        SSHTargetAuth::IamRole(_) => {
            bail!(
                "IAM-role SSH authentication is not yet supported for connect_via tunnels \
                 (target {}:{})",
                ssh_options.host,
                ssh_options.port
            );
        }
    }
    Ok(())
}
