use russh::keys::PublicKeyOrCertificate;
use warpgate_core::Services;
use warpgate_db_entities::Parameters;
use warpgate_db_entities::Parameters::SshHostKeyVerificationMode;

use crate::known_hosts::{KnownHostValidationResult, KnownHosts};

#[derive(Debug, thiserror::Error)]
pub enum TunnelHandlerError {
    #[error("SSH: {0}")]
    Ssh(#[from] russh::Error),
    #[error("host key for {host}:{port} does not match the one on record - refusing to connect")]
    HostKeyMismatch { host: String, port: u16 },
    #[error(
        "host key for {host}:{port} is unknown and the configured host-key \
         verification mode requires interactive approval, which a tunnel dial \
         can't provide - log into that host once through an interactive SSH \
         session first (to record its key), or switch host-key verification \
         to Auto-accept"
    )]
    HostKeyUnknownRequiresPrompt { host: String, port: u16 },
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),
}

/// A minimal `russh` client handler for a headless tunnel dial: verifies the
/// server's host key against the same `KnownHosts` store and global
/// verification policy interactive SSH sessions use, but - having no user to
/// prompt - fails closed instead of asking when the policy is `Prompt` and
/// the key is unknown. Every other `Handler` method keeps its default
/// (reject server-initiated channels), which is correct for a client that
/// only ever originates its own outbound `direct-tcpip` channel.
pub struct TunnelHandler {
    pub host: String,
    pub port: u16,
    pub services: Services,
}

impl russh::client::Handler for TunnelHandler {
    type Error = TunnelHandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let server_public_key = server_public_key.public_key();
        let mode = Parameters::Entity::get(&self.services.db)
            .await?
            .ssh_host_key_verification;

        if mode == SshHostKeyVerificationMode::Ignore {
            return Ok(true);
        }

        let known_hosts = KnownHosts::new(&self.services.db);
        match known_hosts
            .validate(&self.host, self.port, &server_public_key)
            .await?
        {
            KnownHostValidationResult::Valid => Ok(true),
            KnownHostValidationResult::Invalid { .. } => Err(TunnelHandlerError::HostKeyMismatch {
                host: self.host.clone(),
                port: self.port,
            }),
            KnownHostValidationResult::Unknown => match mode {
                SshHostKeyVerificationMode::AutoAccept => {
                    known_hosts
                        .trust(&self.host, self.port, &server_public_key)
                        .await?;
                    Ok(true)
                }
                SshHostKeyVerificationMode::AutoReject => Ok(false),
                SshHostKeyVerificationMode::Prompt => {
                    Err(TunnelHandlerError::HostKeyUnknownRequiresPrompt {
                        host: self.host.clone(),
                        port: self.port,
                    })
                }
                SshHostKeyVerificationMode::Ignore => unreachable!("handled above"),
            },
        }
    }
}
