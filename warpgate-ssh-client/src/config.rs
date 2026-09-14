use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::{Preferred, kex, mac};
use warpgate_common::TargetSSHOptions;
use warpgate_core::Services;

/// Builds the `russh` client config for connecting to `ssh_options`, applying
/// the legacy-algorithm allowlist (`allow_insecure_algos`) and the
/// keepalive/inactivity-timeout settings from the global SSH config.
pub async fn build_ssh_config(
    services: &Services,
    ssh_options: &TargetSSHOptions,
) -> Arc<russh::client::Config> {
    let algos = if ssh_options.allow_insecure_algos {
        Preferred {
            kex: Cow::Borrowed(&[
                kex::MLKEM768X25519_SHA256,
                kex::CURVE25519,
                kex::CURVE25519_PRE_RFC_8731,
                kex::ECDH_SHA2_NISTP256,
                kex::ECDH_SHA2_NISTP384,
                kex::ECDH_SHA2_NISTP521,
                kex::DH_G16_SHA512,
                kex::DH_G14_SHA256,
                kex::DH_GEX_SHA256,
                kex::DH_G1_SHA1,
                kex::EXTENSION_SUPPORT_AS_CLIENT,
                kex::EXTENSION_SUPPORT_AS_SERVER,
                kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
                kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
            ]),
            key: Cow::Borrowed(&[
                russh::keys::Algorithm::Ed25519,
                russh::keys::Algorithm::Ecdsa {
                    curve: russh::keys::EcdsaCurve::NistP256,
                },
                russh::keys::Algorithm::Ecdsa {
                    curve: russh::keys::EcdsaCurve::NistP384,
                },
                russh::keys::Algorithm::Ecdsa {
                    curve: russh::keys::EcdsaCurve::NistP521,
                },
                russh::keys::Algorithm::Rsa {
                    hash: Some(russh::keys::HashAlg::Sha256),
                },
                russh::keys::Algorithm::Rsa {
                    hash: Some(russh::keys::HashAlg::Sha512),
                },
                russh::keys::Algorithm::Rsa { hash: None },
                russh::keys::Algorithm::Dsa,
            ]),
            cipher: Cow::Borrowed(&[
                russh::cipher::CHACHA20_POLY1305,
                russh::cipher::AES_256_GCM,
                russh::cipher::AES_256_CTR,
                russh::cipher::AES_256_CBC,
                russh::cipher::AES_192_CTR,
                russh::cipher::AES_192_CBC,
                russh::cipher::AES_128_CTR,
                russh::cipher::AES_128_CBC,
                russh::cipher::TRIPLE_DES_CBC,
            ]),
            // The secure defaults exclude SHA-1 MACs; append them here for
            // legacy devices (e.g. older network switches that only offer
            // hmac-sha1). https://github.com/warp-tech/warpgate/issues/2066
            mac: Cow::Borrowed(&[
                mac::HMAC_SHA512_ETM,
                mac::HMAC_SHA256_ETM,
                mac::HMAC_SHA512,
                mac::HMAC_SHA256,
                mac::HMAC_SHA1_ETM,
                mac::HMAC_SHA1,
            ]),
            ..<_>::default()
        }
    } else {
        Preferred::default()
    };

    let ssh_config = { services.config.lock().await.store.ssh.clone() };
    let mut config = russh::client::Config {
        preferred: algos,
        nodelay: true,
        // Extra time for the "closing due to inactivity" message to be sent
        inactivity_timeout: Some(ssh_config.inactivity_timeout + Duration::from_secs(10)),
        keepalive_interval: ssh_config.keepalive_interval,
        ..Default::default()
    };
    if ssh_options.allow_insecure_algos
        && let Ok(gex) = russh::client::GexParams::new(2048, 2048, 8192)
    {
        config.gex = gex;
    }
    Arc::new(config)
}
