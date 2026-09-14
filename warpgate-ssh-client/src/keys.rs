use russh::keys::{PrivateKey, decode_secret_key};
use sea_orm::{DatabaseConnection, EntityTrait};
use tracing::warn;
use uuid::Uuid;
use warpgate_common::WarpgateError;
use warpgate_common::encryption::idempotent_maybe_decrypt;
use warpgate_db_entities::SshClientKey;

/// The stored keys to offer a target that authenticates without a specific key
/// selected: the default-flagged ones, or — if none are flagged — every key, so
/// clearing every default never locks targets out.
async fn default_client_keys(
    db: &DatabaseConnection,
) -> Result<Vec<SshClientKey::Model>, WarpgateError> {
    let defaults = SshClientKey::Entity::find_default().all(db).await?;
    if defaults.is_empty() {
        Ok(SshClientKey::Entity::find_ordered().all(db).await?)
    } else {
        Ok(defaults)
    }
}

/// The private keys to try against a target: the specific chosen key, or the
/// default set. A chosen key that no longer exists falls back to the default
/// set (e.g. after the key was deleted, or on a node that hasn't synced it).
pub async fn load_client_keys(
    db: &DatabaseConnection,
    key_id: Option<Uuid>,
) -> Result<Vec<PrivateKey>, WarpgateError> {
    let models = match key_id {
        Some(id) => {
            if let Some(model) = SshClientKey::Entity::find_by_id(id).one(db).await? {
                vec![model]
            } else {
                warn!("SSH client key {id} chosen for the target does not exist; using defaults");
                default_client_keys(db).await?
            }
        }
        None => default_client_keys(db).await?,
    };
    models
        .iter()
        .map(|m| {
            Ok(decode_secret_key(
                &idempotent_maybe_decrypt(&m.secret_key)?,
                None,
            )?)
        })
        .collect()
}
