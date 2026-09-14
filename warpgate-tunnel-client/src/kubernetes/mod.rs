pub mod auth;
pub mod endpoints;
pub mod portforward;

use anyhow::{Context, bail};
use warpgate_common::{KubernetesTunnelOptions, TargetOptions};
use warpgate_core::{ConfigProvider, Services};

use crate::BoxedStream;

/// Reach `tunnel`'s Service by port-forwarding through the `Kubernetes`-kind
/// target it references.
pub async fn dial(
    tunnel: &KubernetesTunnelOptions,
    services: &Services,
    connecting_username: Option<&str>,
) -> anyhow::Result<BoxedStream> {
    let targets = services
        .config_provider
        .list_targets()
        .await
        .context("listing targets to resolve Kubernetes tunnel")?;

    let k8s_target = targets
        .iter()
        .find(|t| t.id == tunnel.kubernetes_target_id)
        .with_context(|| {
            format!(
                "Kubernetes tunnel target {} does not exist",
                tunnel.kubernetes_target_id
            )
        })?;

    let TargetOptions::Kubernetes(k8s_options) = &k8s_target.options else {
        bail!(
            "target {} ({}) referenced by connect_via is not a Kubernetes target",
            k8s_target.name,
            tunnel.kubernetes_target_id
        );
    };

    let client = auth::create_authenticated_client(k8s_options, connecting_username)
        .await
        .context("authenticating to the Kubernetes cluster")?
        .http1_only()
        .build()
        .context("building Kubernetes API client")?;

    let backend = endpoints::resolve_service_backend(
        &client,
        &k8s_options.cluster_url,
        &tunnel.namespace,
        &tunnel.service,
        tunnel.port,
    )
    .await
    .context("resolving Kubernetes service backend")?;

    let stream = portforward::connect(
        client,
        &k8s_options.cluster_url,
        &tunnel.namespace,
        &backend.pod_name,
        backend.pod_port,
    )
    .await
    .context("opening Kubernetes port-forward")?;

    Ok(BoxedStream::new(stream))
}
