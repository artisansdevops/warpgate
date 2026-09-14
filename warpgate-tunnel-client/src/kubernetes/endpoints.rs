use anyhow::{Context, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct EndpointsList {
    #[serde(default)]
    subsets: Vec<EndpointSubset>,
}

#[derive(Debug, Deserialize)]
struct EndpointSubset {
    #[serde(default)]
    addresses: Vec<EndpointAddress>,
    #[serde(default)]
    ports: Vec<EndpointPort>,
}

#[derive(Debug, Deserialize)]
struct EndpointAddress {
    #[serde(rename = "targetRef")]
    target_ref: Option<TargetRef>,
}

#[derive(Debug, Deserialize)]
struct TargetRef {
    kind: Option<String>,
    name: String,
}

#[derive(Debug, Deserialize)]
struct EndpointPort {
    port: u16,
}

/// A live backend for a Kubernetes Service, resolved from its Endpoints - the
/// same information `kubectl port-forward svc/x` uses client-side to pick a
/// pod to forward to, since the port-forward API itself only ever addresses
/// pods.
pub struct ServiceBackend {
    pub pod_name: String,
    pub pod_port: u16,
}

/// Resolve `service`'s live backend by reading its `Endpoints` object.
/// `service_port` is the port number as declared on the Service; when the
/// Service exposes more than one port, it must match one of them exactly.
pub async fn resolve_service_backend(
    client: &reqwest::Client,
    cluster_url: &str,
    namespace: &str,
    service: &str,
    service_port: u16,
) -> anyhow::Result<ServiceBackend> {
    let url = format!("{cluster_url}/api/v1/namespaces/{namespace}/endpoints/{service}");
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetching Endpoints for service {namespace}/{service}"))?;

    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("Kubernetes API returned {status} for Endpoints {namespace}/{service}: {body}");
    }

    let endpoints: EndpointsList = response
        .json()
        .await
        .context("decoding Endpoints response")?;

    for subset in &endpoints.subsets {
        // A single-port Service's subset carries exactly one port; only
        // multi-port Services require matching by number.
        let pod_port = if subset.ports.len() == 1 {
            subset.ports[0].port
        } else if let Some(port) = subset.ports.iter().find(|p| p.port == service_port) {
            port.port
        } else {
            continue;
        };

        for address in &subset.addresses {
            if let Some(target_ref) = &address.target_ref
                && target_ref.kind.as_deref().unwrap_or("Pod") == "Pod"
            {
                return Ok(ServiceBackend {
                    pod_name: target_ref.name.clone(),
                    pod_port,
                });
            }
        }
    }

    bail!(
        "service {namespace}/{service} has no ready pod backing port {service_port} \
         (checked its Endpoints; is the Service selector matching any running, ready pods?)"
    )
}
