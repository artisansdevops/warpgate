use anyhow::Context;
use tracing::debug;
use warpgate_aws::EksClusterInfo;
use warpgate_common::{KubernetesTargetAuth, TargetKubernetesOptions};

/// Build an authenticated `reqwest` client builder for talking to the cluster
/// backing `k8s_options`, applying whichever credential kind it's configured
/// with and, if `impersonate_connecting_user` is set, the `Impersonate-User`
/// header for `auth_user`.
///
/// Shared between the `Kubernetes` target's own reverse proxy
/// (`warpgate-protocol-kubernetes`) and anything tunneling a different
/// protocol through the same cluster's port-forward API (`crate::portforward`,
/// `crate::endpoints`) — both need to authenticate to the cluster identically.
pub async fn create_authenticated_client(
    k8s_options: &TargetKubernetesOptions,
    auth_user: Option<&str>,
) -> anyhow::Result<reqwest::ClientBuilder> {
    debug!(
        server_url = ?k8s_options.cluster_url,
        auth_kind = ?k8s_options.auth,
        tls_config = ?k8s_options.tls,
        impersonate_connecting_user = k8s_options.impersonate_connecting_user,
        "Creating authenticated Kubernetes client"
    );

    // Create HTTP client with the configuration
    let mut client_builder = reqwest::Client::builder();

    if !k8s_options.tls.verify {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    // Collected into a single map and applied with one `default_headers` call so
    // the credential's Authorization header and the impersonation header (set
    // below) can't clobber each other.
    let mut default_headers = reqwest::header::HeaderMap::new();

    match &k8s_options.auth {
        KubernetesTargetAuth::Token(auth) => {
            default_headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    auth.token.reveal()?.expose_secret()
                ))
                .context("setting Authorization header")?,
            );
        }
        KubernetesTargetAuth::Certificate(auth) => {
            // Expect PEM certificate and PEM private key in the auth config
            // Combine into a single PEM bundle for reqwest::Identity
            let cert_pem = auth.certificate.expose_secret();
            let key_pem = auth.private_key.reveal()?;
            let pem_bundle = format!(
                "{}\n{}\n",
                cert_pem.trim_end_matches('\n'),
                key_pem.expose_secret().trim_end_matches('\n')
            );

            let identity = reqwest::Identity::from_pem(pem_bundle.as_bytes())
                .context("Invalid client certificate/key for Kubernetes upstream")?;
            client_builder = client_builder.identity(identity);
        }
        KubernetesTargetAuth::IamRole(_) => {
            // EKS IAM role authentication: generate a token from the cluster URL
            let EksClusterInfo { name, region } =
                warpgate_aws::find_eks_cluster_by_url(&k8s_options.cluster_url)
                    .await
                    .context("EKS cluster lookup")?;

            let token = warpgate_aws::generate_eks_token(&name, &region)
                .await
                .context("EKS token generation")?;

            default_headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("setting Authorization header for EKS token")?,
            );
        }
    }

    if k8s_options.impersonate_connecting_user {
        let username = auth_user.context(
            "Kubernetes target has impersonation enabled but no Warpgate user is available",
        )?;
        default_headers.insert(
            reqwest::header::HeaderName::from_static("impersonate-user"),
            reqwest::header::HeaderValue::from_str(username)
                .context("setting Impersonate-User header")?,
        );
    }

    if !default_headers.is_empty() {
        client_builder = client_builder.default_headers(default_headers);
    }

    Ok(client_builder)
}
