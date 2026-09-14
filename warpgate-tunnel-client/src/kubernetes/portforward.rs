use anyhow::{Context, bail};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use reqwest_websocket::{Message, Upgrade};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tracing::{debug, warn};
use url::Url;

/// The subprotocol Kubernetes API servers negotiate for a WebSocket-carried
/// port-forward stream, the same one `warpgate-protocol-kubernetes` already
/// offers when it proxies a connecting `kubectl port-forward` through to a
/// cluster (see `server::handlers`). Requires a cluster new enough to support
/// port-forwarding over WebSocket rather than only over SPDY.
const PORTFORWARD_PROTOCOL: &str = "SPDY/3.1+portforward.k8s.io";

/// Data channel index for the (single) forwarded port. Kubernetes' WebSocket
/// channel protocols multiplex several logical streams over one connection by
/// prefixing every binary message with a 1-byte channel id; port-forward uses
/// two channels per requested port (data, then error) in the order the ports
/// were requested. Since exactly one port is ever requested here, its data
/// channel is always 0 and its error channel is always 1.
const CHANNEL_DATA: u8 = 0;
const CHANNEL_ERROR: u8 = 1;

fn portforward_url(cluster_url: &str, namespace: &str, pod: &str, port: u16) -> anyhow::Result<Url> {
    let mut url = Url::parse(&format!(
        "{cluster_url}/api/v1/namespaces/{namespace}/pods/{pod}/portforward?ports={port}"
    ))
    .context("constructing port-forward URL")?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme)
        .map_err(|()| anyhow::anyhow!("failed to set websocket scheme on port-forward URL"))?;
    Ok(url)
}

/// Open a port-forward to `pod:port` in `namespace` on the cluster `client` is
/// authenticated against, returning a plain byte stream spliced onto the
/// forwarded port's data channel.
///
/// A background task owns the WebSocket connection for the lifetime of the
/// returned stream: it demultiplexes incoming data-channel messages onto one
/// end of a duplex pipe, prefixes outgoing bytes from the other end with the
/// data channel id, and logs whatever the cluster sends on the error channel
/// (there's no way to surface it to the caller mid-stream; it isn't fatal by
/// itself; the socket just closes if the target process really did fail).
pub async fn connect(
    client: reqwest::Client,
    cluster_url: &str,
    namespace: &str,
    pod: &str,
    port: u16,
) -> anyhow::Result<DuplexStream> {
    let url = portforward_url(cluster_url, namespace, pod, port)?;

    let response = client
        .get(url)
        .upgrade()
        .protocols(vec![PORTFORWARD_PROTOCOL])
        .send()
        .await
        .context("sending port-forward websocket upgrade request to Kubernetes API")?;

    let status = response.status();
    if status != reqwest::StatusCode::SWITCHING_PROTOCOLS {
        let body = response.into_inner().text().await.unwrap_or_default();
        bail!("Kubernetes API refused the port-forward upgrade ({status}): {body}");
    }

    let socket = response
        .into_websocket()
        .await
        .context("negotiating port-forward websocket connection with Kubernetes")?;
    let (mut sink, mut source) = socket.split();

    let (near, far) = tokio::io::duplex(64 * 1024);
    let (mut near_read, mut near_write) = tokio::io::split(near);

    tokio::spawn(async move {
        let mut read_buf = [0u8; 64 * 1024];
        loop {
            tokio::select! {
                incoming = source.next() => {
                    match incoming {
                        Some(Ok(Message::Binary(data))) => {
                            match data.first() {
                                Some(&CHANNEL_DATA) if data.len() > 1 => {
                                    if near_write.write_all(&data[1..]).await.is_err() {
                                        break;
                                    }
                                }
                                Some(&CHANNEL_ERROR) => {
                                    warn!(
                                        message = %String::from_utf8_lossy(&data[1..]),
                                        "Kubernetes port-forward error channel"
                                    );
                                }
                                _ => {}
                            }
                        }
                        Some(Ok(Message::Close { .. })) | None => break,
                        Some(Ok(_)) => {}
                        Some(Err(error)) => {
                            debug!(%error, "Kubernetes port-forward websocket error");
                            break;
                        }
                    }
                }
                read = near_read.read(&mut read_buf) => {
                    match read {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut frame = Vec::with_capacity(n + 1);
                            frame.push(CHANNEL_DATA);
                            frame.extend_from_slice(&read_buf[..n]);
                            if sink.send(Message::Binary(Bytes::from(frame))).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
        let _ = sink.close().await;
    });

    Ok(far)
}
