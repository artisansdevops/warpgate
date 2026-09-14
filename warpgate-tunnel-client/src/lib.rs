pub mod kubernetes;

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use warpgate_common::ConnectVia;
use warpgate_core::Services;

/// A dialed target connection, opaque to whichever transport actually
/// produced it: a direct TCP connection, or a tunnel through another target
/// (Kubernetes port-forward, SSH `direct-tcpip`). Every protocol client
/// (Redis/RabbitMQ/MySQL/Postgres/Tcp) layers its own TLS/wire protocol on
/// top of this the same way it used to layer it directly on a `TcpStream`.
///
/// A concrete newtype rather than a bare `Box<dyn Trait>` alias: erasing the
/// type through a generic blanket impl (as `warpgate_tls::UpgradableStream`
/// requires) confuses rustc's higher-ranked trait resolution once the stream
/// crosses an `async move` boundary (`tokio::spawn`), producing "implementation
/// of `UpgradableStream` is not general enough" errors. Naming the type
/// directly and implementing `AsyncRead`/`AsyncWrite` on it by hand sidesteps
/// that.
pub struct BoxedStream(Pin<Box<dyn AsyncReadWriteDyn>>);

trait AsyncReadWriteDyn: AsyncRead + AsyncWrite + Send {}
impl<T: AsyncRead + AsyncWrite + Send> AsyncReadWriteDyn for T {}

impl BoxedStream {
    pub fn new<T: AsyncRead + AsyncWrite + Send + 'static>(inner: T) -> Self {
        Self(Box::pin(inner))
    }
}

impl AsyncRead for BoxedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.0.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.0.as_mut().poll_shutdown(cx)
    }
}

/// Dial a target backend: directly over TCP to `host:port`, or - when
/// `connect_via` is set - through the tunnel it names (a Kubernetes target's
/// port-forward, or an SSH target's `direct-tcpip` channel).
///
/// `connecting_username` is only used by the Kubernetes tunnel, and only if
/// that Kubernetes target has `impersonate_connecting_user` set.
pub async fn dial_target(
    host: &str,
    port: u16,
    connect_via: Option<&ConnectVia>,
    services: &Services,
    connecting_username: Option<&str>,
) -> anyhow::Result<BoxedStream> {
    match connect_via {
        None => {
            let tcp = TcpStream::connect((host, port))
                .await
                .with_context(|| format!("connecting to {host}:{port}"))?;
            let _ = tcp.set_nodelay(true);
            Ok(BoxedStream::new(tcp))
        }
        Some(ConnectVia::Kubernetes(tunnel)) => {
            kubernetes::dial(tunnel, services, connecting_username).await
        }
        Some(ConnectVia::Ssh(tunnel)) => {
            let stream = warpgate_ssh_client::dial_tunnel(services, tunnel)
                .await
                .context("opening SSH tunnel")?;
            Ok(BoxedStream::new(stream))
        }
    }
}
