use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use amq_protocol::frame::AMQPFrame;
use amq_protocol::protocol::AMQPClass;
use amq_protocol::protocol::connection::{self, AMQPMethod};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio::time;
use tracing::{info, info_span, warn};
use url::Url;
use warpgate_common::auth::AuthSelector;
use warpgate_common::{Protocol, Secret, TargetRabbitMqOptions, UserSessionId};
use warpgate_common_http::ext::construct_external_url;
use warpgate_core::{
    AdmittedTarget, ApprovedTarget, AuthOkPermit, DbAuthTransport, Services, WarpgateServerHandle,
    run_db_authorization,
};

use crate::client::RabbitMqClient;
use crate::common::{OUR_CHANNEL_MAX, OUR_FRAME_MAX, OUR_HEARTBEAT, PROTOCOL_HEADER};
use crate::error::RabbitMqError;
use crate::relay::{RelayEnd, parse_idle_timeout, relay};
use crate::wire::{
    long_string, peer_properties, read_frame, read_header, write_frame, write_header,
};

pub struct RabbitMqSession<S: AsyncRead + AsyncWrite + Send + Unpin> {
    stream: S,
    username: Option<String>,
    /// The password arrives inline with `Connection.StartOk`'s SASL `PLAIN`
    /// response, so the shared auth flow can only be handed it once - never
    /// prompted for it again.
    pending_password: Option<Secret<String>>,
    server_handle: Arc<Mutex<WarpgateServerHandle>>,
    id: UserSessionId,
    services: Services,
    remote_address: SocketAddr,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> DbAuthTransport for RabbitMqSession<S> {
    type Error = RabbitMqError;

    const PROTOCOL: Protocol = crate::common::PROTOCOL_NAME;
    const SUPPORTS_WEB_APPROVAL: bool = false;

    async fn prompt_password(&mut self) -> Result<Option<Secret<String>>, RabbitMqError> {
        Ok(self.pending_password.take())
    }

    /// There's no lightweight "you're in" reply in AMQP - a successful login
    /// is signalled by continuing the handshake with `Connection.Tune`.
    async fn send_auth_ok(&mut self, _permit: AuthOkPermit) -> Result<(), RabbitMqError> {
        write_frame(&mut self.stream, &tune_frame()).await
    }

    async fn external_url(&mut self) -> Result<Url, RabbitMqError> {
        Ok(construct_external_url(None, &*self.services.config.lock().await, None).await?)
    }

    /// AMQP has no side-channel message a client displays mid-authentication,
    /// so a policy requiring web approval can't be satisfied over RabbitMQ.
    async fn send_web_approval_prompt(
        &mut self,
        _url: &Url,
        _identification_string: &str,
    ) -> Result<bool, RabbitMqError> {
        warn!("Web user approval is not supported over the RabbitMQ protocol");
        Ok(false)
    }

    async fn send_denied(&mut self) -> Result<(), RabbitMqError> {
        self.send_close(
            530,
            "ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN. For details see the broker logfile.",
        )
        .await
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> RabbitMqSession<S> {
    pub async fn new(
        server_handle: Arc<Mutex<WarpgateServerHandle>>,
        services: Services,
        stream: S,
        remote_address: SocketAddr,
    ) -> Self {
        let id = server_handle.lock().await.user_session_id();
        Self {
            stream,
            username: None,
            pending_password: None,
            server_handle,
            id,
            services,
            remote_address,
        }
    }

    pub fn make_logging_span(&self) -> tracing::Span {
        let client_ip = self.remote_address.ip().to_string();
        if let Some(ref username) = self.username {
            info_span!("RabbitMQ", session=%self.id, session_username=%username, %client_ip)
        } else {
            info_span!("RabbitMQ", session=%self.id, %client_ip)
        }
    }

    async fn send_close(&mut self, reply_code: u16, reply_text: &str) -> Result<(), RabbitMqError> {
        let frame = AMQPFrame::Method(
            0,
            AMQPClass::Connection(AMQPMethod::Close(connection::Close {
                reply_code,
                reply_text: reply_text.into(),
                class_id: 0,
                method_id: 0,
            })),
        );
        write_frame(&mut self.stream, &frame).await?;
        // Best-effort: give the client a moment to send CloseOk so it sees a
        // clean close rather than a reset, then close either way.
        let _ = time::timeout(Duration::from_secs(2), read_frame(&mut self.stream)).await;
        Ok(())
    }

    /// AMQP's handshake is driven entirely by the client: Warpgate answers the
    /// protocol header with a synthetic `Connection.Start` advertising `PLAIN`
    /// as the only SASL mechanism, then reads the `StartOk` back to recover
    /// the `user#target` selector and password carried in its response.
    pub async fn run(mut self) -> Result<(), RabbitMqError> {
        let header = match read_header(&mut self.stream).await {
            Ok(header) => header,
            Err(_) => return Ok(()),
        };
        if header != PROTOCOL_HEADER {
            // Per spec, a version mismatch gets the header we do support back,
            // rather than continuing a handshake the client can't speak.
            let _ = write_header(&mut self.stream).await;
            return Ok(());
        }

        write_frame(&mut self.stream, &start_frame()).await?;

        let start_ok = match read_frame(&mut self.stream).await? {
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::StartOk(start_ok))) => start_ok,
            _ => {
                self.send_close(503, "COMMAND_INVALID - expected Connection.StartOk")
                    .await?;
                return Ok(());
            }
        };

        if start_ok.mechanism.as_str() != "PLAIN" {
            self.send_close(
                503,
                "COMMAND_INVALID - only the PLAIN SASL mechanism is supported",
            )
            .await?;
            return Ok(());
        }

        let Some((username, password)) = parse_plain_response(start_ok.response.as_bytes()) else {
            self.send_close(503, "COMMAND_INVALID - malformed PLAIN response")
                .await?;
            return Ok(());
        };

        self.authenticate(username, Secret::from(password)).await
    }

    async fn authenticate(
        mut self,
        raw_selector: String,
        password: Secret<String>,
    ) -> Result<(), RabbitMqError> {
        self.username = Some(raw_selector.clone());
        self.pending_password = Some(password);

        let selector: AuthSelector = raw_selector.into();
        let remote_ip = self.remote_address.ip();
        let session_id = self.id;
        let services = self.services.clone();

        let Some(approved) =
            run_db_authorization(&mut self, &services, session_id, selector, remote_ip).await?
        else {
            return Ok(());
        };

        self.run_authorized(approved).await
    }

    async fn run_authorized(mut self, approved: ApprovedTarget) -> Result<(), RabbitMqError> {
        let Ok(approved) = approved.narrow::<TargetRabbitMqOptions>() else {
            warn!("Selected target is not a RabbitMQ target");
            self.send_close(530, "NOT_ALLOWED - Warpgate target not found")
                .await?;
            return Ok(());
        };

        let admitted = self
            .server_handle
            .lock()
            .await
            .register_approved_target_session(approved)
            .await?;

        self.run_authorized_inner(admitted).await
    }

    async fn run_authorized_inner(
        mut self,
        admitted: AdmittedTarget<TargetRabbitMqOptions>,
    ) -> Result<(), RabbitMqError> {
        let options = admitted.specific_target().options().clone();
        let connecting_username = admitted.user_info().username.clone();
        match read_frame(&mut self.stream).await? {
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::TuneOk(_))) => {}
            _ => {
                self.send_close(503, "COMMAND_INVALID - expected Connection.TuneOk")
                    .await?;
                return Ok(());
            }
        }

        let open = match read_frame(&mut self.stream).await? {
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::Open(open))) => open,
            _ => {
                self.send_close(503, "COMMAND_INVALID - expected Connection.Open")
                    .await?;
                return Ok(());
            }
        };
        let vhost = open.virtual_host.as_str().to_owned();

        let services = self.services.clone();
        let mut client =
            match RabbitMqClient::connect(&options, &vhost, &services, Some(&connecting_username))
                .await
            {
                Err(error) => {
                    self.send_close(541, "INTERNAL_ERROR - Warpgate target connection failed")
                        .await?;
                    Err(error)
                }
                x => x,
            }?;

        write_frame(&mut self.stream, &open_ok_frame()).await?;

        let idle_timeout = parse_idle_timeout(options.idle_timeout.as_deref());
        if let Some(timeout) = idle_timeout {
            info!(
                idle_timeout_seconds = timeout.as_secs(),
                "Using configured idle timeout for session"
            );
        }

        match relay(&mut self.stream, &mut client.stream, idle_timeout).await? {
            RelayEnd::Eof => {}
            RelayEnd::IdleTimeout { elapsed, timeout } => {
                self.send_close(
                    530,
                    &format!(
                        "CONNECTION_FORCED - Session idle for {} exceeded configured timeout of {}. Please reconnect.",
                        humantime::format_duration(elapsed),
                        humantime::format_duration(timeout)
                    ),
                )
                .await?;
            }
        }

        Ok(())
    }
}

/// Parses a SASL `PLAIN` response: `[authzid] NUL authcid NUL passwd`. The
/// authzid is conventionally empty and always ignored here.
fn parse_plain_response(bytes: &[u8]) -> Option<(String, String)> {
    let mut parts = bytes.splitn(3, |&b| b == 0);
    let _authzid = parts.next()?;
    let username = parts.next()?;
    let password = parts.next()?;
    Some((
        String::from_utf8_lossy(username).into_owned(),
        String::from_utf8_lossy(password).into_owned(),
    ))
}

fn start_frame() -> AMQPFrame {
    AMQPFrame::Method(
        0,
        AMQPClass::Connection(AMQPMethod::Start(connection::Start {
            version_major: 0,
            version_minor: 9,
            server_properties: peer_properties(),
            mechanisms: long_string("PLAIN"),
            locales: long_string("en_US"),
        })),
    )
}

fn tune_frame() -> AMQPFrame {
    AMQPFrame::Method(
        0,
        AMQPClass::Connection(AMQPMethod::Tune(connection::Tune {
            channel_max: OUR_CHANNEL_MAX,
            frame_max: OUR_FRAME_MAX,
            heartbeat: OUR_HEARTBEAT,
        })),
    )
}

fn open_ok_frame() -> AMQPFrame {
    AMQPFrame::Method(
        0,
        AMQPClass::Connection(AMQPMethod::OpenOk(connection::OpenOk {})),
    )
}
