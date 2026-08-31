use std::sync::Arc;

use amq_protocol::frame::AMQPFrame;
use amq_protocol::protocol::AMQPClass;
use amq_protocol::protocol::connection::{self, AMQPMethod};
use bytes::Bytes;
use tokio::net::TcpStream;
use tracing::info;
use warpgate_common::{RabbitMqTargetAuth, TargetRabbitMqOptions, WarpgateError};
use warpgate_tls::{ClientTlsStream, MaybeTlsStream, TlsMode, configure_tls_connector};

use crate::common::{OUR_CHANNEL_MAX, OUR_FRAME_MAX, OUR_HEARTBEAT};
use crate::error::RabbitMqError;
use crate::wire::{long_string, peer_properties, read_frame, write_frame};

pub struct RabbitMqClient {
    pub stream: MaybeTlsStream<TcpStream, ClientTlsStream<TcpStream>>,
}

impl RabbitMqClient {
    /// Dials the target broker and completes the AMQP handshake with
    /// Warpgate's own configured credentials, opening the same virtual host
    /// the client asked Warpgate for. On success, the returned stream is
    /// ready for the two sides to be blindly relayed to each other.
    pub async fn connect(
        target: &TargetRabbitMqOptions,
        vhost: &str,
    ) -> Result<Self, RabbitMqError> {
        let tcp = TcpStream::connect((target.host.clone(), target.port)).await?;
        tcp.set_nodelay(true)?;

        let mut stream = MaybeTlsStream::<TcpStream, ClientTlsStream<TcpStream>>::new(tcp);

        if target.tls.mode != TlsMode::Disabled {
            let accept_invalid_certs = !target.tls.verify;
            let accept_invalid_hostname = false; // CA + hostname verification
            let client_config = Arc::new(
                configure_tls_connector(accept_invalid_certs, accept_invalid_hostname, None)
                    .await?,
            );
            let domain = target
                .host
                .clone()
                .try_into()
                .map_err(|_| RabbitMqError::InvalidDomainName)?;
            stream = stream
                .upgrade((domain, client_config), Bytes::new())
                .await?;
            info!("Target connection established over TLS");
        }

        crate::wire::write_header(&mut stream).await?;

        let start = match read_frame(&mut stream).await? {
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::Start(start))) => start,
            other => {
                return Err(RabbitMqError::ProtocolError(format!(
                    "expected Connection.Start from target, got {other:?}"
                )));
            }
        };

        if !mechanisms_contains_plain(start.mechanisms.as_bytes()) {
            return Err(RabbitMqError::ProtocolError(
                "target does not support the PLAIN SASL mechanism".into(),
            ));
        }

        let RabbitMqTargetAuth::Password(auth) = &target.auth;
        let password = auth
            .password
            .reveal()
            .map_err(WarpgateError::from)?
            .expose_secret()
            .clone();

        let response = format!("\0{}\0{password}", target.username);
        write_frame(
            &mut stream,
            &AMQPFrame::Method(
                0,
                AMQPClass::Connection(AMQPMethod::StartOk(connection::StartOk {
                    client_properties: peer_properties(),
                    mechanism: "PLAIN".into(),
                    response: long_string(&response),
                    locale: "en_US".into(),
                })),
            ),
        )
        .await?;

        let tune = match read_frame(&mut stream).await? {
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::Tune(tune))) => tune,
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::Close(close))) => {
                return Err(RabbitMqError::RemoteError(format!(
                    "{}: {}",
                    close.reply_code,
                    close.reply_text.as_str()
                )));
            }
            other => {
                return Err(RabbitMqError::ProtocolError(format!(
                    "expected Connection.Tune from target, got {other:?}"
                )));
            }
        };

        let (channel_max, frame_max, heartbeat) = negotiate_tune(&tune);
        write_frame(
            &mut stream,
            &AMQPFrame::Method(
                0,
                AMQPClass::Connection(AMQPMethod::TuneOk(connection::TuneOk {
                    channel_max,
                    frame_max,
                    heartbeat,
                })),
            ),
        )
        .await?;

        write_frame(
            &mut stream,
            &AMQPFrame::Method(
                0,
                AMQPClass::Connection(AMQPMethod::Open(connection::Open {
                    virtual_host: vhost.into(),
                })),
            ),
        )
        .await?;

        match read_frame(&mut stream).await? {
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::OpenOk(_))) => {}
            AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::Close(close))) => {
                return Err(RabbitMqError::RemoteError(format!(
                    "{}: {}",
                    close.reply_code,
                    close.reply_text.as_str()
                )));
            }
            other => {
                return Err(RabbitMqError::ProtocolError(format!(
                    "expected Connection.OpenOk from target, got {other:?}"
                )));
            }
        }

        Ok(Self { stream })
    }
}

fn mechanisms_contains_plain(raw: &[u8]) -> bool {
    String::from_utf8_lossy(raw)
        .split_whitespace()
        .any(|m| m == "PLAIN")
}

/// TuneOk sent to the target has to stay within what it just offered; the
/// values already promised to the client (`OUR_*`) are used as-is only when
/// the target imposes no stricter limit (`0` conventionally means "no
/// limit"). A target requiring a *smaller* frame-max than what the client was
/// already told is a rare mismatch this proxy doesn't reconcile - see
/// `session.rs` for the corresponding tradeoff on the client side.
fn negotiate_tune(target: &connection::Tune) -> (u16, u32, u16) {
    let channel_max = if target.channel_max == 0 {
        OUR_CHANNEL_MAX
    } else {
        OUR_CHANNEL_MAX.min(target.channel_max)
    };
    let frame_max = if target.frame_max == 0 {
        OUR_FRAME_MAX
    } else {
        OUR_FRAME_MAX.min(target.frame_max)
    };
    let heartbeat = if target.heartbeat == 0 || OUR_HEARTBEAT == 0 {
        0
    } else {
        OUR_HEARTBEAT.min(target.heartbeat)
    };
    (channel_max, frame_max, heartbeat)
}

#[cfg(test)]
mod tests {
    use amq_protocol::types::FieldTable;
    use tokio::net::TcpListener;
    use warpgate_common::{DatabaseTargetPasswordAuth, StoredSecret, Tls};
    use warpgate_tls::TlsMode;

    use super::*;
    use crate::wire::{long_string, read_frame, read_header, write_frame};

    /// Drives `RabbitMqClient::connect` against a hand-scripted TCP listener
    /// playing the real broker's side of the handshake, exercising the wire
    /// encoding/decoding and the tune negotiation end to end.
    #[tokio::test]
    async fn completes_handshake_against_a_mock_broker() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            let header = read_header(&mut sock).await.unwrap();
            assert_eq!(header, crate::common::PROTOCOL_HEADER);

            write_frame(
                &mut sock,
                &AMQPFrame::Method(
                    0,
                    AMQPClass::Connection(AMQPMethod::Start(connection::Start {
                        version_major: 0,
                        version_minor: 9,
                        server_properties: FieldTable::default(),
                        mechanisms: long_string("PLAIN"),
                        locales: long_string("en_US"),
                    })),
                ),
            )
            .await
            .unwrap();

            let AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::StartOk(start_ok))) =
                read_frame(&mut sock).await.unwrap()
            else {
                panic!("expected StartOk");
            };
            assert_eq!(start_ok.mechanism.as_str(), "PLAIN");
            assert_eq!(start_ok.response.as_bytes(), b"\0myuser\0mypass");

            write_frame(
                &mut sock,
                &AMQPFrame::Method(
                    0,
                    AMQPClass::Connection(AMQPMethod::Tune(connection::Tune {
                        channel_max: 100,
                        frame_max: 4096,
                        heartbeat: 30,
                    })),
                ),
            )
            .await
            .unwrap();

            let AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::TuneOk(tune_ok))) =
                read_frame(&mut sock).await.unwrap()
            else {
                panic!("expected TuneOk");
            };
            // Negotiated values must never exceed what the target proposed.
            assert_eq!(tune_ok.channel_max, 100);
            assert_eq!(tune_ok.frame_max, 4096);
            assert_eq!(tune_ok.heartbeat, 30);

            let AMQPFrame::Method(0, AMQPClass::Connection(AMQPMethod::Open(open))) =
                read_frame(&mut sock).await.unwrap()
            else {
                panic!("expected Open");
            };
            assert_eq!(open.virtual_host.as_str(), "/my-vhost");

            write_frame(
                &mut sock,
                &AMQPFrame::Method(
                    0,
                    AMQPClass::Connection(AMQPMethod::OpenOk(connection::OpenOk {})),
                ),
            )
            .await
            .unwrap();
        });

        let options = TargetRabbitMqOptions {
            host: addr.ip().to_string(),
            port: addr.port(),
            username: "myuser".to_owned(),
            auth: RabbitMqTargetAuth::Password(DatabaseTargetPasswordAuth {
                password: StoredSecret::from("mypass".to_owned()),
            }),
            tls: Tls {
                mode: TlsMode::Disabled,
                verify: true,
            },
            default_vhost: None,
            idle_timeout: None,
        };

        RabbitMqClient::connect(&options, "/my-vhost")
            .await
            .expect("handshake should succeed");
        server.await.unwrap();
    }

    #[test]
    fn tune_negotiation_never_exceeds_the_targets_offer() {
        assert_eq!(
            negotiate_tune(&connection::Tune {
                channel_max: 100,
                frame_max: 4096,
                heartbeat: 30,
            }),
            (100, 4096, 30)
        );
        // 0 conventionally means "no limit" - fall back to our own values.
        assert_eq!(
            negotiate_tune(&connection::Tune {
                channel_max: 0,
                frame_max: 0,
                heartbeat: 0,
            }),
            (OUR_CHANNEL_MAX, OUR_FRAME_MAX, 0)
        );
    }
}
