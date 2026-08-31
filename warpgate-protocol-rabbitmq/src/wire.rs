//! Byte-level AMQP 0-9-1 frame I/O, built on `amq-protocol`'s spec-generated
//! encoder/decoder (the same crate `lapin` uses internally). Only used during
//! the handshake, where Warpgate has to read/write specific Connection-class
//! methods; once a session is authorized and open, the two sides are relayed
//! as a blind byte stream (see `relay.rs`).

use amq_protocol::frame::{AMQPFrame, gen_frame, parse_frame};
use amq_protocol::types::{AMQPValue, FieldTable, LongString, ShortString};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::RabbitMqError;

/// Frames larger than this during the handshake are rejected outright rather
/// than trusted for an allocation - well above `OUR_FRAME_MAX`, since a real
/// client's `client-properties` table can be sizeable, but far below anything
/// a well-behaved peer would ever send before the connection is even tuned.
const MAX_HANDSHAKE_FRAME_SIZE: usize = 1024 * 1024;

pub async fn write_header<S: AsyncWrite + Unpin>(stream: &mut S) -> Result<(), RabbitMqError> {
    stream.write_all(&crate::common::PROTOCOL_HEADER).await?;
    Ok(())
}

pub async fn read_header<S: AsyncRead + Unpin>(stream: &mut S) -> Result<[u8; 8], RabbitMqError> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<AMQPFrame, RabbitMqError> {
    let mut header = [0u8; 7];
    if stream.read_exact(&mut header).await.is_err() {
        return Err(RabbitMqError::Eof);
    }
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    if size > MAX_HANDSHAKE_FRAME_SIZE {
        return Err(RabbitMqError::ProtocolError(format!(
            "frame too large ({size} bytes)"
        )));
    }

    let mut buf = vec![0u8; 7 + size + 1];
    buf[..7].copy_from_slice(&header);
    stream.read_exact(&mut buf[7..]).await?;

    match parse_frame(&buf[..]) {
        Ok((_, frame)) => Ok(frame),
        Err(error) => Err(RabbitMqError::ProtocolError(format!(
            "malformed AMQP frame: {error:?}"
        ))),
    }
}

pub async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    frame: &AMQPFrame,
) -> Result<(), RabbitMqError> {
    let bytes = cookie_factory::gen_simple(gen_frame(frame), Vec::new()).map_err(|error| {
        RabbitMqError::ProtocolError(format!("failed to encode AMQP frame: {error:?}"))
    })?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub fn long_string(s: &str) -> LongString {
    LongString::from(s.as_bytes().to_vec())
}

/// `server-properties`/`client-properties` table Warpgate identifies itself
/// with on both sides of the proxy.
pub fn peer_properties() -> FieldTable {
    let mut table = FieldTable::default();
    table.insert(
        ShortString::from("product"),
        AMQPValue::LongString(long_string("Warpgate")),
    );
    table.insert(
        ShortString::from("version"),
        AMQPValue::LongString(long_string(warpgate_common::version::warpgate_version())),
    );
    table
}
