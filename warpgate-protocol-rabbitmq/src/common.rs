use warpgate_common::Protocol;

pub const PROTOCOL_NAME: Protocol = Protocol::RabbitMq;

/// AMQP 0-9-1 protocol header clients open a connection with.
pub const PROTOCOL_HEADER: [u8; 8] = *b"AMQP\x00\x00\x09\x01";

/// Tune values Warpgate offers to the client. They're fixed rather than
/// negotiated with the target up front, since the target isn't known (nor
/// dialed) until after the client's credentials arrive - these match
/// RabbitMQ's own defaults so proxying to a real RabbitMQ broker negotiates
/// identically.
pub const OUR_CHANNEL_MAX: u16 = 2047;
pub const OUR_FRAME_MAX: u32 = 131_072;
pub const OUR_HEARTBEAT: u16 = 60;
