use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time;
use tracing::{error, info, warn};

use crate::error::RabbitMqError;

const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(10);

/// Map a configured `idle_timeout` string to an effective policy. An explicit
/// zero duration (`"0"`, `"0s"`) disables the timeout; an unset or unparseable
/// value falls back to [`DEFAULT_IDLE_TIMEOUT`].
pub fn parse_idle_timeout(value: Option<&str>) -> Option<Duration> {
    let Some(trimmed) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return Some(DEFAULT_IDLE_TIMEOUT);
    };
    match humantime::parse_duration(trimmed) {
        Ok(duration) if duration.is_zero() => None,
        Ok(duration) => Some(duration),
        Err(error) => {
            warn!(
                timeout_string = %trimmed,
                error = %error,
                "Invalid idle_timeout value, falling back to default"
            );
            Some(DEFAULT_IDLE_TIMEOUT)
        }
    }
}

/// Result of a relay session ending, so the caller can tell the client why
/// (only possible for the client side, since it's still speaking to us).
pub enum RelayEnd {
    Eof,
    IdleTimeout {
        elapsed: Duration,
        timeout: Duration,
    },
}

/// Blindly copies bytes between the client and the target once the AMQP
/// connection is open - channels, exchanges, queues, publishing and
/// consuming all flow through untouched, same as pub/sub and transactions do
/// for the Redis proxy's post-`AUTH` relay.
pub async fn relay<A, B>(
    client: &mut A,
    target: &mut B,
    idle_timeout: Option<Duration>,
) -> Result<RelayEnd, RabbitMqError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_buf = [0u8; 16 * 1024];
    let mut target_buf = [0u8; 16 * 1024];
    let mut last_activity = std::time::Instant::now();
    let check_interval = Duration::from_secs(5);

    loop {
        let select_timeout = match idle_timeout {
            Some(timeout) => {
                let elapsed = last_activity.elapsed();
                if elapsed > timeout {
                    info!(
                        idle_seconds = elapsed.as_secs(),
                        timeout_seconds = timeout.as_secs(),
                        "Session idle timeout exceeded, closing connection"
                    );
                    return Ok(RelayEnd::IdleTimeout { elapsed, timeout });
                }
                timeout.saturating_sub(elapsed).min(check_interval)
            }
            None => check_interval,
        };

        tokio::select! {
            c_to_t = time::timeout(select_timeout, client.read(&mut client_buf)) => {
                match c_to_t {
                    Ok(Ok(0)) => return Ok(RelayEnd::Eof),
                    Ok(Ok(n)) => {
                        last_activity = std::time::Instant::now();
                        target.write_all(&client_buf[..n]).await?;
                    }
                    Ok(Err(error)) => {
                        error!(%error, "Error relaying client -> target");
                        return Ok(RelayEnd::Eof);
                    }
                    Err(_) => {
                        // Timeout tick - loop back around to re-check idle timeout.
                    }
                }
            },
            t_to_c = time::timeout(select_timeout, target.read(&mut target_buf)) => {
                match t_to_c {
                    Ok(Ok(0)) => return Ok(RelayEnd::Eof),
                    Ok(Ok(n)) => {
                        last_activity = std::time::Instant::now();
                        client.write_all(&target_buf[..n]).await?;
                    }
                    Ok(Err(error)) => {
                        error!(%error, "Error relaying target -> client");
                        return Ok(RelayEnd::Eof);
                    }
                    Err(_) => {}
                }
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{DEFAULT_IDLE_TIMEOUT, parse_idle_timeout};

    #[test]
    fn explicit_zero_disables() {
        assert_eq!(parse_idle_timeout(Some("0")), None);
        assert_eq!(parse_idle_timeout(Some("0s")), None);
    }

    #[test]
    fn valid_duration_is_used() {
        assert_eq!(
            parse_idle_timeout(Some("30m")),
            Some(Duration::from_secs(30 * 60))
        );
    }

    #[test]
    fn unset_or_unparseable_uses_default() {
        assert_eq!(parse_idle_timeout(None), Some(DEFAULT_IDLE_TIMEOUT));
        assert_eq!(
            parse_idle_timeout(Some("garbage")),
            Some(DEFAULT_IDLE_TIMEOUT)
        );
    }
}
