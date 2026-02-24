use anyhow::{Context, Result, bail};
use rand08::RngCore;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::api_client::{ApiClient, CliTokenExchangeResult};

/// Complete browser-based CLI OAuth login flow.
pub fn login_via_browser(api_base_url: &str, timeout: Duration) -> Result<CliTokenExchangeResult> {
    let nonce = generate_nonce();

    let listener =
        TcpListener::bind("127.0.0.1:0").context("failed to bind local callback port")?;
    listener
        .set_nonblocking(true)
        .context("failed to configure callback listener")?;

    let local_port = listener
        .local_addr()
        .context("failed to read local callback address")?
        .port();

    let auth_url = format!(
        "{}/auth/token?port={}&state={}",
        api_base_url.trim_end_matches('/'),
        local_port,
        nonce
    );

    open::that(&auth_url).with_context(|| {
        format!("failed to open browser. Open this URL manually to continue login: {auth_url}")
    })?;

    let deadline = Instant::now() + timeout;
    let exchange_code = wait_for_exchange_code(&listener, &nonce, deadline)?;

    let client = ApiClient::new(api_base_url);
    client
        .exchange_cli_code(&exchange_code, Duration::from_secs(10))
        .context("failed to exchange login code for CLI token")
}

fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand08::thread_rng().fill_bytes(&mut bytes);
    bytes_to_hex(&bytes)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

fn wait_for_exchange_code(
    listener: &TcpListener,
    expected_state: &str,
    deadline: Instant,
) -> Result<String> {
    loop {
        if Instant::now() >= deadline {
            bail!("login timed out waiting for browser callback");
        }

        match listener.accept() {
            Ok((mut stream, _addr)) => {
                if let Some(code) = handle_callback_request(&mut stream, expected_state)? {
                    return Ok(code);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e).context("failed while waiting for browser callback"),
        }
    }
}

fn handle_callback_request(stream: &mut TcpStream, expected_state: &str) -> Result<Option<String>> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .context("failed to set callback read timeout")?;

    let mut buffer = [0u8; 8192];
    let n = stream
        .read(&mut buffer)
        .context("failed to read callback request")?;
    if n == 0 {
        return Ok(None);
    }

    let request = String::from_utf8_lossy(&buffer[..n]);
    let mut lines = request.lines();
    let first_line = match lines.next() {
        Some(line) => line,
        None => return Ok(None),
    };

    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();

    if method != "GET" {
        write_http_response(
            stream,
            405,
            "Method Not Allowed",
            "Only GET callbacks are supported.",
        )?;
        return Ok(None);
    }

    if !target.starts_with("/callback") {
        write_http_response(stream, 404, "Not Found", "Not a Cadence callback URL.")?;
        return Ok(None);
    }

    let url = reqwest::Url::parse(&format!("http://127.0.0.1{target}"))
        .context("failed to parse callback URL")?;

    let code = url
        .query_pairs()
        .find_map(|(k, v)| {
            if k == "code" {
                Some(v.into_owned())
            } else {
                None
            }
        })
        .unwrap_or_default();

    let returned_state = url
        .query_pairs()
        .find_map(|(k, v)| {
            if k == "state" {
                Some(v.into_owned())
            } else {
                None
            }
        })
        .unwrap_or_default();

    if code.is_empty() {
        write_http_response(
            stream,
            400,
            "Bad Request",
            "Missing exchange code in callback.",
        )?;
        return Ok(None);
    }

    if returned_state != expected_state {
        write_http_response(
            stream,
            400,
            "Bad Request",
            "State mismatch. Please retry `cadence login`.",
        )?;
        return Ok(None);
    }

    write_http_response(
        stream,
        200,
        "OK",
        "Authentication complete. You can close this tab.",
    )?;

    Ok(Some(code))
}

fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    body_text: &str,
) -> Result<()> {
    let html = format!(
        "<!doctype html><html><body style=\"font-family:system-ui; padding:24px\"><h2>{body_text}</h2></body></html>"
    );
    let response = format!(
        "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    stream
        .write_all(response.as_bytes())
        .context("failed to write callback response")?;
    stream
        .flush()
        .context("failed to flush callback response")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_32_hex_chars() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hex_encoder_round_trip_length() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "deadbeef");
    }
}
