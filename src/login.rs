//! Browser-based login flow for exchanging a short-lived code into a CLI token.

use anyhow::{Context, Result, bail};
use rand08::RngCore;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::api_client::{ApiClient, CliTokenExchangeResult};
use crate::output;

const CADENCE_LOCKUP_INLINE_SVG: &str = include_str!("../assets/cadence-lockup-inline.svg");

/// Complete browser-based CLI OAuth login flow.
/// Completes the browser login flow and returns the exchanged CLI token data.
pub async fn login_via_browser(
    api_base_url: &str,
    timeout: Duration,
) -> Result<CliTokenExchangeResult> {
    let nonce = generate_nonce();
    let client = ApiClient::new(api_base_url).await?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind local callback port")?;
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

    output::detail(&format!("Open this URL manually if needed: {auth_url}"));
    open::that(&auth_url).with_context(|| {
        format!("failed to open browser. Open this URL manually to continue login: {auth_url}")
    })?;

    let deadline = Instant::now() + timeout;
    let exchange_code = wait_for_exchange_code(&listener, &nonce, deadline).await?;

    client
        .exchange_cli_code(&exchange_code, Duration::from_secs(10))
        .await
        .context("failed to exchange login code for CLI token")
}

/// Generates a random nonce used to validate the OAuth callback.
fn generate_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand08::thread_rng().fill_bytes(&mut bytes);
    bytes_to_hex(&bytes)
}

/// Encodes raw bytes as lowercase hexadecimal.
fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Starts the local callback server and waits for a valid exchange code.
async fn wait_for_exchange_code(
    listener: &TcpListener,
    expected_state: &str,
    deadline: Instant,
) -> Result<String> {
    loop {
        if Instant::now() >= deadline {
            bail!("login timed out waiting for browser callback");
        }

        match tokio::time::timeout(Duration::from_millis(250), listener.accept()).await {
            Ok(Ok((mut stream, _addr))) => {
                if let Some(code) = handle_callback_request(&mut stream, expected_state).await? {
                    return Ok(code);
                }
            }
            Ok(Err(e)) => return Err(e).context("failed while waiting for browser callback"),
            Err(_) => continue,
        }
    }
}

/// Handles one HTTP callback request from the browser-based login flow.
async fn handle_callback_request(
    stream: &mut TcpStream,
    expected_state: &str,
) -> Result<Option<String>> {
    let mut buffer = [0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buffer))
        .await
        .context("timed out reading callback request")?
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
        )
        .await?;
        return Ok(None);
    }

    if !target.starts_with("/callback") {
        write_http_response(stream, 404, "Not Found", "Not a Cadence callback URL.").await?;
        return Ok(None);
    }

    let code = callback_query_param(target, "code").unwrap_or_default();
    let returned_state = callback_query_param(target, "state").unwrap_or_default();

    if code.is_empty() {
        write_http_response(
            stream,
            400,
            "Bad Request",
            "Missing exchange code in callback.",
        )
        .await?;
        return Ok(None);
    }

    if returned_state != expected_state {
        write_http_response(
            stream,
            400,
            "Bad Request",
            "State mismatch. Please retry `cadence login`.",
        )
        .await?;
        return Ok(None);
    }

    write_http_response(stream, 200, "OK", "You can close this tab").await?;

    Ok(Some(code))
}

/// Writes a complete HTTP response to the callback socket.
async fn write_http_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    body_text: &str,
) -> Result<()> {
    let html = render_callback_html(status_code, body_text);
    let response = format!(
        "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("failed to write callback response")?;
    stream
        .flush()
        .await
        .context("failed to flush callback response")?;
    Ok(())
}

/// Renders the HTML shown in the browser after login completes or fails.
fn render_callback_html(status_code: u16, body_text: &str) -> String {
    let is_success = (200..300).contains(&status_code);
    let title = if is_success {
        "Authentication Complete"
    } else {
        "Authentication Failed"
    };
    let escaped_body = escape_html(body_text);
    let escaped_title = escape_html(title);
    let brand_svg = CADENCE_LOCKUP_INLINE_SVG;

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escaped_title}</title>
<style>
* {{ box-sizing: border-box; }}
html, body {{ height: 100%; margin: 0; }}
body {{
  font-family: 'Work Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  color: #e2e8f0;
  background:
    radial-gradient(1200px 640px at 8% -5%, rgba(99, 102, 241, 0.26) 0%, rgba(99, 102, 241, 0) 58%),
    radial-gradient(720px 460px at 92% 110%, rgba(30, 64, 175, 0.2) 0%, rgba(30, 64, 175, 0) 62%),
    linear-gradient(180deg, #070b14 0%, #0b1020 100%);
}}
.wrap {{
  min-height: 100%;
  display: grid;
  place-items: center;
  padding: 32px;
}}
.card {{
  position: relative;
  overflow: hidden;
  width: min(640px, 100%);
  text-align: left;
  background: linear-gradient(180deg, rgba(15, 23, 42, 0.9) 0%, rgba(10, 15, 30, 0.92) 100%);
  border: 1px solid rgba(148, 163, 184, 0.28);
  border-radius: 24px;
  box-shadow: 0 30px 72px rgba(2, 6, 23, 0.55);
  padding: 58px 52px 56px;
}}
.card::before {{
  content: "";
  position: absolute;
  inset: 0 0 auto;
  height: 7px;
  background: linear-gradient(90deg, #1A1363 0%, #4f46e5 52%, #1e40af 100%);
}}
.brand {{
  margin: 0 0 14px;
  display: flex;
  justify-content: flex-start;
}}
.brand-logo {{
  display: block;
  height: 66px;
  width: auto;
  max-width: 300px;
  color: #ffffff;
}}
.brand-logo path {{
  fill: #ffffff;
}}
.content {{
  max-width: 40ch;
  padding-left: 12px;
}}
h1 {{
  margin: 0 0 14px;
  font-size: 30px;
  line-height: 1.14;
  letter-spacing: -0.015em;
  color: #f8fafc;
}}
p {{
  margin: 0;
  font-size: 18px;
  line-height: 1.5;
  color: #cbd5e1;
}}
@media (max-width: 600px) {{
  .wrap {{
    padding: 20px;
  }}
  .card {{
    border-radius: 20px;
    padding: 44px 24px 40px;
  }}
  .brand-logo {{
    height: 54px;
    max-width: 250px;
  }}
  .content {{
    padding-left: 8px;
  }}
  h1 {{
    font-size: 24px;
  }}
  p {{
    font-size: 16px;
  }}
}}
</style>
</head>
<body>
<div class="wrap">
<main class="card">
<div class="brand" aria-label="Cadence">
{brand_svg}
</div>
<div class="content">
<h1>{escaped_title}</h1>
<p>{escaped_body}</p>
</div>
</main>
</div>
</body>
</html>"#
    )
}

fn callback_query_param(target: &str, key: &str) -> Option<String> {
    let (_, query) = target.split_once('?')?;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if decode_callback_component(raw_key) == key {
            return Some(decode_callback_component(raw_value));
        }
    }
    None
}

fn decode_callback_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(high), Some(low)) = (from_hex(bytes[i + 1]), from_hex(bytes[i + 2]))
        {
            out.push((high << 4) | low);
            i += 3;
            continue;
        }

        // Preserve literal '+' to avoid corrupting auth codes when the upstream
        // callback URL is not form-encoded.
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Escapes user-visible text for safe inclusion in callback HTML.
fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
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

    #[test]
    fn callback_html_success_variant_is_styled() {
        let html = render_callback_html(200, "You can close this tab");
        assert!(html.contains("Authentication Complete"));
        assert!(!html.contains(">OK<"));
        assert!(html.contains("Work Sans"));
        assert!(html.contains("class=\"brand-logo\""));
        assert!(html.contains("viewBox=\"0 0 770 300\""));
        assert!(html.contains("fill=\"currentColor\""));
        assert!(!html.contains("You can close this tab and return to your terminal."));
    }

    #[test]
    fn callback_html_error_variant_is_styled() {
        let html = render_callback_html(400, "State mismatch. Please retry cadence login.");
        assert!(html.contains("Authentication Failed"));
        assert!(!html.contains(">ERR<"));
        assert!(!html.contains("run cadence login again"));
    }

    #[test]
    fn callback_html_escapes_message_content() {
        let html = render_callback_html(400, "<script>alert('xss')</script>");
        assert!(html.contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"));
        assert!(!html.contains("<script>alert('xss')</script>"));
    }

    #[test]
    fn callback_query_param_preserves_literal_plus_in_exchange_code() {
        let target = "/callback?code=a+b%2Bc&state=state123";

        assert_eq!(
            callback_query_param(target, "code"),
            Some("a+b+c".to_string())
        );
    }

    #[test]
    fn callback_query_param_decodes_percent_escapes() {
        let target = "/callback?state=hello%20world&code=abc123";

        assert_eq!(
            callback_query_param(target, "state"),
            Some("hello world".to_string())
        );
    }
}
