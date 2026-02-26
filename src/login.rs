use anyhow::{Context, Result, bail};
use rand08::RngCore;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::api_client::{ApiClient, CliTokenExchangeResult};

const CADENCE_LOCKUP_INLINE_SVG: &str = include_str!("../assets/cadence-lockup-inline.svg");

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

    write_http_response(stream, 200, "OK", "You can close this tab")?;

    Ok(Some(code))
}

fn write_http_response(
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
        .context("failed to write callback response")?;
    stream
        .flush()
        .context("failed to flush callback response")?;
    Ok(())
}

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
}
