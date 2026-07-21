/// MCP Stdio Transport Layer
///
/// Implements the Model Context Protocol (MCP) standard stdio framing:
/// - Headers: `Header: value\r\n...Header: value\r\n\r\n`
/// - Body: exactly N bytes of JSON, where N is specified by `Content-Length` header
///
/// Reference: <https://spec.modelcontextprotocol.io/2024-11-05/basic/transports/#stdio-transport>
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::{debug, warn};

pub const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024; // 100 MB

/// Maximum length of a single header line (name + ": " + value + "\r\n").
const MAX_HEADER_LINE_BYTES: usize = 8192;

/// Maximum number of headers per message to prevent header-bombing.
const MAX_HEADER_COUNT: usize = 64;

/// Environment variable that enables verbose stdio framing diagnostics.
const STDIN_TRACE_ENV: &str = "NEXUS_MCP_STDIN_TRACE";

/// MCP transport backed by a `BufReader<R>`.
///
/// `BufReader` maintains an internal byte buffer that survives across calls to
/// `read_message`. Any bytes of a subsequent message that arrive in the same
/// kernel `read()` as the current message body are retained in that buffer and
/// consumed correctly on the next call — eliminating the silent data-loss that
/// a bare `AsyncRead` implementation would suffer when messages are pipelined.
pub struct McpTransport<R, W> {
    reader: BufReader<R>,
    writer: W,
    line_delimited_json_mode: bool,
}

impl<R, W> McpTransport<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            line_delimited_json_mode: false,
        }
    }

    /// Reads one MCP message using HTTP-style framing (Content-Length header).
    ///
    /// Headers are read line-by-line via `BufReader::read_line`; the body is
    /// consumed with `read_exact`. Because `BufReader` preserves its internal
    /// buffer between invocations, pipelined messages are never lost.
    ///
    /// Returns `None` on a clean EOF before any data, `Some(message)` on
    /// success, or an error on protocol violation.
    pub async fn read_message(&mut self) -> Result<Option<Value>> {
        if self.line_delimited_json_mode {
            return self.read_message_line_delimited().await;
        }

        let trace_enabled = stdin_trace_enabled();
        if trace_enabled {
            warn!("MCP stdin trace enabled: waiting for header lines (expecting Content-Length framing)");
        }

        let Some(headers) = self.read_headers(trace_enabled).await? else {
            return Ok(None);
        };

        if let Some(msg_str) = headers.get("x-compat-json-message") {
            let msg = serde_json::from_str::<Value>(msg_str)
                .map_err(|e| anyhow!("JSON parse error (line-delimited mode): {e}"))?;
            return Ok(Some(msg));
        }

        let content_length = extract_content_length(&headers)?;
        if trace_enabled {
            warn!(headers = ?headers, content_length, "MCP stdin trace: parsed headers");
        }

        validate_content_length(content_length)?;
        let msg = self.read_body(content_length, trace_enabled).await?;

        debug!("Message received via MCP transport");
        Ok(Some(msg))
    }

    /// Reads exactly `content_length` bytes from the buffered reader and
    /// parses the result as JSON.
    ///
    /// `BufReader` drains its internal buffer first, so pipelined messages are
    /// never lost.
    async fn read_body(&mut self, content_length: usize, trace_enabled: bool) -> Result<Value> {
        let mut body = vec![0u8; content_length];
        self.reader.read_exact(&mut body).await.map_err(|e| {
            anyhow!("EOF while reading body (expected {content_length} bytes): {e}")
        })?;

        if trace_enabled {
            let preview_len = body.len().min(256);
            let preview = String::from_utf8_lossy(&body[..preview_len]).to_string();
            warn!(body_bytes = body.len(), preview = %preview, "MCP stdin trace: body received");
        }

        serde_json::from_slice(&body).map_err(|e| anyhow!("JSON parse error: {e}"))
    }

    async fn read_headers(
        &mut self,
        trace_enabled: bool,
    ) -> Result<Option<HashMap<String, String>>> {
        let mut headers: HashMap<String, String> = HashMap::new();
        let mut saw_first_line = false;

        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;

            if n == 0 {
                // EOF
                if !saw_first_line {
                    if trace_enabled {
                        warn!("MCP stdin trace: EOF before first header line");
                    }
                    return Ok(None); // clean shutdown — no data was in flight
                }
                return Err(anyhow!("EOF while reading headers"));
            }

            if trace_enabled {
                let escaped = line.replace('\r', "\\r").replace('\n', "\\n");
                warn!(bytes = n, line = %escaped, "MCP stdin trace: header chunk");
            }

            if line.len() > MAX_HEADER_LINE_BYTES {
                return Err(anyhow!(
                    "Header line exceeds maximum size ({MAX_HEADER_LINE_BYTES} bytes)"
                ));
            }

            let is_first_header_line = !saw_first_line;
            saw_first_line = true;

            // Strip the line terminator (\r\n or bare \n).
            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');

            // Compatibility mode: some clients send one JSON-RPC message per
            // line instead of MCP Content-Length framing. If the first line
            // looks like JSON, parse and return it immediately.
            if is_first_header_line && looks_like_json(trimmed) {
                self.line_delimited_json_mode = true;

                if trace_enabled {
                    warn!("MCP stdin trace: detected line-delimited JSON message (no Content-Length header)");
                }

                let mut compat_headers = HashMap::new();
                compat_headers.insert("x-compat-json-message".to_string(), trimmed.to_string());
                return Ok(Some(compat_headers));
            }

            // Empty line signals the end of the header block.
            if trimmed.is_empty() {
                break;
            }

            if headers.len() >= MAX_HEADER_COUNT {
                return Err(anyhow!("Too many headers (max {MAX_HEADER_COUNT})"));
            }

            Self::parse_header_line(trimmed, &mut headers)?;
        }

        if headers.is_empty() {
            return Err(anyhow!("Received empty header block"));
        }

        Ok(Some(headers))
    }

    fn parse_header_line(trimmed: &str, headers: &mut HashMap<String, String>) -> Result<()> {
        let (name, value) = trimmed
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid header format: {trimmed}"))?;

        let name_lower = name.trim().to_lowercase();
        let value_trimmed = value.trim().to_string();

        if headers.contains_key(&name_lower) {
            warn!(header = %name_lower, "Duplicate header received");
            return Err(anyhow!("Duplicate header: {}", name.trim()));
        }

        headers.insert(name_lower, value_trimmed);
        Ok(())
    }

    /// Serializes a JSON message and sends it with MCP stdio framing.
    pub async fn write_message<T: serde::Serialize>(&mut self, msg: &T) -> Result<()> {
        if self.line_delimited_json_mode {
            let serialized = serde_json::to_vec(msg)?;
            self.writer.write_all(&serialized).await?;
            self.writer.write_all(b"\n").await?;
            self.writer.flush().await?;

            debug!(
                size = serialized.len(),
                "Message sent via line-delimited JSON mode"
            );
            return Ok(());
        }

        let serialized = serde_json::to_vec(msg)?;
        let length = serialized.len();

        let header = format!("Content-Length: {length}\r\n\r\n");

        self.writer.write_all(header.as_bytes()).await?;
        self.writer.write_all(&serialized).await?;
        self.writer.flush().await?;

        debug!(size = length, "Message sent via MCP transport");
        Ok(())
    }
}

impl<R, W> McpTransport<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    async fn read_message_line_delimited(&mut self) -> Result<Option<Value>> {
        let trace_enabled = stdin_trace_enabled();

        loop {
            let mut line = String::new();
            let n = self.reader.read_line(&mut line).await?;

            if n == 0 {
                if trace_enabled {
                    warn!("MCP stdin trace: EOF in line-delimited JSON mode");
                }
                return Ok(None);
            }

            if trace_enabled {
                let escaped = line.replace('\r', "\\r").replace('\n', "\\n");
                warn!(bytes = n, line = %escaped, "MCP stdin trace: line-delimited chunk");
            }

            let trimmed = line.trim_end_matches('\n').trim_end_matches('\r').trim();
            if trimmed.is_empty() {
                continue;
            }

            let msg = serde_json::from_str::<Value>(trimmed)
                .map_err(|e| anyhow!("JSON parse error (line-delimited mode): {e}"))?;
            return Ok(Some(msg));
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn extract_content_length(headers: &HashMap<String, String>) -> Result<usize> {
    let value = headers
        .get("content-length")
        .ok_or_else(|| anyhow!("Missing Content-Length header"))?;

    value
        .parse::<usize>()
        .map_err(|_| anyhow!("Content-Length is not a valid number: {value}"))
}

/// Rejects a `Content-Length` value that would produce an empty or
/// oversized allocation before any I/O is attempted.
fn validate_content_length(content_length: usize) -> Result<()> {
    if content_length == 0 {
        return Err(anyhow!("Content-Length must be greater than 0"));
    }
    if content_length > MAX_MESSAGE_SIZE {
        return Err(anyhow!(
            "Content-Length exceeds maximum: {content_length} > {MAX_MESSAGE_SIZE}"
        ));
    }
    Ok(())
}

fn stdin_trace_enabled() -> bool {
    env::var(STDIN_TRACE_ENV).is_ok_and(|v| {
        let v = v.trim();
        v.eq_ignore_ascii_case("1")
            || v.eq_ignore_ascii_case("true")
            || v.eq_ignore_ascii_case("yes")
            || v.eq_ignore_ascii_case("on")
    })
}

fn looks_like_json(s: &str) -> bool {
    let s = s.trim_start();
    s.starts_with('{') || s.starts_with('[')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;

    fn make_frame(body: &str) -> Vec<u8> {
        let mut frame = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        frame.extend_from_slice(body.as_bytes());
        frame
    }

    // -----------------------------------------------------------------------
    // Pipelining — the core correctness tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_single_message() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#;
        let mut transport = McpTransport::new(Cursor::new(make_frame(body)), Vec::new());
        let msg = transport.read_message().await.unwrap().unwrap();
        assert_eq!(msg["id"], 1);
        assert_eq!(msg["method"], "ping");
    }

    #[tokio::test]
    async fn test_two_pipelined_messages_no_data_loss() {
        let body1 = r#"{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}"#;
        let body2 = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;

        let mut input = make_frame(body1);
        input.extend_from_slice(&make_frame(body2));

        let mut transport = McpTransport::new(Cursor::new(input), Vec::new());

        let msg1 = transport.read_message().await.unwrap().unwrap();
        assert_eq!(msg1["id"], 1, "First message id mismatch");

        let msg2 = transport.read_message().await.unwrap().unwrap();
        assert_eq!(msg2["id"], 2, "Second message lost — pipelining is broken");
        assert_eq!(msg2["method"], "tools/list");
    }

    #[tokio::test]
    async fn test_three_pipelined_messages() {
        let mut input = Vec::new();
        for i in 1u64..=3 {
            let body = format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"ping","params":{{}}}}"#);
            input.extend_from_slice(&make_frame(&body));
        }

        let mut transport = McpTransport::new(Cursor::new(input), Vec::new());
        for expected_id in 1u64..=3 {
            let msg = transport
                .read_message()
                .await
                .expect("read_message should not fail");
            assert!(msg.is_some(), "Expected message {expected_id} but got EOF");
            let msg = msg.unwrap();
            assert_eq!(
                msg["id"], expected_id,
                "Message {expected_id} id mismatch (pipelining broken)"
            );
        }
    }

    // -----------------------------------------------------------------------
    // EOF behaviour
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_clean_eof_returns_none() {
        let mut transport = McpTransport::new(Cursor::new(Vec::new()), Vec::new());
        let result = transport.read_message().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_line_delimited_json_message_supported() {
        let input =
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n".to_vec();
        let mut transport = McpTransport::new(Cursor::new(input), Vec::new());
        let msg = transport.read_message().await.unwrap().unwrap();
        assert_eq!(msg["id"], 1);
        assert_eq!(msg["method"], "initialize");
    }

    #[tokio::test]
    async fn test_line_delimited_mode_roundtrip_after_detection() {
        let input =
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n".to_vec();
        let mut output = Vec::new();
        let mut transport = McpTransport::new(Cursor::new(input), &mut output);

        let _ = transport.read_message().await.unwrap().unwrap();
        let response = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}});
        transport.write_message(&response).await.unwrap();

        let out = String::from_utf8(output).unwrap();
        assert!(out.starts_with('{'));
        assert!(out.ends_with('\n'));
        assert!(!out.starts_with("Content-Length:"));
    }

    // -----------------------------------------------------------------------
    // Header validation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_missing_content_length() {
        let input = b"Other-Header: value\r\n\r\n{\"id\":1}".to_vec();
        let mut transport = McpTransport::new(Cursor::new(input), Vec::new());
        let err = transport.read_message().await.unwrap_err();
        assert!(err.to_string().contains("Missing Content-Length"));
    }

    #[tokio::test]
    async fn test_duplicate_header_rejected() {
        let input = b"Content-Length: 10\r\nContent-Length: 20\r\n\r\n".to_vec();
        let mut transport = McpTransport::new(Cursor::new(input), Vec::new());
        let err = transport.read_message().await.unwrap_err();
        assert!(err.to_string().contains("Duplicate"));
    }

    #[tokio::test]
    async fn test_content_length_too_large() {
        let huge = MAX_MESSAGE_SIZE + 1;
        let input = format!("Content-Length: {huge}\r\n\r\n").into_bytes();
        let mut transport = McpTransport::new(Cursor::new(input), Vec::new());
        let err = transport.read_message().await.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"));
    }

    #[tokio::test]
    async fn test_invalid_content_length() {
        let input = b"Content-Length: abc\r\n\r\n".to_vec();
        let mut transport = McpTransport::new(Cursor::new(input), Vec::new());
        let err = transport.read_message().await.unwrap_err();
        assert!(err.to_string().contains("not a valid number"));
    }

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_write_message_framing() {
        let msg = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{}});
        let mut output = Vec::new();
        let mut transport = McpTransport::new(Cursor::new(Vec::new()), &mut output);
        transport.write_message(&msg).await.unwrap();

        let out = String::from_utf8(output).unwrap();
        assert!(
            out.starts_with("Content-Length:"),
            "Missing Content-Length header"
        );
        assert!(out.contains("\r\n\r\n"), "Missing header terminator");
        assert!(out.contains(r#""id":1"#), "Body missing from output");
    }

    #[tokio::test]
    async fn test_roundtrip_write_then_read() {
        let original = serde_json::json!({"jsonrpc":"2.0","id":42,"method":"ping","params":{}});

        // Write into a buffer
        let mut buf = Vec::new();
        let mut writer_transport = McpTransport::new(Cursor::new(Vec::new()), &mut buf);
        writer_transport.write_message(&original).await.unwrap();

        // Read back from that buffer
        let mut reader_transport = McpTransport::new(Cursor::new(buf), Vec::new());
        let received = reader_transport.read_message().await.unwrap().unwrap();
        assert_eq!(received, original);
    }

    // -----------------------------------------------------------------------
    // extract_content_length unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_content_length() {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "42".to_string());
        assert_eq!(extract_content_length(&headers).unwrap(), 42);
    }

    #[test]
    fn test_extract_content_length_missing() {
        let result = extract_content_length(&HashMap::new());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing Content-Length"));
    }

    #[test]
    fn test_extract_content_length_invalid() {
        let mut headers = HashMap::new();
        headers.insert("content-length".to_string(), "not_a_number".to_string());
        let result = extract_content_length(&headers);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not a valid number"));
    }
}
