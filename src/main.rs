use std::env;
use std::process::Stdio;
use tokio::io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command as TokioCommand;

mod filter;
mod prompt;
#[cfg(test)]
mod tests;

use filter::{FilterDecision, JsonRpcRequest, SecurityFilter};

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    // Usage: talos <target-command> [target-args...]
    if args.len() < 2 {
        eprintln!("Usage: talos <mcp-server-command> [mcp-server-args...]");
        std::process::exit(1);
    }

    let target_cmd = &args[1];
    let target_args = &args[2..];

    // Spawn the underlying MCP server process with standard pipes
    let mut child = TokioCommand::new(target_cmd)
        .args(target_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // Forward stderr directly for server logs/diagnostic info
        .spawn()?;

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    let filter = SecurityFilter::new();

    // Task 1: Proxy stdin (client -> talos -> target server)
    // We parse and check streaming JSON-RPC objects here to handle multi-line formatting or packet fragments.
    tokio::spawn(async move {
        let stdin = io::stdin();
        // Standard blocking wrapper to feed the stream parser safely
        let mut reader = BufReader::new(stdin);
        let mut buffer = Vec::new();

        loop {
            let mut chunk = vec![0; 4096];
            let n = match reader.read(&mut chunk).await {
                Ok(0) => break, // EOF
                Ok(n) => n,
                Err(_) => break,
            };

            buffer.extend_from_slice(&chunk[..n]);

            // Attempt to parse complete JSON objects out of the stream buffer
            let mut cursor = 0;
            let mut stream = serde_json::Deserializer::from_slice(&buffer).into_iter::<serde_json::Value>();

            while let Some(result) = stream.next() {
                let parsed_len = stream.byte_offset();
                let val = match result {
                    Ok(v) => v,
                    Err(_) => {
                        // Incomplete or invalid JSON, wait for more data
                        break;
                    }
                };

                // Extract substring corresponding to this parsed JSON object
                let raw_json_bytes = &buffer[cursor..parsed_len];
                let raw_json_str = String::from_utf8_lossy(raw_json_bytes).to_string();

                // Check if it is a JSON-RPC request and filter it
                if let Ok(req) = serde_json::from_value::<JsonRpcRequest>(val) {
                    match filter.inspect_request(&req) {
                        FilterDecision::Allow => {
                            let _ = child_stdin.write_all(raw_json_str.as_bytes()).await;
                            let _ = child_stdin.write_all(b"\n").await;
                            let _ = child_stdin.flush().await;
                        }
                        FilterDecision::Block(reason) => {
                            eprintln!("\x1b[33m[Talos Intercepted]: {}\x1b[0m", reason);

                            if prompt::prompt_user_approval(&reason) {
                                let _ = child_stdin.write_all(raw_json_str.as_bytes()).await;
                                let _ = child_stdin.write_all(b"\n").await;
                                let _ = child_stdin.flush().await;
                            } else {
                                let err_resp = filter.make_error_response(req.id, &reason);
                                let mut stdout = io::stdout();
                                let _ = stdout.write_all(format!("{}\n", err_resp).as_bytes()).await;
                                let _ = stdout.flush().await;
                            }
                        }
                    }
                } else {
                    // Forward directly if not matching a security inspected request structure
                    let _ = child_stdin.write_all(raw_json_bytes).await;
                    let _ = child_stdin.flush().await;
                }

                cursor = parsed_len;
            }

            // Drain processed bytes from the buffer
            if cursor > 0 {
                buffer.drain(..cursor);
            }
        }
    });

    // Task 2: Proxy stdout (target server -> talos -> client)
    let mut child_reader = BufReader::new(child_stdout);
    let mut child_line = String::new();
    let mut parent_stdout = io::stdout();

    while let Ok(n) = child_reader.read_line(&mut child_line).await {
        if n == 0 {
            break; // EOF
        }

        // Just pass all server responses back to client stdout
        parent_stdout.write_all(child_line.as_bytes()).await?;
        parent_stdout.flush().await?;
        child_line.clear();
    }

    // Wait for the wrapped subprocess to finish
    let _ = child.wait().await;

    Ok(())
}
