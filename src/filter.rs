use serde::{Deserialize, Serialize};
use regex::Regex;
use std::path::Path;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcErrorResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    pub error: JsonRpcError,
}

pub enum FilterDecision {
    Allow,
    Block(String),
}

pub struct SecurityFilter {
    blocked_commands: Vec<Regex>,
    sensitive_file_patterns: Vec<Regex>,
}

impl SecurityFilter {
    pub fn new() -> Self {
        // High-value dangerous commands, network tools, and obfuscation tricks (base64, hex)
        let blocked_commands = vec![
            Regex::new(r"(?i)\brm\s+-[rf]{1,2}\b").unwrap(),
            Regex::new(r"(?i)\bmkfs\b").unwrap(),
            Regex::new(r"(?i)\bdd\b").unwrap(),
            Regex::new(r"(?i)\bsh\b|\bbash\b|\bpowershell\b|\bcmd\b").unwrap(), // Direct shells
            Regex::new(r"(?i)curl\s+.*\|\s*(sh|bash)").unwrap(), // Piping curl
            Regex::new(r"(?i)\bbase64\s+-d\b|\bfrombase64string\b").unwrap(), // Base64 decode execution triggers
            Regex::new(r"(?i)\bbytes\.fromhex\b|\bexec\b.*\(.*fromhex").unwrap(), // Hex decode execution triggers
            Regex::new(r"(?i)\b(curl|wget|nc|nslookup|ping)\b.*(id_rsa|\.env|credentials|aws_access_key)").unwrap(), // Network exfiltration attempts
        ];

        // Sensitive target files/folders exfiltration risk
        let sensitive_file_patterns = vec![
            Regex::new(r"(?i)\.env").unwrap(),
            Regex::new(r"(?i)id_rsa|id_dsa|id_ed25519").unwrap(),
            Regex::new(r"(?i)\.git/config").unwrap(),
            Regex::new(r"(?i)aws/credentials").unwrap(),
            Regex::new(r"(?i)ssh/config").unwrap(),
        ];

        Self {
            blocked_commands,
            sensitive_file_patterns,
        }
    }

    pub fn inspect_request(&self, req: &JsonRpcRequest) -> FilterDecision {
        if req.method == "tools/call" || req.method == "callTool" {
            let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let arguments = req.params.get("arguments").cloned().unwrap_or(serde_json::Value::Null);

            // 1. Inspect command executions (tools like execute_command, run_command, bash, shell)
            if name.contains("command") || name.contains("execute") || name.contains("bash") || name.contains("run") {
                let cmd_str = arguments.get("command").and_then(|v| v.as_str())
                    .or_else(|| arguments.get("cmd").and_then(|v| v.as_str()))
                    .unwrap_or("");
                
                let args_str = arguments.get("args")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().map(|v| v.as_str().unwrap_or("")).collect::<Vec<&str>>().join(" "))
                    .unwrap_or_default();

                let full_cmd = format!("{} {}", cmd_str, args_str);

                for re in &self.blocked_commands {
                    if re.is_match(&full_cmd) {
                        return FilterDecision::Block(format!("Dangerous execution pattern matched rule: {}", re.as_str()));
                    }
                }
            }

            // 2. Inspect file reads, writes, and modifications (read_file, write_file, edit_file, etc.)
            if name.contains("file") || name.contains("read") || name.contains("write") || name.contains("patch") || name.contains("edit") {
                let path_str = arguments.get("path").and_then(|v| v.as_str())
                    .or_else(|| arguments.get("filename").and_then(|v| v.as_str()))
                    .unwrap_or("");

                // Prevent absolute path escapes outside current workspace directory using canonical paths
                let path = Path::new(path_str);
                if let Ok(canonical) = path.canonicalize() {
                    let canon_str = canonical.to_string_lossy();
                    if canon_str.contains(".ssh") || canon_str.contains(".aws") || canon_str.contains(".git/config") {
                        return FilterDecision::Block(format!("Resolved canonical path accesses sensitive directory: {}", canon_str));
                    }
                } else if path.is_absolute() {
                    // Fallback for paths that do not exist yet (like writing a new file)
                    if path_str.contains(".ssh") || path_str.contains(".aws") || path_str.contains("AppData") || path_str.contains(".git") {
                        return FilterDecision::Block(format!("Absolute path targets sensitive system directory: {}", path_str));
                    }
                }

                // Check directory rules against pattern blocklist
                for re in &self.sensitive_file_patterns {
                    if re.is_match(path_str) {
                        return FilterDecision::Block(format!("Attempt to access sensitive file matching rule: {}", re.as_str()));
                    }
                }

                // Scan content details for write operations containing malicious vectors (scripts, keys, base64 payloads)
                if name.contains("write") || name.contains("patch") || name.contains("edit") {
                    let content_str = arguments.get("content").and_then(|v| v.as_str())
                        .or_else(|| arguments.get("contents").and_then(|v| v.as_str()))
                        .or_else(|| arguments.get("text").and_then(|v| v.as_str()))
                        .unwrap_or("");

                    for re in &self.blocked_commands {
                        if re.is_match(content_str) {
                            return FilterDecision::Block(format!("File content contains blocked execution signature: {}", re.as_str()));
                        }
                    }
                }
            }
        }

        FilterDecision::Allow
    }

    pub fn make_error_response(&self, id: serde_json::Value, message: &str) -> String {
        let resp = JsonRpcErrorResponse {
            jsonrpc: "2.0".to_string(),
            id,
            error: JsonRpcError {
                code: -32602, // Invalid params or custom security violation code
                message: format!("[TALOS BLOCK] {}", message),
                data: None,
            },
        };
        serde_json::to_string(&resp).unwrap()
    }
}
