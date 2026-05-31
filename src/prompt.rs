use std::io::{self, Write, BufRead, BufReader};
use std::fs::File;
use crossterm::{
    execute,
    style::{Color, Print, ResetColor, SetForegroundColor},
};

pub fn prompt_user_approval(action: &str) -> bool {
    let mut stderr = io::stderr();
    
    // Print a premium looking alert
    let _ = execute!(
        stderr,
        SetForegroundColor(Color::Yellow),
        Print("\n┌─── TALOS SECURITY GATEWAY ──────────────────────────────────────────\n"),
        Print("│ BY DYNE RESEARCH | https://dyneresearch.com\n"),
        Print("│\n"),
        Print("│ WARNING: AI is requesting permission to execute a suspicious action:\n"),
        Print(&format!("│ Action details: {}\n", action)),
        Print("└─────────────────────────────────────────────────────────────────────\n"),
        SetForegroundColor(Color::Cyan),
        Print("Allow this action? (y/N): "),
        ResetColor
    );
    let _ = stderr.flush();

    // When stdin is redirected, read directly from the console TTY device
    let mut input = String::new();
    let read_result = if cfg!(windows) {
        File::open("CONIN$").map(|f| BufReader::new(f).read_line(&mut input))
    } else {
        File::open("/dev/tty").map(|f| BufReader::new(f).read_line(&mut input))
    };

    match read_result {
        Ok(Ok(_)) => {
            let trimmed = input.trim().to_lowercase();
            trimmed == "y" || trimmed == "yes"
        }
        _ => false,
    }
}
