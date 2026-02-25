// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! PID file management for stop/restart/status commands.

use std::io;

/// Write the current process ID to a file.
pub fn write_pid(path: &str) -> io::Result<()> {
    std::fs::write(path, std::process::id().to_string())
}

/// Read a PID from file. Returns `None` if the file does not exist.
pub fn read_pid(path: &str) -> io::Result<Option<u32>> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s.trim().parse().ok()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Remove the PID file. No error if it doesn't exist.
pub fn remove_pid(path: &str) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Check whether a process with the given PID is currently running.
pub fn is_running(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Stop a running node by reading its PID file, sending SIGTERM, and waiting.
///
/// Falls back to SIGKILL after 30 seconds. Removes the PID file on success.
pub fn stop_node(pid_file: &str) {
    match read_pid(pid_file) {
        Ok(Some(pid)) => {
            if !is_running(pid) {
                eprintln!("Process {pid} is not running. Removing stale PID file.");
                let _ = remove_pid(pid_file);
                return;
            }

            eprintln!("Sending SIGTERM to PID {pid}...");
            let _ = std::process::Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            // Wait up to 30 seconds for graceful shutdown
            for i in 0..30 {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if !is_running(pid) {
                    eprintln!("Node stopped after {}s.", i + 1);
                    let _ = remove_pid(pid_file);
                    return;
                }
            }

            eprintln!("Process did not exit after 30s. Sending SIGKILL...");
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            let _ = remove_pid(pid_file);
        }
        Ok(None) => {
            eprintln!("No PID file found at {pid_file}. Node may not be running.");
        }
        Err(e) => {
            eprintln!("Failed to read PID file: {e}");
            std::process::exit(1);
        }
    }
}
