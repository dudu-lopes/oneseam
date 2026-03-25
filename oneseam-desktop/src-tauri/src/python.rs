use std::{
    fs::{self, OpenOptions},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use tauri::{path::BaseDirectory, AppHandle, Manager};

const HEALTH_URL: &str = "http://localhost:8000/health";
const HEALTH_TIMEOUT_SECS: u64 = 30;
const HEALTH_POLL_MS: u64 = 500;
const DEFAULT_API_KEYS_JSON: &str = r#"{\"local-ui-key\":{\"client_id\":\"local_user\",\"roles\":[\"admin\"],\"scopes\":[\"*\"]}}"#;
const DEFAULT_WALLET_PRIVATE_KEY: &str = "0x59c6995e998f97a5a0044966f0945380f7f660aa1d8b9c5e1d8b0a93d9f5a3b5";

fn resolve_backend_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(path) = app.path().resolve("backend", BaseDirectory::Resource) {
        candidates.push(path);
    }
    if let Ok(path) = app.path().resolve("", BaseDirectory::Resource) {
        candidates.push(path);
    }
    if let Ok(path) = std::env::current_dir() {
        candidates.push(path.join("backend"));
        candidates.push(path.clone());
        candidates.push(path.join("..\\backend"));
    }
    for candidate in candidates {
        if candidate.join("oneseam_backend.exe").exists()
            || candidate.join("oneseam_backend").exists()
            || candidate.join("oneseam.py").exists()
        {
            return Ok(candidate);
        }
    }
    Err("backend directory not found".to_string())
}

fn open_backend_log(app: &AppHandle) -> Result<std::fs::File, String> {
    let log_dir = app
        .path()
        .resolve("logs", BaseDirectory::AppData)
        .map_err(|e| format!("log_dir_resolve_failed: {}", e))?;
    let _ = fs::create_dir_all(&log_dir);
    let log_path = log_dir.join("oneseam-backend.log");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("log_open_failed: {}", e))
}


fn kill_existing_backend() {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/F", "/T", "/IM", "oneseam_backend.exe"])
            .status();
    }
}

fn wait_for_health() -> Result<(), String> {
    let start = Instant::now();
    let client = reqwest::blocking::Client::new();
    while start.elapsed() < Duration::from_secs(HEALTH_TIMEOUT_SECS) {
        if let Ok(resp) = client.get(HEALTH_URL).send() {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(HEALTH_POLL_MS));
    }
    Err("health check timeout".to_string())
}

pub fn start_backend(app: &AppHandle) -> Result<Child, String> {
    kill_existing_backend();
    sleep(Duration::from_secs(1));
    let backend_dir = resolve_backend_dir(app)?;
    let requirements = backend_dir.join("requirements.txt");
    let backend_script = backend_dir.join("oneseam.py");
    let backend_exe = if cfg!(windows) {
        backend_dir.join("oneseam_backend.exe")
    } else {
        backend_dir.join("oneseam_backend")
    };

    let log_file = open_backend_log(app).ok();

    if backend_exe.exists() {
        let stdout_log = log_file.as_ref().and_then(|f| f.try_clone().ok());
        let stderr_log = log_file.as_ref().and_then(|f| f.try_clone().ok());
        let mut cmd = Command::new(&backend_exe);
        cmd.arg("api")
            .current_dir(&backend_dir)
            .stdin(Stdio::null())
            .stdout(stdout_log.map(Stdio::from).unwrap_or(Stdio::null()))
            .stderr(stderr_log.map(Stdio::from).unwrap_or(Stdio::null()));

        if std::env::var("ONESEAM_API_KEYS_JSON").is_err() {
            cmd.env("ONESEAM_API_KEYS_JSON", DEFAULT_API_KEYS_JSON);
        }
        if std::env::var("ONESEAM_WALLET_PRIVATE_KEY").is_err() {
            cmd.env("ONESEAM_WALLET_PRIVATE_KEY", DEFAULT_WALLET_PRIVATE_KEY);
        }
        cmd.env("ONESEAM_LOCAL_TEST", "0");

        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }

        sleep(Duration::from_secs(1));
        match cmd.spawn() {
            Ok(mut child) => match wait_for_health_with_fallback() {
                Ok(()) => return Ok(child),
                Err(_) => {
                    eprintln!("[Backend] EXE health check failed, falling back to Python interpreter");
                    let _ = child.kill();
                    let _ = child.wait();
                    sleep(Duration::from_millis(500));
                }
            },
            Err(_) => {
                eprintln!("[Backend] EXE spawn failed, falling back to Python interpreter");
            }
        }
    }

    let python_check = Command::new("python")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if python_check.is_err() {
        return Err("python_not_found".to_string());
    }

    let pip_status = Command::new("python")
        .arg("-m")
        .arg("pip")
        .arg("install")
        .arg("-r")
        .arg(&requirements)
        .current_dir(&backend_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if pip_status.is_err() {
        return Err("pip_install_failed".to_string());
    }

    let stdout_log = log_file.as_ref().and_then(|f| f.try_clone().ok());
    let stderr_log = log_file.as_ref().and_then(|f| f.try_clone().ok());
    let mut cmd = Command::new("python");
    cmd.arg(backend_script)
        .arg("api")
        .current_dir(&backend_dir)
        .stdin(Stdio::null())
        .stdout(stdout_log.map(Stdio::from).unwrap_or(Stdio::null()))
        .stderr(stderr_log.map(Stdio::from).unwrap_or(Stdio::null()));

    if std::env::var("ONESEAM_API_KEYS_JSON").is_err() {
        cmd.env("ONESEAM_API_KEYS_JSON", DEFAULT_API_KEYS_JSON);
    }
    if std::env::var("ONESEAM_WALLET_PRIVATE_KEY").is_err() {
        cmd.env("ONESEAM_WALLET_PRIVATE_KEY", DEFAULT_WALLET_PRIVATE_KEY);
    }
    cmd.env("ONESEAM_LOCAL_TEST", "0");

    #[cfg(windows)]
    {
        cmd.creation_flags(0x08000000);
    }

    sleep(Duration::from_secs(1));
    let child = cmd.spawn().map_err(|e| format!("spawn_failed: {}", e))?;
    wait_for_health()?;
    Ok(child)
}

fn wait_for_health_with_fallback() -> Result<(), String> {
    let client = reqwest::blocking::Client::new();
    let mut failed_checks = 0;
    const MAX_FAILURES: u32 = 3;
    const CHECK_INTERVAL_MS: u64 = 500;

    for _ in 0..((HEALTH_TIMEOUT_SECS * 1000) / CHECK_INTERVAL_MS) {
        if let Ok(resp) = client.get(HEALTH_URL).send() {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        failed_checks += 1;
        if failed_checks >= MAX_FAILURES {
            return Err("health_check_failed_threshold_exceeded".to_string());
        }
        sleep(Duration::from_millis(CHECK_INTERVAL_MS));
    }
    Err("health_check_timeout".to_string())
}

pub fn stop_backend(child: &mut Child) {
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/F", "/T"])
            .status();
    }

    let _ = child.kill();
    let _ = child.try_wait();
}
