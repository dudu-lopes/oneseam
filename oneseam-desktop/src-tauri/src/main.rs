use std::{process::Child, sync::Mutex};
use tauri::{Manager, WindowEvent};

mod python;

struct BackendState(Mutex<Option<Child>>);

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let child = python::start_backend(&app.handle())
                .map_err(|e| format!("Failed to start ONESEAM node: {}", e))?;
            app.manage(BackendState(Mutex::new(Some(child))));
            Ok(())
        })
        .on_window_event(|app, event| {
            if let WindowEvent::CloseRequested { .. } = event {
                if let Some(state) = app.try_state::<BackendState>() {
                    if let Ok(mut guard) = state.0.lock() {
                        if let Some(mut child) = guard.take() {
                            python::stop_backend(&mut child);
                        }
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
