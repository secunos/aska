//! Off-thread work for a single-threaded toolkit: run a closure on a worker thread and hand
//! its result back on the main loop. Secrets travel by *move* — a whole `Session` goes out
//! and comes back — never by sharing, so nothing GTK-side ever holds a reference into locked
//! memory while another thread works on it (M3 risk note: keep secrets out of captured state).
//!
//! No extra dependency: a standard channel polled from the main loop every 100 ms.

use gtk::glib;
use std::sync::mpsc;
use std::time::Duration;

/// Run `job` on a new thread; call `on_done` with its result on the main thread.
pub fn run<T, J, D>(job: J, on_done: D)
where
    T: Send + 'static,
    J: FnOnce() -> T + Send + 'static,
    D: FnOnce(T) + 'static,
{
    let (tx, rx) = mpsc::channel::<T>();
    // 2 MiB stack: `scrub_stack` in the core needs ≥ 512 KiB (secret.rs).
    let _ = std::thread::Builder::new()
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            let _ = tx.send(job());
        });
    let mut on_done = Some(on_done);
    glib::timeout_add_local(Duration::from_millis(100), move || match rx.try_recv() {
        Ok(v) => {
            if let Some(f) = on_done.take() {
                f(v);
            }
            glib::ControlFlow::Break
        }
        Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
        Err(mpsc::TryRecvError::Disconnected) => glib::ControlFlow::Break,
    });
}
