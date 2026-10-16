//! Be told when Windows locks the session or goes to sleep.
//!
//! The UI toolkit owns the application's window and gives no access to raw window messages, so
//! this module runs its own never-shown top-level window on a dedicated thread. A top-level
//! window (not a message-only one) is required to receive the power broadcast messages. The
//! window procedure forwards two events to a callback; the callback should only hand the event to
//! another thread, never do real work.

use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::mpsc;
use std::thread::JoinHandle;

use windows::core::w;
use windows::Win32::Foundation::{
    GetLastError, ERROR_CLASS_ALREADY_EXISTS, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostMessageW,
    PostQuitMessage, RegisterClassW, TranslateMessage, MSG, PBT_APMSUSPEND, WINDOW_EX_STYLE,
    WM_CLOSE, WM_DESTROY, WM_POWERBROADCAST, WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED,
    WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
};

use crate::PlatformError;

/// Something that should make an unlocked vault lock itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The Windows session was locked, or its console or remote connection was dropped.
    Locked,
    /// The machine is going to sleep or hibernate.
    Suspending,
}

type Handler = Box<dyn Fn(SessionEvent)>;

thread_local! {
    /// Lives on the watcher thread, the only thread that runs the window procedure.
    static HANDLER: RefCell<Option<Handler>> = const { RefCell::new(None) };
}

fn dispatch(event: SessionEvent) {
    HANDLER.with(|h| {
        if let Some(handler) = h.borrow().as_ref() {
            handler(event);
        }
    });
}

/// Window procedure of the hidden watcher window.
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_WTSSESSION_CHANGE => {
            let code = u32::try_from(wparam.0).unwrap_or(u32::MAX);
            if matches!(code, WTS_SESSION_LOCK | WTS_REMOTE_DISCONNECT | WTS_CONSOLE_DISCONNECT) {
                dispatch(SessionEvent::Locked);
            }
            LRESULT(0)
        }
        WM_POWERBROADCAST => {
            if u32::try_from(wparam.0) == Ok(PBT_APMSUSPEND) {
                dispatch(SessionEvent::Suspending);
            }
            // TRUE: grant the request (the message is informational for suspend).
            LRESULT(1)
        }
        WM_CLOSE => {
            // SAFETY: `hwnd` is this window, being closed on the thread that created it.
            let _ = unsafe { WTSUnRegisterSessionNotification(hwnd) };
            // SAFETY: as above; the window is destroyed exactly once.
            let _ = unsafe { DestroyWindow(hwnd) };
            LRESULT(0)
        }
        WM_DESTROY => {
            // SAFETY: ends this thread's message loop; no pointers involved.
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        // SAFETY: forwards the unmodified message to the default handler.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// Create the hidden, never-shown top-level window that receives session and power messages.
pub(crate) fn create_hidden_window() -> Result<HWND, PlatformError> {
    // SAFETY: a null module name asks for this process's own module handle.
    let module = unsafe { GetModuleHandleW(None) }.map_err(|_| PlatformError::Api)?;
    let instance = windows::Win32::Foundation::HINSTANCE(module.0);
    let class = WNDCLASSW {
        lpfnWndProc: Some(wndproc),
        hInstance: instance,
        lpszClassName: w!("ArgusVaultSessionWatcher"),
        ..Default::default()
    };
    // SAFETY: `class` is fully initialized and its string pointer is a static literal.
    if unsafe { RegisterClassW(&raw const class) } == 0 {
        // SAFETY: reads this thread's last-error value set by the failed call above.
        if unsafe { GetLastError() } != ERROR_CLASS_ALREADY_EXISTS {
            return Err(PlatformError::Api);
        }
    }
    // SAFETY: the class was registered above; all other arguments are plain values. The window
    // is never shown.
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class.lpszClassName,
            w!("Argus Vault session watcher"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance),
            None,
        )
    }
    .map_err(|_| PlatformError::Api)
}

fn hwnd_from(raw: isize) -> HWND {
    HWND(raw as *mut c_void)
}

fn watcher_thread(
    on_event: Box<dyn Fn(SessionEvent) + Send>,
    ready: &mpsc::Sender<Result<isize, PlatformError>>,
) {
    HANDLER.with(|h| *h.borrow_mut() = Some(on_event));

    let hwnd = match create_hidden_window() {
        Ok(hwnd) => hwnd,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    // SAFETY: `hwnd` is the live window just created on this thread.
    if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) }.is_err() {
        // SAFETY: as above; nothing else uses the window.
        let _ = unsafe { DestroyWindow(hwnd) };
        let _ = ready.send(Err(PlatformError::Api));
        return;
    }
    let _ = ready.send(Ok(hwnd.0 as isize));

    let mut msg = MSG::default();
    // SAFETY: `msg` is a valid out pointer; a zero window filter reads this thread's messages.
    // `GetMessageW` returns 0 on WM_QUIT and -1 on error, hence `> 0`.
    while unsafe { GetMessageW(&raw mut msg, None, 0, 0) }.0 > 0 {
        // SAFETY: `msg` was filled by `GetMessageW`.
        let _ = unsafe { TranslateMessage(&raw const msg) };
        // SAFETY: as above.
        unsafe { DispatchMessageW(&raw const msg) };
    }
    HANDLER.with(|h| *h.borrow_mut() = None);
}

/// Watches for session lock and suspend until dropped.
#[derive(Debug)]
pub struct SessionWatcher {
    hwnd: isize,
    thread: Option<JoinHandle<()>>,
}

impl SessionWatcher {
    /// Start watching. `on_event` runs on the watcher's own thread: keep it tiny and hand the
    /// event to the UI thread.
    ///
    /// # Errors
    /// [`PlatformError::Api`] if the window or the session notification cannot be created.
    pub fn start<F>(on_event: F) -> Result<Self, PlatformError>
    where
        F: Fn(SessionEvent) + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("argus-session-watcher".to_owned())
            .spawn(move || watcher_thread(Box::new(on_event), &tx))
            .map_err(|_| PlatformError::Api)?;
        match rx.recv() {
            Ok(Ok(hwnd)) => Ok(Self { hwnd, thread: Some(thread) }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => Err(PlatformError::Api),
        }
    }
}

impl Drop for SessionWatcher {
    fn drop(&mut self) {
        // SAFETY: posting to a window handle is thread-safe; if the window is already gone the
        // call just fails.
        let _ = unsafe { PostMessageW(Some(hwnd_from(self.hwnd)), WM_CLOSE, WPARAM(0), LPARAM(0)) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    use windows::Win32::UI::WindowsAndMessaging::SendMessageW;

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    /// Deliver a window message to the watcher exactly as Windows would, from another thread.
    /// This exercises our dispatch; it does not prove Windows registered us for real events.
    fn send(watcher: &SessionWatcher, msg: u32, wparam: u32) {
        let hwnd = hwnd_from(watcher.hwnd);
        // SAFETY: `hwnd` is the watcher's live window; the message carries plain integers.
        let _ = unsafe { SendMessageW(hwnd, msg, Some(WPARAM(wparam as usize)), Some(LPARAM(0))) };
    }

    fn start() -> (SessionWatcher, mpsc::Receiver<SessionEvent>) {
        let (tx, rx) = mpsc::channel();
        let watcher = SessionWatcher::start(move |e| {
            let _ = tx.send(e);
        })
        .unwrap();
        (watcher, rx)
    }

    #[test]
    fn session_lock_is_reported() {
        let (watcher, rx) = start();
        send(&watcher, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK);
        assert_eq!(rx.recv_timeout(WAIT), Ok(SessionEvent::Locked));
    }

    #[test]
    fn remote_and_console_disconnects_count_as_lock() {
        let (watcher, rx) = start();
        send(&watcher, WM_WTSSESSION_CHANGE, WTS_REMOTE_DISCONNECT);
        send(&watcher, WM_WTSSESSION_CHANGE, WTS_CONSOLE_DISCONNECT);
        assert_eq!(rx.recv_timeout(WAIT), Ok(SessionEvent::Locked));
        assert_eq!(rx.recv_timeout(WAIT), Ok(SessionEvent::Locked));
    }

    #[test]
    fn suspend_is_reported() {
        let (watcher, rx) = start();
        send(&watcher, WM_POWERBROADCAST, PBT_APMSUSPEND);
        assert_eq!(rx.recv_timeout(WAIT), Ok(SessionEvent::Suspending));
    }

    #[test]
    fn unrelated_messages_are_ignored() {
        let (watcher, rx) = start();
        // 1 = WTS_CONSOLE_CONNECT, 8 = WTS_SESSION_UNLOCK: neither must lock.
        send(&watcher, WM_WTSSESSION_CHANGE, 1);
        send(&watcher, WM_WTSSESSION_CHANGE, 8);
        send(&watcher, WM_POWERBROADCAST, 7); // PBT_APMRESUMEAUTOMATIC
        assert_eq!(rx.recv_timeout(Duration::from_millis(300)), Err(RecvTimeoutError::Timeout));
    }

    #[test]
    fn dropping_the_watcher_stops_its_thread() {
        let (watcher, rx) = start();
        drop(watcher);
        // The callback (and its sender) is gone once the thread has exited.
        assert_eq!(rx.recv_timeout(WAIT), Err(RecvTimeoutError::Disconnected));
    }

    #[test]
    fn two_watchers_can_coexist() {
        let (first, rx1) = start();
        let (second, rx2) = start();
        send(&first, WM_WTSSESSION_CHANGE, WTS_SESSION_LOCK);
        assert_eq!(rx1.recv_timeout(WAIT), Ok(SessionEvent::Locked));
        assert_eq!(rx2.recv_timeout(Duration::from_millis(300)), Err(RecvTimeoutError::Timeout));
        drop(second);
    }
}
