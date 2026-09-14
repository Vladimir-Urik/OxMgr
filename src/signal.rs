//! Shutdown signal handling shared by the daemon loop and the foreground
//! runtime command.
//!
//! Both entry points need the same behaviour: wake up on SIGTERM or SIGINT so
//! managed processes get a graceful shutdown. SIGTERM matters most in
//! containers, where `docker stop` sends SIGTERM and PID 1 gets no default
//! disposition from the kernel: a process that only listens for SIGINT would
//! ignore it outright and be SIGKILLed after the stop timeout, leaving managed
//! children no chance to exit cleanly.

/// Listens for shutdown signals.
///
/// Construct this once with [`ShutdownListener::install`] and poll
/// [`ShutdownListener::recv`] inside the event loop. Registering the handlers up
/// front matters: building a fresh signal stream on every `select!` iteration
/// can drop a signal that arrives between iterations.
///
/// There is deliberately no `Default` implementation: constructing a listener
/// installs process-wide signal handlers, which is an observable side effect
/// rather than a neutral default value.
pub struct ShutdownListener {
    #[cfg(unix)]
    sigterm: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    sigint: Option<tokio::signal::unix::Signal>,
}

impl ShutdownListener {
    /// Registers the signal handlers.
    ///
    /// A handler that cannot be installed is left as `None` and simply never
    /// fires, so a partial failure degrades instead of taking the daemon down.
    #[must_use]
    pub fn install() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let sigterm = signal(SignalKind::terminate()).map_or_else(
                |err| {
                    tracing::warn!("failed to install SIGTERM handler: {err}");
                    None
                },
                Some,
            );
            let sigint = signal(SignalKind::interrupt()).map_or_else(
                |err| {
                    tracing::warn!("failed to install SIGINT handler: {err}");
                    None
                },
                Some,
            );
            Self { sigterm, sigint }
        }
        #[cfg(not(unix))]
        {
            Self {}
        }
    }

    /// Resolves once a shutdown signal arrives, yielding the signal name for
    /// logging. Waits forever when no handler could be installed.
    #[cfg(unix)]
    pub async fn recv(&mut self) -> &'static str {
        match (self.sigterm.as_mut(), self.sigint.as_mut()) {
            (Some(sigterm), Some(sigint)) => {
                tokio::select! {
                    _ = sigterm.recv() => "SIGTERM",
                    _ = sigint.recv() => "SIGINT",
                }
            }
            (Some(sigterm), None) => {
                sigterm.recv().await;
                "SIGTERM"
            }
            (None, Some(sigint)) => {
                sigint.recv().await;
                "SIGINT"
            }
            (None, None) => std::future::pending().await,
        }
    }

    /// Non-Unix fallback: only Ctrl-C is available.
    #[cfg(not(unix))]
    pub async fn recv(&mut self) -> &'static str {
        let _ = tokio::signal::ctrl_c().await;
        "CTRL-C"
    }
}

/// One-shot helper for call sites that only need to await a single shutdown
/// signal rather than poll inside a loop.
pub async fn wait_for_shutdown_signal() -> &'static str {
    ShutdownListener::install().recv().await
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::OnceLock;
    use std::time::Duration;

    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    use tokio::sync::Mutex;

    use super::ShutdownListener;

    /// Signal dispositions are process-wide, so the signalling tests must not
    /// overlap with each other. This is an async mutex because the guard is held
    /// across the `.await` on the listener.
    fn signal_mutex() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    /// The regression this guards: the daemon previously only listened for
    /// SIGINT, so `docker stop` (SIGTERM) was ignored by PID 1 and managed
    /// processes never got a graceful shutdown.
    #[tokio::test]
    async fn listener_receives_sigterm() {
        let _guard = signal_mutex().lock().await;
        let mut listener = ShutdownListener::install();

        // Raise after the handler is installed, otherwise the default
        // disposition would terminate the test process.
        kill(Pid::this(), Signal::SIGTERM).expect("failed to raise SIGTERM");

        let name = tokio::time::timeout(Duration::from_secs(5), listener.recv())
            .await
            .expect("SIGTERM should be delivered to the listener");
        assert_eq!(name, "SIGTERM");
    }

    #[tokio::test]
    async fn listener_receives_sigint() {
        let _guard = signal_mutex().lock().await;
        let mut listener = ShutdownListener::install();

        kill(Pid::this(), Signal::SIGINT).expect("failed to raise SIGINT");

        let name = tokio::time::timeout(Duration::from_secs(5), listener.recv())
            .await
            .expect("SIGINT should be delivered to the listener");
        assert_eq!(name, "SIGINT");
    }

    #[tokio::test]
    async fn listener_stays_pending_without_a_signal() {
        // Must hold the same lock: signals are process-wide, so without it this
        // test races the cases above and observes their SIGTERM/SIGINT.
        let _guard = signal_mutex().lock().await;
        let mut listener = ShutdownListener::install();
        let result = tokio::time::timeout(Duration::from_millis(200), listener.recv()).await;
        assert!(
            result.is_err(),
            "listener should not resolve without a signal"
        );
    }
}
