//! Windows Job Object wrapper used to bind the lifetime of a managed process
//! tree to the daemon.
//!
//! Every spawned child is assigned to a dedicated job configured with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Descendants inherit job membership
//! automatically, so the OS kills the entire tree when the last job handle is
//! closed — even if the daemon itself is force-killed. This closes the gaps
//! that `taskkill /T` cannot cover (children re-parented after an intermediate
//! process exits, processes spawned mid-kill, crashed roots whose children
//! outlive them).

use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::time::Duration;

use tokio::time::sleep;
use tracing::warn;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

/// Owns a job handle; dropping it closes the handle, which terminates any
/// processes still in the job thanks to kill-on-close.
pub(super) struct JobObject {
    handle: OwnedHandle,
}

impl JobObject {
    /// Creates an anonymous job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` set.
    pub(super) fn create() -> io::Result<Self> {
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { handle })
    }

    /// Assigns a freshly spawned child to the job. Descendants spawned by the
    /// child afterwards join the job automatically.
    ///
    /// Processes the child spawned in the window between `CreateProcess` and
    /// this call are not captured; the window is microseconds wide and closing
    /// it would require spawning suspended, which `tokio::process` does not
    /// expose.
    pub(super) fn assign(&self, child: &tokio::process::Child) -> io::Result<()> {
        let Some(process_handle) = child.raw_handle() else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "child has no process handle (already reaped)",
            ));
        };
        let ok = unsafe {
            AssignProcessToJobObject(self.handle.as_raw_handle() as HANDLE, process_handle)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Number of processes currently alive inside the job.
    fn active_process_count(&self) -> io::Result<u32> {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle() as HANDLE,
                JobObjectBasicAccountingInformation,
                &mut info as *mut _ as *mut core::ffi::c_void,
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses)
    }

    fn terminate(&self) -> io::Result<()> {
        let ok = unsafe { TerminateJobObject(self.handle.as_raw_handle() as HANDLE, 1) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Called after the root process has exited: gives surviving descendants
    /// up to `grace` to finish on their own (they may still be handling the
    /// graceful `taskkill` close request), then terminates whatever is left.
    /// Consumes the job; dropping the handle keeps kill-on-close as a final
    /// backstop.
    pub(super) async fn reap_survivors(self, name: &str, grace: Duration) {
        let deadline = tokio::time::Instant::now() + grace;
        loop {
            match self.active_process_count() {
                Ok(0) => return,
                Ok(_) => {}
                Err(err) => {
                    warn!("failed to query job object for process {name}: {err}");
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            sleep(Duration::from_millis(200)).await;
        }

        match self.terminate() {
            Ok(()) => warn!("terminated orphaned child processes left behind by process {name}"),
            Err(err) => warn!("failed to terminate job object for process {name}: {err}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// `ping -n <count>` is the portable way to keep a console child alive
    /// without needing stdin (unlike `timeout`, which rejects redirected input).
    fn spawn_ping() -> tokio::process::Child {
        tokio::process::Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn ping")
    }

    #[tokio::test]
    async fn terminate_kills_assigned_child() {
        let job = JobObject::create().expect("create job");
        let mut child = spawn_ping();
        job.assign(&child).expect("assign child to job");
        assert_eq!(job.active_process_count().unwrap(), 1);

        job.terminate().expect("terminate job");
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("child did not exit after job termination")
            .expect("wait failed");
        assert!(!status.success());
        assert_eq!(job.active_process_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn reap_survivors_returns_quickly_when_job_is_empty() {
        let job = JobObject::create().expect("create job");
        let mut child = spawn_ping();
        job.assign(&child).expect("assign child to job");
        child.kill().await.expect("kill child");
        let _ = child.wait().await;

        let start = std::time::Instant::now();
        job.reap_survivors("test", Duration::from_secs(10)).await;
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
