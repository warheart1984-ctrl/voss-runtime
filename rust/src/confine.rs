//! Windows job for the worker process.
//!
//! The job blocks child-process creation and ends the worker when the host
//! drops the handle. The worker still runs as the host user. This is not a
//! file or network boundary.

#![allow(unsafe_code)]

#[cfg(windows)]
mod windows {
    use std::ptr;

    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: u32 = 9;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_SET_QUOTA: u32 = 0x0100;

    #[repr(C)]
    struct BasicLimit {
        per_process_user_time: i64,
        per_job_user_time: i64,
        limit_flags: u32,
        minimum_working_set: usize,
        maximum_working_set: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    struct ExtendedLimit {
        basic: BasicLimit,
        io: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    unsafe extern "system" {
        fn CreateJobObjectW(attrs: *mut core::ffi::c_void, name: *const u16) -> *mut core::ffi::c_void;
        fn SetInformationJobObject(
            job: *mut core::ffi::c_void,
            class: u32,
            info: *const core::ffi::c_void,
            length: u32,
        ) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut core::ffi::c_void;
        fn AssignProcessToJobObject(job: *mut core::ffi::c_void, process: *mut core::ffi::c_void) -> i32;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub struct WorkerJob {
        handle: *mut core::ffi::c_void,
    }

    unsafe impl Send for WorkerJob {}

    impl Drop for WorkerJob {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    pub fn confine_pid(pid: u32) -> Result<WorkerJob, String> {
        unsafe {
            let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
            if job.is_null() {
                return Err(format!("CreateJobObjectW failed ({})", GetLastError()));
            }
            let info = ExtendedLimit {
                basic: BasicLimit {
                    per_process_user_time: 0,
                    per_job_user_time: 0,
                    limit_flags: JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                    minimum_working_set: 0,
                    maximum_working_set: 0,
                    active_process_limit: 1,
                    affinity: 0,
                    priority_class: 0,
                    scheduling_class: 0,
                },
                io: IoCounters {
                    read_operation_count: 0,
                    write_operation_count: 0,
                    other_operation_count: 0,
                    read_transfer_count: 0,
                    write_transfer_count: 0,
                    other_transfer_count: 0,
                },
                process_memory_limit: 0,
                job_memory_limit: 0,
                peak_process_memory_used: 0,
                peak_job_memory_used: 0,
            };
            if SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                &info as *const ExtendedLimit as *const core::ffi::c_void,
                std::mem::size_of::<ExtendedLimit>() as u32,
            ) == 0
            {
                let error = GetLastError();
                CloseHandle(job);
                return Err(format!("SetInformationJobObject failed ({error})"));
            }
            let process = OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA, 0, pid);
            if process.is_null() {
                let error = GetLastError();
                CloseHandle(job);
                return Err(format!("OpenProcess failed ({error})"));
            }
            let assigned = AssignProcessToJobObject(job, process);
            let error = GetLastError();
            CloseHandle(process);
            if assigned == 0 {
                CloseHandle(job);
                return Err(format!("AssignProcessToJobObject failed ({error})"));
            }
            Ok(WorkerJob { handle: job })
        }
    }
}

#[cfg(windows)]
pub use windows::{WorkerJob, confine_pid};

#[cfg(not(windows))]
mod other {
    pub struct WorkerJob;

    pub fn confine_pid(_pid: u32) -> Result<WorkerJob, String> {
        Err("worker confinement is implemented for Windows".to_string())
    }
}

#[cfg(not(windows))]
pub use other::{WorkerJob, confine_pid};

#[cfg(all(test, windows))]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    use super::confine_pid;

    #[test]
    fn confined_process_cannot_create_a_child() {
        let script = "import subprocess,sys\nsys.stdin.readline()\ntry:\n subprocess.check_call([sys.executable,'-c','raise SystemExit(0)'])\nexcept Exception:\n print('blocked', flush=True)\nelse:\n print('spawned', flush=True)\n";
        let mut child = Command::new("python")
            .arg("-c")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python");
        let job = confine_pid(child.id()).expect("confine");
        let mut stdin = child.stdin.take().expect("stdin");
        writeln!(stdin).expect("signal");
        drop(stdin);
        let mut stdout = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read");
        drop(job);
        let _ = child.wait();
        assert_eq!(line.trim(), "blocked", "{line:?}");
    }
}
