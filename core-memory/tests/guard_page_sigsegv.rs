//! Integration test: verify guard pages cause SIGSEGV on buffer overflow.
//!
//! Uses subprocess harness pattern: the parent test spawns the test binary
//! with `--exact` targeting a specific harness function, plus an env var
//! that gates the dangerous code. The child attempts an out-of-bounds read
//! and the parent verifies it was killed by SIGSEGV.

#[cfg(unix)]
mod guard_page_tests {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    fn spawn_harness(test_name: &str, env_val: &str) -> std::process::Output {
        let exe = std::env::current_exe().expect("cannot find test binary path");
        Command::new(&exe)
            .arg("--exact")
            .arg(test_name)
            .arg("--test-threads=1")
            .arg("--nocapture")
            .env("__GUARD_PAGE_HARNESS", env_val)
            .output()
            .expect("failed to spawn child process")
    }

    fn assert_signal_death(output: &std::process::Output, expected_signals: &[i32]) {
        let status = output.status;
        assert!(
            !status.success(),
            "child should NOT exit successfully. stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        if let Some(signal) = status.signal() {
            assert!(
                expected_signals.contains(&signal),
                "expected signal {:?}, got signal {signal}. stderr: {}",
                expected_signals,
                String::from_utf8_lossy(&output.stderr),
            );
        } else {
            // Some platforms report signal death as exit code 128+signal.
            let code = status.code().unwrap_or(0);
            let matches = expected_signals
                .iter()
                .any(|&s| code == 128 + s || code == s);
            assert!(
                matches,
                "expected signal death {:?}, got exit code {code}. stderr: {}",
                expected_signals,
                String::from_utf8_lossy(&output.stderr),
            );
        }
    }

    /// Parent test: spawn child that overflows into the trailing guard page.
    #[test]
    fn overflow_hits_trailing_guard_page() {
        let output = spawn_harness("guard_page_tests::overflow_harness", "overflow");
        // SIGSEGV = 11
        assert_signal_death(&output, &[11]);
    }

    /// Child harness: read one byte past the allocation end.
    #[test]
    fn overflow_harness() {
        if std::env::var("__GUARD_PAGE_HARNESS").ok().as_deref() != Some("overflow") {
            return; // Skip when not invoked as child.
        }

        let alloc = core_memory::ProtectedAlloc::from_slice(b"test").expect("allocation failed");
        let ptr = alloc.as_bytes().as_ptr();
        let len = alloc.len();

        // SAFETY: Deliberately out-of-bounds. Testing that SIGSEGV fires.
        #[allow(unsafe_code)]
        unsafe {
            let _byte = std::ptr::read_volatile(ptr.add(len));
        }

        // Unreachable if guard page works.
        std::process::exit(1);
    }

    /// Parent test: spawn child that underflows into the leading guard page.
    #[test]
    fn underflow_hits_leading_guard_page() {
        let output = spawn_harness("guard_page_tests::underflow_harness", "underflow");
        // SIGSEGV = 11, SIGBUS = 7 (some platforms)
        assert_signal_death(&output, &[7, 11]);
    }

    /// Child harness: read before the data region (into guard page 1).
    #[test]
    fn underflow_harness() {
        if std::env::var("__GUARD_PAGE_HARNESS").ok().as_deref() != Some("underflow") {
            return;
        }

        let alloc = core_memory::ProtectedAlloc::from_slice(b"test").expect("allocation failed");
        let ptr = alloc.as_bytes().as_ptr();

        // Go back one full page — past the canary, past any padding,
        // into the guard page between metadata and data region.
        // SAFETY: sysconf is always safe.
        #[allow(unsafe_code)]
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

        // SAFETY: Deliberately out-of-bounds. Testing guard page.
        #[allow(unsafe_code)]
        unsafe {
            let _byte = std::ptr::read_volatile(ptr.sub(page_size));
        }

        std::process::exit(1);
    }
}
