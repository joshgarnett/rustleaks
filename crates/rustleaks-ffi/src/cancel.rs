//! Cancellation: a flag that another thread sets, and a deadline.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use rustleaks_core::ScanCancellation;

/// The flag behind a `rustleaks_cancel` handle. Setting it stops every scan
/// that uses the handle at its next check.
#[derive(Debug, Default)]
pub struct CancelFlag {
    set: AtomicBool,
}

impl CancelFlag {
    /// Sets the flag. It stays set.
    pub fn set(&self) {
        self.set.store(true, Ordering::Release);
    }

    /// Returns whether the flag is set.
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.set.load(Ordering::Acquire)
    }
}

/// The object behind a `rustleaks_cancel` handle. Scans that run on scan
/// threads hold their own reference to the flag.
#[derive(Debug, Default)]
pub struct CancelHandle(Arc<CancelFlag>);

impl CancelHandle {
    /// Sets the flag.
    pub fn set(&self) {
        self.0.set();
    }

    /// A shared reference to the flag.
    #[must_use]
    pub fn flag(&self) -> Arc<CancelFlag> {
        Arc::clone(&self.0)
    }
}

/// The cancellation signal of one scan: an optional shared flag and an
/// optional deadline.
///
/// Core polls the signal between work units, and only once for a run of
/// units that it charges together, so polls are rare next to the work
/// between them. Each poll with a deadline reads the clock, which costs tens
/// of nanoseconds; reading it less often would save nothing measurable and
/// would stop a slow scan later. One long step, such as one pattern search
/// or the keyword pass over a large input, still runs to its end before the
/// next poll.
#[derive(Debug)]
pub(crate) struct ScanSignal<'a> {
    flag: Option<&'a CancelFlag>,
    deadline: Option<Instant>,
    expired: AtomicBool,
}

impl<'a> ScanSignal<'a> {
    /// A signal for one scan.
    pub(crate) fn new(flag: Option<&'a CancelFlag>, deadline: Option<Instant>) -> Self {
        Self {
            flag,
            deadline,
            expired: AtomicBool::new(false),
        }
    }

    /// Returns whether this signal has anything to check.
    pub(crate) const fn is_active(&self) -> bool {
        self.flag.is_some() || self.deadline.is_some()
    }

    /// Returns whether a poll saw the deadline pass.
    pub(crate) fn deadline_expired(&self) -> bool {
        self.expired.load(Ordering::Relaxed)
    }

    /// Returns whether the shared flag is set.
    pub(crate) fn flag_set(&self) -> bool {
        self.flag.is_some_and(CancelFlag::is_set)
    }
}

impl ScanCancellation for ScanSignal<'_> {
    fn is_cancelled(&self) -> bool {
        if self.flag_set() || self.deadline_expired() {
            return true;
        }
        let Some(deadline) = self.deadline else {
            return false;
        };
        if Instant::now() >= deadline {
            self.expired.store(true, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// The signal reads a flag and the clock. Polls with no work between
    /// them give the same answer, apart from the clock moving, so the engine
    /// can poll once for a run of work units.
    fn reads_state_only(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_cancels_and_stays_set() {
        let flag = CancelFlag::default();
        let signal = ScanSignal::new(Some(&flag), None);
        assert!(signal.is_active());
        assert!(!signal.is_cancelled());
        flag.set();
        assert!(signal.is_cancelled());
        assert!(signal.is_cancelled());
        assert!(signal.flag_set());
        assert!(!signal.deadline_expired());
        assert!(signal.reads_state_only());
    }

    use std::time::Duration;

    #[test]
    fn passed_deadline_cancels_at_the_first_poll() {
        let signal = ScanSignal::new(None, Some(Instant::now()));
        assert!(signal.is_cancelled());
        assert!(signal.deadline_expired());
        assert!(!signal.flag_set());
    }

    #[test]
    fn far_deadline_does_not_cancel() {
        let deadline = Instant::now().checked_add(Duration::from_secs(3600));
        let signal = ScanSignal::new(None, deadline);
        for _ in 0..48 {
            assert!(!signal.is_cancelled());
        }
        assert!(!signal.deadline_expired());
    }

    #[test]
    fn no_flag_and_no_deadline_never_cancel() {
        let signal = ScanSignal::new(None, None);
        assert!(!signal.is_active());
        assert!(!signal.is_cancelled());
    }

    #[test]
    fn handles_share_one_flag() {
        let handle = CancelHandle::default();
        let flag = handle.flag();
        assert!(!flag.is_set());
        handle.set();
        assert!(flag.is_set());
    }
}
