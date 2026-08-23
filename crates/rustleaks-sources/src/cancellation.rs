use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Read-only cancellation state accepted by source adapters.
pub trait Cancellation: Send + Sync {
    /// Returns whether cancellation has been requested.
    fn is_cancelled(&self) -> bool;
}

/// Cloneable cooperative cancellation token.
///
/// Clones observe the same atomic state. Cancellation never detaches source
/// runner workers: a runner closes its work queue and joins every worker before
/// returning a cancelled outcome.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Creates a token in the non-cancelled state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cooperative cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Cancellation for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

impl rustleaks_core::ScanCancellation for CancellationToken {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

impl Cancellation for AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(Ordering::Acquire)
    }
}
