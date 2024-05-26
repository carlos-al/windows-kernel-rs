//--- This file has been modified, differing from the original github repo wvwwvwwv/scalable-concurrent-containers ---//
//! Epoch-based reclamation.
//!
//! The epoch consensus algorithm and the use of memory barriers and RMW semantics are similar to
//! that of [`crossbeam_epoch`](https://docs.rs/crossbeam-epoch/), however the API set is vastly
//! different, for instance, `unsafe` blocks are not required to read an instance subject to EBR.

pub use atomic_owned::AtomicOwned;
pub use atomic_shared::AtomicShared;
pub use collectible::Collectible;
pub use guard::Guard;
pub use owned::Owned;
pub use ptr::Ptr;
pub use shared::Shared;
pub use tag::Tag;

mod atomic_owned;
mod atomic_shared;
mod collectible;
mod collector;
mod guard;
mod owned;
mod ptr;
mod ref_counted;
mod shared;
mod tag;

/// Suspends the garbage collector of the current thread.
///
/// If returns `false` if there is an active [`Guard`] in the thread. Otherwise, it passes all its
/// retired instances to a free flowing garbage container that can be cleaned up by other threads.
///
/// # Examples
///
/// ```
/// use scc::ebr::{suspend, Guard, Shared};
///
/// assert!(suspend());
///
/// {
///     let shared: Shared<usize> = Shared::new(47);
///     let guard = Guard::new();
///     shared.release(&guard);
///     assert!(!suspend());
/// }
///
/// assert!(suspend());
///
/// let new_shared: Shared<usize> = Shared::new(17);
/// let guard = Guard::new();
/// new_shared.release(&guard);
/// ```
#[inline]
#[must_use]
pub fn suspend() -> bool {
    collector::Collector::pass_garbage()
}
