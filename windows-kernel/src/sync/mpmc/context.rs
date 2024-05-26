//! Thread-local channel context.

use alloc::sync::Arc;
use core::cell::{Cell, SyncUnsafeCell};
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use crate::sync::once_lock::OnceLock;
use crate::sync::thread;
use crate::sync::thread::Thread;
use crate::sync::thread_local::lib::ThreadLocal;
use crate::sync::time::Instant;
use crate::Error;

use super::select::Selected;
use super::waker::current_thread_id;

/// Thread-local context.
// TODO: readd Debug (si no boxeas lo tienes de gratis)
#[derive(Clone)]
pub struct Context {
    inner: Arc<Inner>,
}

/// Inner representation of `Context`.
struct Inner {
    /// Selected operation.
    select: AtomicUsize,

    /// A slot into which another thread may store a pointer to its `Packet`.
    packet: AtomicPtr<()>,

    /// Thread handle.
    thread: Thread,

    /// Thread id.
    thread_id: usize,
}

pub fn try_with<F, R>(cell: &Cell<Option<Context>>, f: F) -> Result<R, Error>
where
    F: FnOnce(&Cell<Option<Context>>) -> R,
{
    let thread_local = cell;
    Ok(f(thread_local))
}

pub fn deinit_CONTEXT() {
    let mut current = None;
    unsafe {
        core::mem::swap(&mut current, &mut *get_CONTEXT().get());
    }
    unsafe {
        *get_CONTEXT().get() = None;
    }
}

static CONTEXT: OnceLock<SyncUnsafeCell<Option<ThreadLocal<Cell<Option<Context>>>>>> =
    OnceLock::new();

#[inline]
fn get_CONTEXT() -> &'static SyncUnsafeCell<Option<ThreadLocal<Cell<Option<Context>>>>> {
    CONTEXT.get_or_init(|| SyncUnsafeCell::new(Some(ThreadLocal::new())))
}

impl Context {
    /// Creates a new context for the duration of the closure.
    #[inline]
    pub fn with<F, R>(f: F) -> R
    where
        F: FnOnce(&Context) -> R,
    {
        let mut f = Some(f);
        let mut f = |cx: &Context| -> R {
            let f = f.take().unwrap();
            f(cx)
        };

        unsafe {
            try_with(
                &get_CONTEXT()
                    .get()
                    .as_ref()
                    .unwrap_unchecked()
                    .as_ref()
                    .unwrap_unchecked()
                    .get_or(|| Cell::new(Some(Context::new()))),
                |cell| match cell.take() {
                    None => f(&Context::new()),
                    Some(cx) => {
                        cx.reset();
                        let res = f(&cx);
                        cell.set(Some(cx));
                        res
                    }
                },
            )
            .unwrap_or_else(|_| f(&Context::new()))
        }
    }

    /// Creates a new `Context`.
    #[cold]
    fn new() -> Context {
        Context {
            inner: Arc::new(Inner {
                select: AtomicUsize::new(Selected::Waiting.into()),
                packet: AtomicPtr::new(ptr::null_mut()),
                thread: thread::current(),
                thread_id: current_thread_id() as usize,
            }),
        }
    }

    /// Resets `select` and `packet`.
    #[inline]
    fn reset(&self) {
        self.inner
            .select
            .store(Selected::Waiting.into(), Ordering::Release);
        self.inner.packet.store(ptr::null_mut(), Ordering::Release);
    }

    /// Attempts to select an operation.
    ///
    /// On failure, the previously selected operation is returned.
    #[inline]
    pub fn try_select(&self, select: Selected) -> Result<(), Selected> {
        self.inner
            .select
            .compare_exchange(
                Selected::Waiting.into(),
                select.into(),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|e| e.into())
    }

    /// Stores a packet.
    ///
    /// This method must be called after `try_select` succeeds and there is a packet to provide.
    #[inline]
    pub fn store_packet(&self, packet: *mut ()) {
        if !packet.is_null() {
            self.inner.packet.store(packet, Ordering::Release);
        }
    }

    /// Waits until an operation is selected and returns it.
    ///
    /// If the deadline is reached, `Selected::Aborted` will be selected.
    #[inline]
    pub fn wait_until(&self, deadline: Option<Instant>) -> Selected {
        loop {
            // Check whether an operation has been selected.
            let sel = Selected::from(self.inner.select.load(Ordering::Acquire));
            if sel != Selected::Waiting {
                return sel;
            }

            // If there's a deadline, park the current thread until the deadline is reached.
            if let Some(end) = deadline {
                let now = Instant::now();

                if now < end {
                    Thread::park_timeout(end - now).expect("TODO: panic message");
                } else {
                    // The deadline has been reached. Try aborting select.
                    return match self.try_select(Selected::Aborted) {
                        Ok(()) => Selected::Aborted,
                        Err(s) => s,
                    };
                }
            } else {
                thread::park().expect("TODO: panic message");
            }
        }
    }

    /// Unparks the thread this context belongs to.
    #[inline]
    pub fn unpark(&self) {
        self.inner.thread.unpark().expect("TODO: panic message");
    }

    /// Returns the id of the thread this context belongs to.
    #[inline]
    pub fn thread_id(&self) -> usize {
        self.inner.thread_id
    }
}
