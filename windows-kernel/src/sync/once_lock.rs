use alloc::fmt;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::MaybeUninit;

mod sys {
    use alloc::fmt;
    use core::cell::Cell;
    use core::ptr;
    use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

    use crate::sync::once_lock;
    use crate::sync::once_lock::ExclusiveState;
    use crate::sync::thread;
    use crate::sync::thread::Thread;

    type Masked = ();

    pub struct Once {
        state_and_queue: AtomicPtr<Masked>,
    }

    pub struct OnceState {
        poisoned: bool,
        set_state_on_drop_to: Cell<*mut Masked>,
    }

    // Four states that a Once can be in, encoded into the lower bits of
    // `state_and_queue` in the Once structure.
    const INCOMPLETE: usize = 0x0;
    const POISONED: usize = 0x1;
    const RUNNING: usize = 0x2;
    const COMPLETE: usize = 0x3;

    // Mask to learn about the state. All other bits are the queue of waiters if
    // this is in the RUNNING state.
    const STATE_MASK: usize = 0x3;

    // Representation of a node in the linked list of waiters, used while in the
    // RUNNING state.
    // Note: `Waiter` can't hold a mutable pointer to the next thread, because then
    // `wait` would both hand out a mutable reference to its `Waiter` node, and keep
    // a shared reference to check `signaled`. Instead we hold shared references and
    // use interior mutability.
    #[repr(align(4))] // Ensure the two lower bits are free to use as state bits.
    struct Waiter {
        thread: Cell<Option<Thread>>,
        signaled: AtomicBool,
        next: *const Waiter,
    }

    // Head of a linked list of waiters.
    // Every node is a struct on the stack of a waiting thread.
    // Will wake up the waiters when it gets dropped, i.e. also on panic.
    struct WaiterQueue<'a> {
        state_and_queue: &'a AtomicPtr<Masked>,
        set_state_on_drop_to: *mut Masked,
    }

    impl Once {
        #[inline]
        pub const fn new() -> Once {
            Once {
                state_and_queue: AtomicPtr::new(ptr::without_provenance_mut(INCOMPLETE)),
            }
        }

        #[inline]
        pub fn is_completed(&self) -> bool {
            // An `Acquire` load is enough because that makes all the initialization
            // operations visible to us, and, this being a fast path, weaker
            // ordering helps with performance. This `Acquire` synchronizes with
            // `Release` operations on the slow path.
            self.state_and_queue.load(Ordering::Acquire).addr() == COMPLETE
        }

        #[inline]
        pub(crate) fn state(&mut self) -> ExclusiveState {
            match self.state_and_queue.get_mut().addr() {
                INCOMPLETE => ExclusiveState::Incomplete,
                POISONED => ExclusiveState::Poisoned,
                COMPLETE => ExclusiveState::Complete,
                _ => unreachable!("invalid Once state"),
            }
        }

        // This is a non-generic function to reduce the monomorphization cost of
        // using `call_once` (this isn't exactly a trivial or small implementation).
        //
        // Additionally, this is tagged with `#[cold]` as it should indeed be cold
        // and it helps let LLVM know that calls to this function should be off the
        // fast path. Essentially, this should help generate more straight line code
        // in LLVM.
        //
        // Finally, this takes an `FnMut` instead of a `FnOnce` because there's
        // currently no way to take an `FnOnce` and call it via virtual dispatch
        // without some allocation overhead.
        #[cold]
        #[track_caller]
        pub fn call(&self, ignore_poisoning: bool, init: &mut dyn FnMut(&once_lock::OnceState)) {
            let mut state_and_queue = self.state_and_queue.load(Ordering::Acquire);
            loop {
                match state_and_queue.addr() {
                    COMPLETE => break,
                    POISONED if !ignore_poisoning => {
                        // Panic to propagate the poison.
                        panic!("Once instance has previously been poisoned");
                    }
                    POISONED | INCOMPLETE => {
                        // Try to register this thread as the one RUNNING.
                        let exchange_result = self.state_and_queue.compare_exchange(
                            state_and_queue,
                            ptr::without_provenance_mut(RUNNING),
                            Ordering::Acquire,
                            Ordering::Acquire,
                        );
                        if let Err(old) = exchange_result {
                            state_and_queue = old;
                            continue;
                        }
                        // `waiter_queue` will manage other waiting threads, and
                        // wake them up on drop.
                        let mut waiter_queue = WaiterQueue {
                            state_and_queue: &self.state_and_queue,
                            set_state_on_drop_to: ptr::without_provenance_mut(POISONED),
                        };
                        // Run the initialization function, letting it know if we're
                        // poisoned or not.
                        let init_state = once_lock::OnceState {
                            inner: OnceState {
                                poisoned: state_and_queue.addr() == POISONED,
                                set_state_on_drop_to: Cell::new(ptr::without_provenance_mut(COMPLETE)),
                            },
                        };
                        init(&init_state);
                        waiter_queue.set_state_on_drop_to =
                            init_state.inner.set_state_on_drop_to.get();
                        break;
                    }
                    _ => {
                        // All other values must be RUNNING with possibly a
                        // pointer to the waiter queue in the more significant bits.
                        assert!(state_and_queue.addr() & STATE_MASK == RUNNING);
                        wait(&self.state_and_queue, state_and_queue);
                        state_and_queue = self.state_and_queue.load(Ordering::Acquire);
                    }
                }
            }
        }
    }

    fn wait(state_and_queue: &AtomicPtr<Masked>, mut current_state: *mut Masked) {
        // Note: the following code was carefully written to avoid creating a
        // mutable reference to `node` that gets aliased.
        loop {
            // Don't queue this thread if the status is no longer running,
            // otherwise we will not be woken up.
            if current_state.addr() & STATE_MASK != RUNNING {
                return;
            }

            // Create the node for our current thread.
            let node = Waiter {
                thread: Cell::new(Some(thread::current())),
                signaled: AtomicBool::new(false),
                next: current_state.with_addr(current_state.addr() & !STATE_MASK) as *const Waiter,
            };
            let me = &node as *const Waiter as *const Masked as *mut Masked;

            // Try to slide in the node at the head of the linked list, making sure
            // that another thread didn't just replace the head of the linked list.
            let exchange_result = state_and_queue.compare_exchange(
                current_state,
                me.with_addr(me.addr() | RUNNING),
                Ordering::Release,
                Ordering::Relaxed,
            );
            if let Err(old) = exchange_result {
                current_state = old;
                continue;
            }

            // We have enqueued ourselves, now lets wait.
            // It is important not to return before being signaled, otherwise we
            // would drop our `Waiter` node and leave a hole in the linked list
            // (and a dangling reference). Guard against spurious wakeups by
            // reparking ourselves until we are signaled.
            while !node.signaled.load(Ordering::Acquire) {
                // If the managing thread happens to signal and unpark us before we
                // can park ourselves, the result could be this thread never gets
                // unparked. Luckily `park` comes with the guarantee that if it got
                // an `unpark` just before on an unparked thread it does not park.
                thread::park();
            }
            break;
        }
    }

    impl fmt::Debug for Once {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Once").finish_non_exhaustive()
        }
    }

    impl Drop for WaiterQueue<'_> {
        fn drop(&mut self) {
            // Swap out our state with however we finished.
            let state_and_queue = self
                .state_and_queue
                .swap(self.set_state_on_drop_to, Ordering::AcqRel);

            // We should only ever see an old state which was RUNNING.
            assert_eq!(state_and_queue.addr() & STATE_MASK, RUNNING);

            // Walk the entire linked list of waiters and wake them up (in lifo
            // order, last to register is first to wake up).
            unsafe {
                // Right after setting `node.signaled = true` the other thread may
                // free `node` if there happens to be has a spurious wakeup.
                // So we have to take out the `thread` field and copy the pointer to
                // `next` first.
                let mut queue = state_and_queue.with_addr(state_and_queue.addr() & !STATE_MASK)
                    as *const Waiter;
                while !queue.is_null() {
                    let next = (*queue).next;
                    let thread = (*queue).thread.take().unwrap();
                    (*queue).signaled.store(true, Ordering::Release);
                    // ^- FIXME (maybe): This is another case of issue #55005
                    // `store()` has a potentially dangling ref to `signaled`.
                    queue = next;
                    thread.unpark();
                }
            }
        }
    }

    impl OnceState {
        #[inline]
        pub fn is_poisoned(&self) -> bool {
            self.poisoned
        }

        #[inline]
        pub fn poison(&self) {
            self.set_state_on_drop_to.set(ptr::without_provenance_mut(POISONED));
        }
    }
}

pub struct Once {
    inner: sys::Once,
}

pub struct OnceState {
    pub(crate) inner: sys::OnceState,
}

impl Once {
    pub const fn new() -> Once {
        Once {
            inner: sys::Once::new(),
        }
    }
    pub fn call_once<F>(&self, f: F)
    where
        F: FnOnce(),
    {
        // Fast path check
        if self.inner.is_completed() {
            return;
        }

        let mut f = Some(f);
        self.inner.call(false, &mut |_| f.take().unwrap()());
    }

    pub fn call_once_force<F>(&self, f: F)
    where
        F: FnOnce(&OnceState),
    {
        // Fast path check
        if self.inner.is_completed() {
            return;
        }

        let mut f = Some(f);
        self.inner.call(true, &mut |p| f.take().unwrap()(p));
    }

    pub(crate) fn state(&mut self) -> ExclusiveState {
        self.inner.state()
    }
}

impl OnceState {
    #[inline]
    pub fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }

    #[inline]
    pub(crate) fn poison(&self) {
        self.inner.poison();
    }
}

pub(crate) enum ExclusiveState {
    Incomplete,
    Poisoned,
    Complete,
}

/// A synchronization primitive which can be written to only once.
///
/// This type is a thread-safe [`OnceCell`], and can be used in statics.
///
/// [`OnceCell`]: crate::cell::OnceCell
///
/// # Examples
///
/// ```
/// use std::sync::OnceLock;
///
/// static CELL: OnceLock<String> = OnceLock::new();
/// assert!(CELL.get().is_none());
///
/// std::thread::spawn(|| {
///     let value: &String = CELL.get_or_init(|| {
///         "Hello, World!".to_string()
///     });
///     assert_eq!(value, "Hello, World!");
/// }).join().unwrap();
///
/// let value: Option<&String> = CELL.get();
/// assert!(value.is_some());
/// assert_eq!(value.unwrap().as_str(), "Hello, World!");
/// ```
pub struct OnceLock<T> {
    once: Once,
    // Whether or not the value is initialized is tracked by `once.is_completed()`.
    value: UnsafeCell<MaybeUninit<T>>,
    /// `PhantomData` to make sure dropck understands we're dropping T in our Drop impl.
    ///
    /// ```compile_fail,E0597
    /// use std::sync::OnceLock;
    ///
    /// struct A<'a>(&'a str);
    ///
    /// impl<'a> Drop for A<'a> {
    ///     fn drop(&mut self) {}
    /// }
    ///
    /// let cell = OnceLock::new();
    /// {
    ///     let s = String::new();
    ///     let _ = cell.set(A(&s));
    /// }
    /// ```
    _marker: PhantomData<T>,
}

impl<T> OnceLock<T> {
    /// Creates a new empty cell.
    #[inline]
    #[must_use]
    pub const fn new() -> OnceLock<T> {
        OnceLock {
            once: Once::new(),
            value: UnsafeCell::new(MaybeUninit::uninit()),
            _marker: PhantomData,
        }
    }

    /// Gets the reference to the underlying value.
    ///
    /// Returns `None` if the cell is empty, or being initialized. This
    /// method never blocks.
    #[inline]
    pub fn get(&self) -> Option<&T> {
        if self.is_initialized() {
            // Safe b/c checked is_initialized
            Some(unsafe { self.get_unchecked() })
        } else {
            None
        }
    }

    /// Gets the mutable reference to the underlying value.
    ///
    /// Returns `None` if the cell is empty. This method never blocks.
    #[inline]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        if self.is_initialized() {
            // Safe b/c checked is_initialized and we have a unique access
            Some(unsafe { self.get_unchecked_mut() })
        } else {
            None
        }
    }

    /// Sets the contents of this cell to `value`.
    ///
    /// May block if another thread is currently attempting to initialize the cell. The cell is
    /// guaranteed to contain a value when set returns, though not necessarily the one provided.
    ///
    /// Returns `Ok(())` if the cell's value was set by this call.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::OnceLock;
    ///
    /// static CELL: OnceLock<i32> = OnceLock::new();
    ///
    /// fn main() {
    ///     assert!(CELL.get().is_none());
    ///
    ///     std::thread::spawn(|| {
    ///         assert_eq!(CELL.set(92), Ok(()));
    ///     }).join().unwrap();
    ///
    ///     assert_eq!(CELL.set(62), Err(62));
    ///     assert_eq!(CELL.get(), Some(&92));
    /// }
    /// ```
    #[inline]
    pub fn set(&self, value: T) -> Result<(), T> {
        let mut value = Some(value);
        self.get_or_init(|| value.take().unwrap());
        match value {
            None => Ok(()),
            Some(value) => Err(value),
        }
    }

    /// Gets the contents of the cell, initializing it with `f` if the cell
    /// was empty.
    ///
    /// Many threads may call `get_or_init` concurrently with different
    /// initializing functions, but it is guaranteed that only one function
    /// will be executed.
    ///
    /// # Panics
    ///
    /// If `f` panics, the panic is propagated to the caller, and the cell
    /// remains uninitialized.
    ///
    /// It is an error to reentrantly initialize the cell from `f`. The
    /// exact outcome is unspecified. Current implementation deadlocks, but
    /// this may be changed to a panic in the future.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::OnceLock;
    ///
    /// let cell = OnceLock::new();
    /// let value = cell.get_or_init(|| 92);
    /// assert_eq!(value, &92);
    /// let value = cell.get_or_init(|| unreachable!());
    /// assert_eq!(value, &92);
    /// ```
    #[inline]
    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        match self.get_or_try_init(|| Ok::<T, !>(f())) {
            Ok(val) => val,
            Err(_) => panic!("noo"),
        }
    }

    /// Gets the contents of the cell, initializing it with `f` if
    /// the cell was empty. If the cell was empty and `f` failed, an
    /// error is returned.
    ///
    /// # Panics
    ///
    /// If `f` panics, the panic is propagated to the caller, and
    /// the cell remains uninitialized.
    ///
    /// It is an error to reentrantly initialize the cell from `f`.
    /// The exact outcome is unspecified. Current implementation
    /// deadlocks, but this may be changed to a panic in the future.
    ///
    /// # Examples
    ///
    /// ```
    /// #![feature(once_cell_try)]
    ///
    /// use std::sync::OnceLock;
    ///
    /// let cell = OnceLock::new();
    /// assert_eq!(cell.get_or_try_init(|| Err(())), Err(()));
    /// assert!(cell.get().is_none());
    /// let value = cell.get_or_try_init(|| -> Result<i32, ()> {
    ///     Ok(92)
    /// });
    /// assert_eq!(value, Ok(&92));
    /// assert_eq!(cell.get(), Some(&92))
    /// ```
    #[inline]
    pub fn get_or_try_init<F, E>(&self, f: F) -> Result<&T, E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        // Fast path check
        // NOTE: We need to perform an acquire on the state in this method
        // in order to correctly synchronize `LazyLock::force`. This is
        // currently done by calling `self.get()`, which in turn calls
        // `self.is_initialized()`, which in turn performs the acquire.
        if let Some(value) = self.get() {
            return Ok(value);
        }
        self.initialize(f)?;

        debug_assert!(self.is_initialized());

        // SAFETY: The inner value has been initialized
        Ok(unsafe { self.get_unchecked() })
    }

    /// Consumes the `OnceLock`, returning the wrapped value. Returns
    /// `None` if the cell was empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::OnceLock;
    ///
    /// let cell: OnceLock<String> = OnceLock::new();
    /// assert_eq!(cell.into_inner(), None);
    ///
    /// let cell = OnceLock::new();
    /// cell.set("hello".to_string()).unwrap();
    /// assert_eq!(cell.into_inner(), Some("hello".to_string()));
    /// ```
    #[inline]
    pub fn into_inner(mut self) -> Option<T> {
        self.take()
    }

    /// Takes the value out of this `OnceLock`, moving it back to an uninitialized state.
    ///
    /// Has no effect and returns `None` if the `OnceLock` hasn't been initialized.
    ///
    /// Safety is guaranteed by requiring a mutable reference.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::OnceLock;
    ///
    /// let mut cell: OnceLock<String> = OnceLock::new();
    /// assert_eq!(cell.take(), None);
    ///
    /// let mut cell = OnceLock::new();
    /// cell.set("hello".to_string()).unwrap();
    /// assert_eq!(cell.take(), Some("hello".to_string()));
    /// assert_eq!(cell.get(), None);
    /// ```
    #[inline]
    pub fn take(&mut self) -> Option<T> {
        if self.is_initialized() {
            self.once = Once::new();
            // SAFETY: `self.value` is initialized and contains a valid `T`.
            // `self.once` is reset, so `is_initialized()` will be false again
            // which prevents the value from being read twice.
            unsafe { Some((&mut *self.value.get()).assume_init_read()) }
        } else {
            None
        }
    }

    #[inline]
    fn is_initialized(&self) -> bool {
        self.once.inner.is_completed()
    }

    #[cold]
    fn initialize<F, E>(&self, f: F) -> Result<(), E>
    where
        F: FnOnce() -> Result<T, E>,
    {
        let mut res: Result<(), E> = Ok(());
        let slot = &self.value;

        // Ignore poisoning from other threads
        // If another thread panics, then we'll be able to run our closure
        self.once.call_once_force(|p| {
            match f() {
                Ok(value) => {
                    unsafe { (&mut *slot.get()).write(value) };
                }
                Err(e) => {
                    res = Err(e);

                    // Treat the underlying `Once` as poisoned since we
                    // failed to initialize our value. Calls
                    p.poison();
                }
            }
        });
        res
    }

    /// # Safety
    ///
    /// The value must be initialized
    #[inline]
    unsafe fn get_unchecked(&self) -> &T {
        debug_assert!(self.is_initialized());
        (&*self.value.get()).assume_init_ref()
    }

    /// # Safety
    ///
    /// The value must be initialized
    #[inline]
    unsafe fn get_unchecked_mut(&mut self) -> &mut T {
        debug_assert!(self.is_initialized());
        (&mut *self.value.get()).assume_init_mut()
    }
}

// Why do we need `T: Send`?
// Thread A creates a `OnceLock` and shares it with
// scoped thread B, which fills the cell, which is
// then destroyed by A. That is, destructor observes
// a sent value.
unsafe impl<T: Sync + Send> Sync for OnceLock<T> {}

unsafe impl<T: Send> Send for OnceLock<T> {}

impl<T> Default for OnceLock<T> {
    /// Creates a new empty cell.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::OnceLock;
    ///
    /// fn main() {
    ///     assert_eq!(OnceLock::<()>::new(), OnceLock::default());
    /// }
    /// ```
    #[inline]
    fn default() -> OnceLock<T> {
        OnceLock::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for OnceLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get() {
            Some(v) => f.debug_tuple("Once").field(v).finish(),
            None => f.write_str("Once(Uninit)"),
        }
    }
}

impl<T: Clone> Clone for OnceLock<T> {
    #[inline]
    fn clone(&self) -> OnceLock<T> {
        let cell = Self::new();
        if let Some(value) = self.get() {
            match cell.set(value.clone()) {
                Ok(()) => (),
                Err(_) => unreachable!(),
            }
        }
        cell
    }
}

impl<T> From<T> for OnceLock<T> {
    /// Create a new cell with its contents set to `value`.
    ///
    /// # Example
    ///
    /// ```
    /// use std::sync::OnceLock;
    ///
    /// # fn main() -> Result<(), i32> {
    /// let a = OnceLock::from(3);
    /// let b = OnceLock::new();
    /// b.set(3)?;
    /// assert_eq!(a, b);
    /// Ok(())
    /// # }
    /// ```
    #[inline]
    fn from(value: T) -> Self {
        let cell = Self::new();
        match cell.set(value) {
            Ok(()) => cell,
            Err(_) => unreachable!(),
        }
    }
}

impl<T: PartialEq> PartialEq for OnceLock<T> {
    #[inline]
    fn eq(&self, other: &OnceLock<T>) -> bool {
        self.get() == other.get()
    }
}

impl<T: Eq> Eq for OnceLock<T> {}

unsafe impl<#[may_dangle] T> Drop for OnceLock<T> {
    #[inline]
    fn drop(&mut self) {
        if self.is_initialized() {
            // SAFETY: The cell is initialized and being dropped, so it can't
            // be accessed again. We also don't touch the `T` other than
            // dropping it, which validates our usage of #[may_dangle].
            unsafe { (&mut *self.value.get()).assume_init_drop() };
        }
    }
}
