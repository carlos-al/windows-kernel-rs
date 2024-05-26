use alloc::boxed::Box;
use alloc::fmt;
use core::cell::UnsafeCell;
use core::fmt::{Debug, Formatter};
use core::ops::{Deref, DerefMut};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use windows_kernel_sys::base::_KWAIT_REASON::Executive;
use windows_kernel_sys::base::_MODE::KernelMode;
use windows_kernel_sys::base::{FALSE, KMUTEX};
use windows_kernel_sys::ntoskrnl::{
    ExTryToAcquireFastMutex, KeInitializeMutex, KeReleaseMutex, KeWaitForSingleObject,
};

use crate::Error;

/// A mutual exclusion primitive useful for protecting shared data.
///
/// This mutex will block threads waiting for the lock to become available. The mutex can also be
/// statically initialized or created via a [`new`] constructor. Each mutex has a type parameter
/// which represents the data that it is protecting. The data can only be accessed through the RAII
/// guards returned from [`lock`] and [`try_lock`], which guarantees that the data is only ever
/// accessed when the mutex is locked.
///
/// [`new`]: RecursiveMutex::new
/// [`lock`]: RecursiveMutex::lock
/// [`try_lock`]: RecursiveMutex::try_lock

pub struct RecursiveMutex<T: ?Sized> {
    pub(crate) lock: Box<KMUTEX>,
    pub(crate) poison: Flag,
    pub(crate) data: UnsafeCell<T>,
}

unsafe impl<T> Send for RecursiveMutex<T> {}

unsafe impl<T> Sync for RecursiveMutex<T> {}

impl<T> Debug for RecursiveMutex<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "mutexito")
    }
}

impl<T> RecursiveMutex<T> {
    /// Creates a new mutex in an unlocked state ready for use.
    pub fn new(data: T) -> Self {
        let mut lock: Box<KMUTEX> = Box::new(unsafe { core::mem::zeroed() });

        unsafe { KeInitializeMutex(&mut *lock, 0) };

        Self {
            lock,
            data: UnsafeCell::new(data),
            poison: Flag {
                failed: AtomicBool::new(false),
            },
        }
    }

    /// Consumes this `FastMutex`, returning the underlying data.
    #[inline]
    pub fn into_inner(self) -> T {
        let Self { data, .. } = self;
        data.into_inner()
    }

    /// Attempts to acquire this lock.
    ///
    /// If the lock could not be acquired at this time, then `None` is returned. Otherwise, an RAII
    /// guard is returned. The lock will be unlocked when the guard is dropped.
    ///
    /// This function does not block.
    #[inline]
    pub fn try_lock(&self) -> Option<RecursiveMutexGuard<T>> {
        let status = unsafe { ExTryToAcquireFastMutex(&*self.lock as *const _ as *mut _) } != 0;

        match status {
            true => Some(RecursiveMutexGuard {
                lock: &self.lock,
                data: unsafe { &mut *self.data.get() },
                poison: &self.poison,
            }),
            _ => None,
        }
    }

    /// Acquires a mutex, blocking the current thread until it is able to do so.
    ///
    /// This function will block the local thread until it is available to acquire the mutex. Upon
    /// returning, the thread is the only thread with the lock held. An RAII guard is returned to
    /// allow scoped unlock of the lock. When the guard goes out of scope, the mutex will be
    /// unlocked.
    ///
    /// The underlying function does not allow for recursion. If the thread already holds the lock
    /// and tries to lock the mutex again, bugcheck
    /// If a thread quits while holding a lock, bugcheck
    #[inline]
    pub fn lock(&self) -> Option<RecursiveMutexGuard<T>> {
        unsafe {
            KeWaitForSingleObject(
                &*self.lock as *const _ as *mut _,
                Executive,
                KernelMode as _,
                FALSE,
                null_mut(),
            )
        };

        Some(RecursiveMutexGuard {
            lock: &self.lock,
            data: unsafe { &mut *self.data.get() },
            poison: &self.poison,
        })
    }

    pub fn guard_poison<'a>(x: &RecursiveMutexGuard<'a, T>) -> &'a Flag {
        &x.poison
    }
}

impl<T: ?Sized + Default> Default for RecursiveMutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> From<T> for RecursiveMutex<T> {
    fn from(data: T) -> Self {
        Self::new(data)
    }
}

/// An RAII implementation of a "scoped lock" of a mutex. When this structure is dropped (falls out
/// of scope), the lock will be unlocked.
///
/// The data protected by the mutex can be accessed through this guard via its [`Deref`] and
/// [`DerefMut`] implementations.
///
/// This structure is created by the [`lock`] and [`try_lock`] methods on [`RecursiveMutex`].
///
/// Due to the lifetime 'a becoming associated with the FastMutex's lifetime when FastMutexGuard is
/// instantiated via  [`lock`] and [`try_lock`], the compiler prohibits dropping the Mutex while
/// still retaining the FastMutexGuard, preventing it from becoming a dangling pointer.

/// [`lock`]: RecursiveMutex::lock
/// [`try_lock`]: RecursiveMutex::try_lock
pub struct RecursiveMutexGuard<'a, T: 'a + ?Sized> {
    pub(crate) lock: &'a KMUTEX,
    pub(crate) data: &'a mut T,
    pub(crate) poison: &'a Flag,
}

impl<'a, T: ?Sized> Drop for RecursiveMutexGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { KeReleaseMutex(&*self.lock as *const _ as *mut _, FALSE) };
    }
}

impl<'a, T: ?Sized> Deref for RecursiveMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.data
    }
}

impl<'a, T: ?Sized> DerefMut for RecursiveMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.data
    }
}

pub fn guard_poison<'a, T: ?Sized>(guard: &'a RecursiveMutexGuard<T>) -> &'a Flag {
    &guard.poison
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct WaitTimeoutResult(pub bool);

impl WaitTimeoutResult {
    /// Returns `true` if the wait was known to have timed out.
    ///
    /// # Examples
    ///
    /// This example spawns a thread which will update the boolean value and
    /// then wait 100 milliseconds before notifying the condvar.
    ///
    /// The main thread will wait with a timeout on the condvar and then leave
    /// once the boolean has been updated and notified.
    ///
    /// ```
    /// use std::sync::{Arc, Condvar, Mutex};
    /// use std::thread;
    /// use std::time::Duration;
    ///
    /// let pair = Arc::new((Mutex::new(false), Condvar::new()));
    /// let pair2 = Arc::clone(&pair);
    ///
    /// thread::spawn(move || {
    ///     let (lock, cvar) = &*pair2;
    ///
    ///     // Let's wait 20 milliseconds before notifying the condvar.
    ///     thread::sleep(Duration::from_millis(20));
    ///
    ///     let mut started = lock.lock().unwrap();
    ///     // We update the boolean value.
    ///     *started = true;
    ///     cvar.notify_one();
    /// });
    ///
    /// // Wait for the thread to start up.
    /// let (lock, cvar) = &*pair;
    /// let mut started = lock.lock().unwrap();
    /// loop {
    ///     // Let's put a timeout on the condvar's wait.
    ///     let result = cvar.wait_timeout(started, Duration::from_millis(10)).unwrap();
    ///     // 10 milliseconds have passed, or maybe the value changed!
    ///     started = result.0;
    ///     if *started == true {
    ///         // We received the notification and the value has been updated, we can leave.
    ///         break;
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.0
    }
}

#[derive(Debug)]
pub struct Flag {
    failed: AtomicBool,
}

impl Flag {
    #[inline]
    pub const fn new() -> Flag {
        Flag {
            failed: AtomicBool::new(false),
        }
    }

    /// Check the flag for an unguarded borrow, where we only care about existing poison.
    #[inline]
    pub fn borrow(&self) -> LockResult<()> {
        if self.get() {
            Err(Error::NONCONTINUABLE_EXCEPTION)
        } else {
            Ok(())
        }
    }

    /// Check the flag for a guarded borrow, where we may also set poison when `done`.
    #[inline]
    pub fn guard(&self) -> LockResult<Guard> {
        let ret = Guard { panicking: false };
        if self.get() {
            Err(Error::NONCONTINUABLE_EXCEPTION)
        } else {
            Ok(ret)
        }
    }

    #[inline]
    pub fn done(&self, guard: &Guard) {
        if !guard.panicking && !false {
            self.failed.store(true, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn get(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn clear(&self) {
        self.failed.store(false, Ordering::Relaxed)
    }
}

pub struct Guard {
    panicking: bool,
}

pub struct PoisonError<T> {
    guard: T,
}

impl<T> fmt::Debug for PoisonError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoisonError").finish_non_exhaustive()
    }
}

impl<T> fmt::Display for PoisonError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        core::fmt::Display::fmt(&"poisoned lock: another task failed inside", f)
    }
}

impl<T> PoisonError<T> {
    /// Creates a `PoisonError`.
    ///
    /// This is generally created by methods like [`Mutex::lock`](crate::sync::Mutex::lock)
    /// or [`RwLock::read`](crate::sync::RwLock::read).
    pub fn new(guard: T) -> PoisonError<T> {
        PoisonError { guard }
    }

    /// Consumes this error indicating that a lock is poisoned, returning the
    /// underlying guard to allow access regardless.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    /// use std::sync::{Arc, Mutex};
    /// use std::thread;
    ///
    /// let mutex = Arc::new(Mutex::new(HashSet::new()));
    ///
    /// // poison the mutex
    /// let c_mutex = Arc::clone(&mutex);
    /// let _ = thread::spawn(move || {
    ///     let mut data = c_mutex.lock().unwrap();
    ///     data.insert(10);
    ///     panic!();
    /// }).join();
    ///
    /// let p_err = mutex.lock().unwrap_err();
    /// let data = p_err.into_inner();
    /// println!("recovered {} items", data.len());
    /// ```
    pub fn into_inner(self) -> T {
        self.guard
    }

    /// Reaches into this error indicating that a lock is poisoned, returning a
    /// reference to the underlying guard to allow access regardless.
    pub fn get_ref(&self) -> &T {
        &self.guard
    }

    /// Reaches into this error indicating that a lock is poisoned, returning a
    /// mutable reference to the underlying guard to allow access regardless.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

pub type LockResult<Guard> = Result<Guard, Error>;
