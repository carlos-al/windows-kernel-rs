use alloc::boxed::Box;
use alloc::fmt;
use alloc::sync::Arc;
use core::ffi::c_void;
use core::ptr::null_mut;
use core::sync::atomic::AtomicBool;
use core::time::Duration;

use windows_kernel_sys::base::_EVENT_TYPE::SynchronizationEvent;
use windows_kernel_sys::base::_KWAIT_REASON::Executive;
use windows_kernel_sys::base::_MODE::KernelMode;
use windows_kernel_sys::base::{
    _DISPATCHER_HEADER__bindgen_ty_1, _DISPATCHER_HEADER__bindgen_ty_1__bindgen_ty_7, FALSE,
    FAST_MUTEX, IO_NO_INCREMENT, KEVENT, KPRIORITY, KPROCESSOR_MODE, LARGE_INTEGER, LONGLONG,
    _DISPATCHER_HEADER, _LIST_ENTRY,
};
use windows_kernel_sys::netio::KeClearEvent;
use windows_kernel_sys::ntoskrnl::{
    ExAcquireFastMutex, ExReleaseFastMutex, KeInitializeEvent, KeSetEvent, KeWaitForSingleObject,
};

use crate::sync::fast_mutex::{
    guard_poison, FastMutex, FastMutexGuard, LockResult, WaitTimeoutResult,
};
use crate::sync::time::Instant;
use crate::Error;

pub struct Condvar {
    inner: KeCondVar,
}

pub struct KeCondVar {
    pub event: Box<KEVENT>,
}

pub struct Condvar2 {
    inner: KeCondVar2,
}

pub struct KeCondVar2 {
    pub event: Box<KEVENT>,
}

impl KeCondVar2 {
    pub fn new() -> Self {
        let mut event = Box::new(KEVENT {
            Header: _DISPATCHER_HEADER {
                __bindgen_anon_1: _DISPATCHER_HEADER__bindgen_ty_1 {
                    __bindgen_anon_7: _DISPATCHER_HEADER__bindgen_ty_1__bindgen_ty_7 {
                        MutantType: 0,
                        MutantSize: 0,
                        DpcActive: 0,
                        MutantReserved: 0,
                    },
                },
                SignalState: 0,
                WaitListHead: _LIST_ENTRY {
                    Flink: null_mut(),
                    Blink: null_mut(),
                },
            },
        });
        unsafe { KeInitializeEvent(&mut *event, SynchronizationEvent, FALSE) };
        Self { event }
    }

    pub fn wait(&self, guard: Arc<AtomicBool>) {
        unsafe {
            KeWaitForSingleObject(
                &*self.event as *const _ as *mut _,
                Executive,
                KernelMode as KPROCESSOR_MODE,
                FALSE,
                null_mut(),
            );
        }

        unsafe {
            KeClearEvent(&*self.event as *const _ as *mut _);
        }
    }

    pub fn wait_timeout(&self, guard: Arc<AtomicBool>, dur: Duration) -> bool {
        let mut timeout = LARGE_INTEGER {
            QuadPart: -(dur.as_nanos() as i64 / 100) as LONGLONG,
        };
        let status = unsafe {
            KeWaitForSingleObject(
                &*self.event as *const _ as *mut c_void,
                Executive,
                KernelMode as KPROCESSOR_MODE,
                FALSE,
                &mut timeout as *mut _,
            )
        };
        unsafe {
            KeClearEvent(&*self.event as *const _ as *mut _);
        }
        return if status == 0 { true } else { false };
    }

    #[inline]
    pub fn notify_one(&self) {
        unsafe {
            KeSetEvent(
                &*self.event as *const _ as _,
                IO_NO_INCREMENT as KPRIORITY,
                FALSE,
            )
        };
    }

    #[inline]
    pub fn notify_all(&self) {
        unsafe {
            KeSetEvent(
                &*self.event as *const _ as _,
                IO_NO_INCREMENT as KPRIORITY,
                FALSE,
            )
        };
    }
}

impl KeCondVar {
    pub fn new() -> Self {
        let mut event = Box::new(KEVENT {
            Header: _DISPATCHER_HEADER {
                __bindgen_anon_1: _DISPATCHER_HEADER__bindgen_ty_1 {
                    __bindgen_anon_7: _DISPATCHER_HEADER__bindgen_ty_1__bindgen_ty_7 {
                        MutantType: 0,
                        MutantSize: 0,
                        DpcActive: 0,
                        MutantReserved: 0,
                    },
                },
                SignalState: 0,
                WaitListHead: _LIST_ENTRY {
                    Flink: null_mut(),
                    Blink: null_mut(),
                },
            },
        });
        unsafe { KeInitializeEvent(&mut *event, SynchronizationEvent, FALSE) };
        Self { event }
    }

    pub fn wait(&self, guard: &FAST_MUTEX) {
        unsafe {
            ExReleaseFastMutex(&*guard as *const _ as *mut _);

            KeWaitForSingleObject(
                &*self.event as *const _ as *mut _,
                Executive,
                KernelMode as KPROCESSOR_MODE,
                FALSE,
                null_mut(),
            );
        }

        unsafe {
            KeClearEvent(&*self.event as *const _ as *mut _);
        }
        unsafe { ExAcquireFastMutex(&*guard as *const _ as *mut _) };
    }

    pub fn wait_timeout(&self, guard: &FAST_MUTEX, dur: Duration) -> bool {
        let mut timeout = LARGE_INTEGER {
            QuadPart: -(dur.as_nanos() as i64 / 100) as LONGLONG,
        };
        unsafe { ExReleaseFastMutex(&*guard as *const _ as *mut _) };
        let status = unsafe {
            KeWaitForSingleObject(
                &*self.event as *const _ as *mut c_void,
                Executive,
                KernelMode as KPROCESSOR_MODE,
                FALSE,
                &mut timeout as *mut _,
            )
        };
        unsafe {
            KeClearEvent(&*self.event as *const _ as *mut _);
        }
        unsafe { ExAcquireFastMutex(&*guard as *const _ as *mut _) };
        return if status == 0 { true } else { false };
    }

    #[inline]
    pub fn notify_one(&self) {
        unsafe {
            KeSetEvent(
                &*self.event as *const _ as _,
                IO_NO_INCREMENT as KPRIORITY,
                FALSE,
            )
        };
    }

    #[inline]
    pub fn notify_all(&self) {
        unsafe {
            KeSetEvent(
                &*self.event as *const _ as _,
                IO_NO_INCREMENT as KPRIORITY,
                FALSE,
            )
        };
    }
}

impl Condvar {
    #[must_use]
    #[inline]
    pub fn new() -> Condvar {
        Condvar {
            inner: KeCondVar::new(),
        }
    }

    pub fn wait<'a, T>(&self, guard: FastMutexGuard<'a, T>) -> LockResult<FastMutexGuard<'a, T>> {
        self.inner.wait(guard.lock);

        let poisoned = guard_poison(&guard).get();
        if poisoned {
            Err(Error::NONCONTINUABLE_EXCEPTION)
        } else {
            Ok(guard)
        }
    }

    pub fn wait_while<'a, T, F>(
        &self,
        mut guard: FastMutexGuard<'a, T>,
        mut condition: F,
    ) -> LockResult<FastMutexGuard<'a, T>>
    where
        F: FnMut(&mut T) -> bool,
    {
        while condition(&mut *guard) {
            guard = self.wait(guard)?;
        }
        Ok(guard)
    }

    pub fn wait_timeout<'a, T>(
        &self,
        guard: FastMutexGuard<'a, T>,
        dur: Duration,
    ) -> LockResult<(FastMutexGuard<'a, T>, WaitTimeoutResult)> {
        let (poisoned, result) = {
            let success = self.inner.wait_timeout(guard.lock, dur);
            (FastMutex::guard_poison(&guard), WaitTimeoutResult(!success))
        };
        if poisoned.get() {
            Err(Error::NONCONTINUABLE_EXCEPTION)
        } else {
            Ok((guard, result))
        }
    }

    pub fn wait_timeout_while<'a, T, F>(
        &self,
        mut guard: FastMutexGuard<'a, T>,
        dur: Duration,
        mut condition: F,
    ) -> LockResult<(FastMutexGuard<'a, T>, WaitTimeoutResult)>
    where
        F: FnMut(&FastMutexGuard<'a, T>) -> bool,
    {
        let start = Instant::now();
        loop {
            if !condition(&guard) {
                return Ok((guard, WaitTimeoutResult(false)));
            }
            let timeout = match dur.checked_sub(start.elapsed()) {
                Some(timeout) => timeout,
                None => return Ok((guard, WaitTimeoutResult(true))),
            };
            guard = self.wait_timeout(guard, timeout)?.0;
        }
    }

    pub fn notify_one(&self) {
        self.inner.notify_one()
    }

    pub fn notify_all(&self) {
        self.inner.notify_all()
    }
}

impl fmt::Debug for Condvar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Condvar").finish_non_exhaustive()
    }
}

impl Default for Condvar {
    /// Creates a `Condvar` which is ready to be waited on and notified.
    fn default() -> Condvar {
        Condvar::new()
    }
}

impl Condvar2 {
    #[must_use]
    #[inline]
    pub fn new() -> Condvar2 {
        Condvar2 {
            inner: KeCondVar2::new(),
        }
    }

    pub fn wait(&self, guard: Arc<AtomicBool>) {
        self.inner.wait(guard);
    }

    /*    pub fn wait_timeout<'a, T>(
        &self,
        guard: FastMutexGuard<'a, T>,
        dur: Duration,
    ) -> LockResult<(FastMutexGuard<'a, T>, WaitTimeoutResult)> {
        let (poisoned, result) = {
            let success = self.inner.wait_timeout(guard.lock, dur);
            (FastMutex::guard_poison(&guard), WaitTimeoutResult(!success))
        };
        if poisoned.get() {
            Err(Error::NONCONTINUABLE_EXCEPTION)
        } else {
            Ok((guard, result))
        }
    }*/

    pub fn notify_one(&self) {
        self.inner.notify_one()
    }

    pub fn notify_all(&self) {
        self.inner.notify_all()
    }
}

impl fmt::Debug for Condvar2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Condvar").finish_non_exhaustive()
    }
}

impl Default for Condvar2 {
    /// Creates a `Condvar` which is ready to be waited on and notified.
    fn default() -> Condvar2 {
        Condvar2::new()
    }
}
