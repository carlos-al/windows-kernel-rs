use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::SyncUnsafeCell;
use core::ffi::c_void;
use core::mem;
use core::pin::Pin;
use core::ptr::{addr_of, addr_of_mut, null_mut};
use core::sync::atomic::AtomicI8;
use core::sync::atomic::Ordering::{Acquire, Release};
use core::time::Duration;

use windows_kernel_sys::base::_KWAIT_REASON::Executive;
use windows_kernel_sys::base::_MODE::KernelMode;
use windows_kernel_sys::base::{
    FALSE, HANDLE, KPROCESSOR_MODE, LARGE_INTEGER, NTSTATUS, PKTHREAD, PVOID, STATUS_SUCCESS,
    SYNCHRONIZE,
};
use windows_kernel_sys::ntoskrnl::{
    KeDelayExecutionThread, KeWaitForSingleObject, ObReferenceObjectByHandleWithTag,
    ObReferenceObjectByPointerWithTag, ObfDereferenceObjectWithTag, PsCreateSystemThread,
    PsGetCurrentThread, PsGetThreadId, ZwClose,
};

use crate::sync::condvar::Condvar;
use crate::sync::dashmap::DashMap;
use crate::sync::once_lock::OnceLock;
use crate::{println, Error, Mutex};

//TODO: Fix Thread/thread fn location

pub struct Inner {
    handle: HANDLE,
    object: PKTHREAD,
    parker: Parker,
}

unsafe impl Sync for Inner {}

unsafe impl Send for Inner {}

pub struct Thread {
    inner: Pin<Arc<Inner>>,
    current: bool, // PsCreateSystemThread is called when spawning a thread, to fill in the Inner struct. We need to ZwClose its handle when dropping the struct if so. A Thread is also instantiated in other ways, see  from_id()/current_thread() or the THREADS static variable. PsGetThreadId() does not return an actual handle. You should not ZwClose the handle in Inner when dropping Threads instantiated these ways.
}

impl AsRef<Thread> for Thread {
    fn as_ref(&self) -> &Thread {
        &self
    }
}

pub fn deinit_THREADS() {
    let mut current = None;
    unsafe {
        mem::swap(&mut current, &mut *get_THREADS().get());
    }
    unsafe {
        *THREADS.get().unwrap_unchecked().get() = None;
    }
}

// The Inner representation of a Thread may be used by several Threads at the same time (i.e. to reference the same thread)
static THREADS: OnceLock<SyncUnsafeCell<Option<DashMap<usize, Option<Pin<Arc<Inner>>>>>>> =
    OnceLock::new();

#[inline]
pub fn get_THREADS() -> &'static SyncUnsafeCell<Option<DashMap<usize, Option<Pin<Arc<Inner>>>>>> {
    THREADS.get_or_init(|| SyncUnsafeCell::new(Some(DashMap::new())))
}

// To be used in tandem with Thread::current_thread() at any non-spawn()ed thread entry/exit points (i.e at IOCTL calls)
pub unsafe fn delete_THREAD() {
    let map = get_THREADS().get().as_ref().unwrap().as_ref().unwrap();
    let object = unsafe { PsGetCurrentThread() };
    let handle = unsafe { PsGetThreadId(object) };
    let id = handle as usize;

    match map.get(&id) {
        Some(a) => {
            drop(a);
            map.remove(&id);
            map.insert(id, None);
        }
        None => {}
    };
}

impl Thread {
    pub fn spawn_inner(p: Box<dyn FnOnce()>) -> Result<Thread, Error> {
        let p = Box::into_raw(Box::new(p));
        let mut handle: HANDLE = null_mut();
        let mut object: PKTHREAD = null_mut();
        let ret = unsafe {
            PsCreateSystemThread(
                &mut handle,
                SYNCHRONIZE,
                null_mut(),
                null_mut(),
                null_mut(),
                Some(thread_start),
                p as *mut _,
            )
        };
        unsafe {
            return if ret == 0 {
                let ret = ObReferenceObjectByHandleWithTag(
                    handle,
                    SYNCHRONIZE,
                    null_mut(),
                    KernelMode as _,
                    0xabcd,
                    &mut object as *mut _ as _,
                    null_mut(),
                );
                if ret == 0 {
                    let id = handle as usize;
                    let event = Condvar::new();
                    let lock = Mutex::new(());
                    let inner = {
                        let mut arc = Arc::<Inner>::new_uninit();
                        let ptr = Arc::get_mut_unchecked(&mut arc).as_mut_ptr();
                        addr_of_mut!((*ptr).object).write(object);
                        addr_of_mut!((*ptr).handle).write(handle);
                        Parker::new_in_place(addr_of_mut!((*ptr).parker), id, event, lock);
                        Pin::new_unchecked(arc.assume_init())
                    };

                    get_THREADS()
                        .get()
                        .as_ref()
                        .unwrap()
                        .as_ref()
                        .unwrap()
                        .insert(id, Some(inner.clone()));

                    Ok(Thread {
                        inner,
                        current: false,
                    })
                } else {
                    ZwClose(handle);
                    drop(Box::from_raw(p));
                    Err(Error::from_ntstatus(ret))
                }
            } else {
                // The thread failed to start and as a result p was not consumed. Therefore, it is
                // safe to reconstruct the box so that it gets deallocated.
                drop(Box::from_raw(p));
                Err(Error::from_ntstatus(ret))
            };
        }

        extern "C" fn thread_start(main: *mut c_void) {
            unsafe {
                Box::from_raw(main as *mut Box<dyn FnOnce()>)();

                // once the spawned thread is about to exit, remove it from the thread map
                let map = get_THREADS().get().as_ref().unwrap().as_ref().unwrap();
                let object = unsafe { PsGetCurrentThread() };
                let handle = unsafe { PsGetThreadId(object) };
                let id = handle as usize;

                match map.get(&id) {
                    Some(a) => {
                        drop(a);
                        map.remove(&id);
                        map.insert(id, None);
                    }
                    None => {}
                };
            }
        }
    }

    pub fn spawn<F, T>(f: F) -> Result<Thread, Error>
    where
        F: FnOnce() -> T,
        F: Send + 'static,
        T: Send + 'static,
    {
        Thread::spawn_unchecked(f)
    }

    fn spawn_unchecked<'a, F, T>(f: F) -> Result<Thread, Error>
    where
        F: FnOnce() -> T,
        F: Send + 'a,
        T: Send + 'a,
    {
        unsafe {
            let a = mem::transmute::<Box<dyn FnOnce() -> T + 'a>, Box<dyn FnOnce() + 'static>>(
                Box::new(f),
            );
            Thread::spawn_inner(a)
        }
    }

    pub fn join(self) {
        let rc: NTSTATUS = unsafe {
            KeWaitForSingleObject(
                self.object() as _,
                Executive,
                KernelMode as KPROCESSOR_MODE,
                FALSE,
                null_mut(),
            )
        };
        if rc != STATUS_SUCCESS {
            println!("failed to join on thread: {:?}", Error::from_ntstatus(rc));
            //FIXME
        }
    }

    pub fn sleep(dur: Duration) {
        let delay = LARGE_INTEGER {
            QuadPart: -((dur.as_nanos() / 100) as i64),
        };
        unsafe {
            KeDelayExecutionThread(KernelMode as KPROCESSOR_MODE, FALSE, addr_of!(delay) as _)
        };
    }

    pub fn from_id(id: usize) -> Result<Thread, Error> {
        let handle = id as HANDLE;
        let mut object = null_mut();
        let ret = unsafe {
            ObReferenceObjectByHandleWithTag(
                handle,
                SYNCHRONIZE,
                null_mut(),
                KernelMode as _,
                0xabcd,
                &mut object as *mut _ as _,
                null_mut(),
            )
        };
        return if ret == 0 {
            let map = unsafe { get_THREADS().get().as_ref().unwrap().as_ref().unwrap() };
            let inner = map.get(&(id));

            let current: bool;
            let inner = match inner {
                None => {
                    let id = handle as usize;
                    let event = Condvar::new();
                    let lock = Mutex::new(());
                    current = true;
                    let a = unsafe {
                        let mut arc = Arc::<Inner>::new_uninit();
                        let ptr = Arc::get_mut_unchecked(&mut arc).as_mut_ptr();
                        addr_of_mut!((*ptr).object).write(object as _);
                        addr_of_mut!((*ptr).handle).write(handle);
                        Parker::new_in_place(addr_of_mut!((*ptr).parker), id, event, lock);
                        Pin::new_unchecked(arc.assume_init())
                    };
                    map.insert(id, Some(a.clone()));

                    a
                }
                Some(p) => {
                    current = true;
                    p.as_ref().unwrap().clone()
                }
            };

            Ok(Thread { inner, current })
        } else {
            Err(Error::from_ntstatus(ret))
        };
    }

    pub fn current_thread() -> Result<Thread, Error> {
        let object = unsafe { PsGetCurrentThread() };
        let handle = unsafe { PsGetThreadId(object) };
        let id = handle as usize;
        let ret = unsafe {
            ObReferenceObjectByPointerWithTag(
                object as _,
                SYNCHRONIZE,
                null_mut(),
                KernelMode as _,
                0xabcd,
            )
        };
        return if ret == 0 {
            let mut map = unsafe { get_THREADS().get().as_ref().unwrap().as_ref().unwrap() };
            let inner = map.get(&(id));

            let current: bool;
            let inner = match inner {
                None => {
                    let id = handle as usize;
                    let event = Condvar::new();
                    let lock = Mutex::new(());
                    current = true;
                    let inner = unsafe {
                        let mut arc = Arc::<Inner>::new_uninit();
                        let ptr = Arc::get_mut_unchecked(&mut arc).as_mut_ptr();
                        addr_of_mut!((*ptr).object).write(object);
                        addr_of_mut!((*ptr).handle).write(handle);
                        Parker::new_in_place(addr_of_mut!((*ptr).parker), id, event, lock);
                        Pin::new_unchecked(arc.assume_init())
                    };
                    map.insert(id, Some(inner.clone()));

                    inner
                }
                Some(p) => {
                    current = true;
                    p.as_ref().unwrap().clone()
                }
            };

            Ok(Thread { inner, current })
        } else {
            Err(Error::from_ntstatus(ret))
        };
    }

    pub fn handle(&self) -> HANDLE {
        Pin::into_inner(self.inner.clone()).handle
    }

    pub fn into_handle(self) -> HANDLE {
        Pin::into_inner(self.inner.clone()).handle
    }

    pub fn object(&self) -> PKTHREAD {
        Pin::into_inner(self.inner.clone()).object
    }

    pub fn into_object(self) -> PKTHREAD {
        Pin::into_inner(self.inner.clone()).object
    }

    pub fn parker(&self) -> Pin<&Parker> {
        Pin::as_ref(&self.inner).parker()
    }

    pub fn current_flag(&self) -> bool {
        self.current
    }

    pub fn park_timeout(dur: Duration) -> Result<(), Error> {
        // SAFETY: park_timeout is called on the parker owned by this thread.
        unsafe { current().as_ref().parker().park_timeout(dur) }

        Ok(())
    }

    pub fn unpark(&self) -> Result<(), Error> {
        self.inner.as_ref().parker().unpark();

        Ok(())
    }

    pub fn yield_now() {
        let mut wait = LARGE_INTEGER { QuadPart: 1 };
        unsafe {
            KeDelayExecutionThread(KernelMode as KPROCESSOR_MODE, FALSE, &mut wait);
        }
    }
}

pub fn current() -> Thread {
    Thread::current_thread().expect(
        "use of std::thread::current() is not possible \
         after the thread's local data has been destroyed",
    )
}

pub fn current_id() -> usize {
    let object = unsafe { PsGetCurrentThread() };
    let handle = unsafe { PsGetThreadId(object) };
    handle as usize
}

pub fn park() -> Result<(), Error> {
    unsafe {
        current().as_ref().parker().park();
    }
    Ok(())
}

impl Inner {
    fn parker(self: Pin<&Self>) -> Pin<&Parker> {
        unsafe { Pin::map_unchecked(self, |inner| &inner.parker) }
    }
}

pub struct Parker {
    state: AtomicI8,
    event: Condvar,
    lock: Mutex<()>,
    id: usize, //TODO: Unused field, compare with std's Parker again
}

const PARKED: i8 = -1;
const EMPTY: i8 = 0;
const NOTIFIED: i8 = 1;

impl Parker {
    pub unsafe fn new_in_place(parker: *mut Parker, id: usize, event: Condvar, lock: Mutex<()>) {
        parker.write(Self {
            state: AtomicI8::new(EMPTY),
            event,
            lock,
            id,
        });
    }

    // Assumes this is only called by the thread that owns the Parker,
    // which means that `self.state != PARKED`. This implementation doesn't require `Pin`,
    // but other implementations do.
    pub unsafe fn park(self: Pin<&Self>) {
        // Change NOTIFIED=>EMPTY or EMPTY=>PARKED, and directly return in the
        // first case.

        if self.state.fetch_sub(1, Acquire) == NOTIFIED {
            return;
        }
        let mut m = self.lock.lock().unwrap();

        loop {
            m = self.event.wait(m).unwrap();
            if self
                .state
                .compare_exchange(NOTIFIED, EMPTY, Acquire, Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    // Assumes this is only called by the thread that owns the Parker,
    // which means that `self.state != PARKED`. This implementation doesn't require `Pin`,
    // but other implementations do.
    pub unsafe fn park_timeout(self: Pin<&Self>, timeout: Duration) {
        // Change NOTIFIED=>EMPTY or EMPTY=>PARKED, and directly return in the
        // first case.
        if self.state.fetch_sub(1, Acquire) == NOTIFIED {
            return;
        }

        let m = self.lock.lock().unwrap();
        let (mut m, _) = self.event.wait_timeout(m, timeout).unwrap();

        let prev_state = self.state.swap(EMPTY, Acquire);

        if prev_state == NOTIFIED {
            // We were awoken by a timeout, not by unpark(), but the state
            // was set to NOTIFIED, which means we *just* missed an
            // unpark(), which is now blocked on us to wait for it.
            // Wait for it to consume the event and unblock that thread.
            m = self.event.wait(m).unwrap();
        }
    }

    // This implementation doesn't require `Pin`, but other implementations do.
    pub fn unpark(self: Pin<&Self>) {
        // Change PARKED=>NOTIFIED, EMPTY=>NOTIFIED, or NOTIFIED=>NOTIFIED, and
        // wake the thread in the first case.
        //
        // Note that even NOTIFIED=>NOTIFIED results in a write. This is on
        // purpose, to make sure every unpark() has a release-acquire ordering
        // with park().
        if self.state.swap(NOTIFIED, Release) == PARKED {
            drop(self.lock.lock().unwrap());
            self.event.notify_one();
        }
    }

    fn ptr(&self) -> PVOID {
        &self.state as *const _ as PVOID
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        unsafe {
            ObfDereferenceObjectWithTag(self.object() as _, 0xabcd);
            if !self.current_flag() {
                ZwClose(self.handle());
            }
        }
    }
}

unsafe impl Send for Thread {}

unsafe impl Sync for Thread {}
