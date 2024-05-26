// Copyright 2017 Amanieu d'Antras
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use alloc::collections::BinaryHeap;
use core::cell::SyncUnsafeCell;
use core::cmp::Reverse;

use crossbeam::atomic::AtomicCell;

use crate::sync::dashmap::DashMap;
use crate::sync::once_lock::OnceLock;
use crate::sync::thread;
use crate::sync::thread_local::lib::POINTER_WIDTH;
use crate::sync::Mutex;

/// Thread ID manager which allocates thread IDs. It attempts to aggressively
/// reuse thread IDs where possible to avoid cases where a ThreadLocal grows
/// indefinitely when it is used by many short-lived threads.
pub(crate) struct ThreadIdManager {
    free_from: usize,
    free_list: BinaryHeap<Reverse<usize>>,
}

impl ThreadIdManager {
    fn new() -> Self {
        Self {
            free_from: 0,
            free_list: BinaryHeap::new(),
        }
    }
    fn alloc(&mut self) -> usize {
        if let Some(id) = self.free_list.pop() {
            id.0
        } else {
            // `free_from` can't overflow as each thread takes up at least 2 bytes of memory and
            // thus we can't even have `usize::MAX / 2 + 1` threads.

            let id = self.free_from;
            self.free_from += 1;
            id
        }
    }
    fn free(&mut self, id: usize) {
        self.free_list.push(Reverse(id));
    }
}

static THREAD_ID_MANAGER: OnceLock<SyncUnsafeCell<Option<Mutex<Option<ThreadIdManager>>>>> =
    OnceLock::new();

#[inline]
fn get_THREAD_ID_MANAGER() -> &'static SyncUnsafeCell<Option<Mutex<Option<ThreadIdManager>>>> {
    THREAD_ID_MANAGER
        .get_or_init(|| SyncUnsafeCell::new(Some(Mutex::new(Some(ThreadIdManager::new())))))
}

/// Data which is unique to the current thread while it is running.
/// A thread ID may be reused after a thread exits.
#[derive(Clone, Copy)]
pub(crate) struct Thread {
    /// The thread ID obtained from the thread ID manager.
    pub(crate) id: usize,
    /// The bucket this thread's local storage will be in.
    pub(crate) bucket: usize,
    /// The size of the bucket this thread's local storage will be in.
    pub(crate) bucket_size: usize,
    /// The index into the bucket this thread's local storage is in.
    pub(crate) index: usize,
}

impl Thread {
    fn new(id: usize) -> Self {
        let bucket = usize::from(POINTER_WIDTH) - ((id + 1).leading_zeros() as usize) - 1;
        let bucket_size = 1 << bucket;
        let index = id - (bucket_size - 1);

        Self {
            id,
            bucket,
            bucket_size,
            index,
        }
    }
}

// This is split into 2 thread-local variables so that we can check whether the
// thread is initialized without having to register a thread-local destructor.
//
// This makes the fast path smaller.

static THREAD: OnceLock<SyncUnsafeCell<Option<DashMap<usize, AtomicCell<Option<Thread>>>>>> =
    OnceLock::new();
static THREAD_GUARD: OnceLock<SyncUnsafeCell<Option<DashMap<usize, ThreadGuard>>>> =
    OnceLock::new();

#[inline]
fn get_THREAD() -> &'static SyncUnsafeCell<Option<DashMap<usize, AtomicCell<Option<Thread>>>>> {
    THREAD.get_or_init(|| SyncUnsafeCell::new(Some(DashMap::new())))
}

#[inline]
fn get_THREAD_GUARD() -> &'static SyncUnsafeCell<Option<DashMap<usize, ThreadGuard>>> {
    THREAD_GUARD.get_or_init(|| SyncUnsafeCell::new(Some(DashMap::new())))
}

// Guard to ensure the thread ID is released on thread exit.
pub(crate) struct ThreadGuard {
    // We keep a copy of the thread ID in the ThreadGuard: we can't
    // reliably access THREAD in our Drop impl due to the unpredictable
    // order of TLS destructors.
    id: AtomicCell<usize>,
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        // Release the thread ID. Any further accesses to the thread ID
        // will go through get_slow which will either panic or
        // initialize a new ThreadGuard.
        //let thread = unsafe {THREAD.get().as_ref().unwrap().as_ref().unwrap().get(&thread::current_id()).unwrap()};
        //thread.store(None);
        //unsafe {THREAD_ID_MANAGER.lock().unwrap().as_mut().unwrap().free(self.id.load())};
    }
}

/// Returns a thread ID for the current thread, allocating one if needed.
#[inline]
pub(crate) fn get() -> Thread {
    let id = thread::current_id();
    let thread = unsafe {
        if get_THREAD()
            .get()
            .as_ref()
            .unwrap_unchecked()
            .as_ref()
            .unwrap_unchecked()
            .contains_key(&id)
        {
            get_THREAD()
                .get()
                .as_ref()
                .unwrap_unchecked()
                .as_ref()
                .unwrap_unchecked()
                .get(&id)
                .unwrap_unchecked()
        } else {
            get_THREAD()
                .get()
                .as_ref()
                .unwrap_unchecked()
                .as_ref()
                .unwrap_unchecked()
                .insert(id, AtomicCell::new(None));
            get_THREAD()
                .get()
                .as_ref()
                .unwrap_unchecked()
                .as_ref()
                .unwrap_unchecked()
                .get(&id)
                .unwrap_unchecked()
        }
    };
    if let Some(thread) = thread.load() {
        thread
    } else {
        get_slow(thread.value(), id)
    }
}

/// Out-of-line slow path for allocating a thread ID.
#[cold]
fn get_slow(thread: &AtomicCell<Option<Thread>>, id: usize) -> Thread {
    let new = Thread::new(unsafe {
        get_THREAD_ID_MANAGER()
            .get()
            .as_ref()
            .unwrap_unchecked()
            .as_ref()
            .unwrap_unchecked()
            .lock()
            .unwrap_unchecked()
            .as_mut()
            .unwrap_unchecked()
            .alloc()
    });
    thread.store(Some(new));
    let guard = unsafe {
        if get_THREAD_GUARD()
            .get()
            .as_ref()
            .unwrap_unchecked()
            .as_ref()
            .unwrap()
            .contains_key(&id)
        {
            get_THREAD_GUARD()
                .get()
                .as_ref()
                .unwrap_unchecked()
                .as_ref()
                .unwrap_unchecked()
                .get(&id)
                .unwrap()
        } else {
            get_THREAD_GUARD()
                .get()
                .as_ref()
                .unwrap_unchecked()
                .as_ref()
                .unwrap_unchecked()
                .insert(
                    id,
                    ThreadGuard {
                        id: AtomicCell::new(id),
                    },
                );
            get_THREAD_GUARD()
                .get()
                .as_ref()
                .unwrap_unchecked()
                .as_ref()
                .unwrap_unchecked()
                .get(&id)
                .unwrap_unchecked()
        }
    };

    guard.id.store(new.id);
    new
}

pub fn deinit() {
    unsafe {
        {
            let mut current = None;
            core::mem::swap(&mut current, &mut *get_THREAD().get());
            *get_THREAD().get() = None;
        }
        {
            let mut current = None;
            core::mem::swap(&mut current, &mut *get_THREAD_ID_MANAGER().get());
            *get_THREAD_ID_MANAGER().get() = None;
        }

        let mut current = None;
        core::mem::swap(&mut current, &mut *get_THREAD_GUARD().get());
        *get_THREAD_GUARD().get() = None;
    }
}
