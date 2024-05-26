use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::cell::SyncUnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::sync::atomic::Ordering::{Acquire, Release, SeqCst};
use core::task::{Context, Poll, Waker};

use cooked_waker::IntoWaker;
pub use cooked_waker::WakeRef;
use crossbeam_queue::ArrayQueue;
use futures::pin_mut;
use futures_channel::oneshot;

use crate::asynk::wsk::{CCOUNTER, Event, PCCOUNTER, PSRCOUNTER, SRCOUNTER};
use crate::{Error, println};
use crate::sync::condvar::Condvar2;
use crate::sync::dashmap::DashMap;
use crate::sync::mutex::RecursiveMutex;
use crate::sync::once_lock::OnceLock;


#[derive(Default)]
pub struct Notifier {
    was_notified: Arc<AtomicBool>,
    cv: Condvar2,
}

impl Notifier {
    fn wait(&self) {
        while !self.was_notified.load(Acquire) {
            self.cv.wait(self.was_notified.clone());
        }
        self.was_notified.store(false, Release);
    }
}

impl WakeRef for Notifier {
    fn wake_by_ref(&self) {
        let was_notified = self.was_notified.swap(true, Release);

        if !was_notified {
            self.cv.notify_one();
        }
    }
}

unsafe impl Sync for Notifier {}

unsafe impl Send for Notifier {}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(usize);

impl TaskId {
    pub fn new() -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        TaskId(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

pub struct Task {
    state: AtomicUsize,
    id: TaskId,
    future: Pin<Box<dyn Future<Output = ()>>>,
}

impl Task {
    pub fn new(future: impl Future<Output = ()> + 'static) -> Task {
        Task {
            state: AtomicUsize::new(INIT),
            id: TaskId::new(),
            future: Box::pin(future),
        }
    }

    fn poll(&mut self, context: &mut Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}

const INIT: usize = 99;
const SPAWNED: usize = 0;
const IN_PROGRESS: usize = 1;
const COMPLETED: usize = 2;

impl Drop for Task {
    fn drop(&mut self) {
        if self.state.load(Acquire) == IN_PROGRESS {}
    }
}

pub struct Executor {
    tasks: RecursiveMutex<BTreeMap<TaskId, Task>>,
    task_queue: Arc<ArrayQueue<TaskId>>,
    waker_cache: DashMap<TaskId, Waker>,
    notifier: Arc<Notifier>,
    exit: Arc<AtomicBool>,
}

type JoinHandle<R> = Pin<Box<dyn Future<Output = R>>>;

pub static EXECUTOR: OnceLock<SyncUnsafeCell<Option<Executor>>> = OnceLock::new();

pub fn init_executor() {
    EXECUTOR.get_or_init(|| SyncUnsafeCell::new(Some(Executor::new())));
}

pub fn get_executor() -> &'static Executor {
    unsafe {
        EXECUTOR
            .get_or_init(|| SyncUnsafeCell::new(Some(Executor::new())))
            .get()
            .as_ref()
            .unwrap_unchecked()
            .as_ref()
            .unwrap_unchecked()
    }
}

pub fn deinit_executor() {
    {
        unsafe {
            EXECUTOR
                .get_or_init(|| SyncUnsafeCell::new(Some(Executor::new())))
                .get()
                .as_mut()
                .map(|executor_opt| executor_opt.take());
            //drop((*EXECUTOR.get().unwrap_unchecked().get()).take());
        }
    }
    let total = PSRCOUNTER.load(Acquire);
    println!("pre s/r: {total}");
    let total = SRCOUNTER.load(Acquire);
    println!("s/r: {total}");
    let total = PCCOUNTER.load(Acquire);
    println!("pre c: {total}");
    let total = CCOUNTER.load(Acquire);
    println!("c: {total}");
}

pub fn spawn<F, R>(future: F) -> Result<JoinHandle<R>, Error>
where
    F: Future<Output = R> + 'static,
    R: 'static,
{
    get_executor().spawn(future)
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    get_executor().block_on(future)
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            tasks: RecursiveMutex::new(BTreeMap::new()),
            task_queue: Arc::new(ArrayQueue::new(500_000)),
            waker_cache: DashMap::new(),
            notifier: Arc::new(Notifier::default()),
            exit: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn notifier(&self) -> Arc<Notifier> {
        self.notifier.clone()
    }

    pub fn signal(&self) -> Arc<AtomicBool> {
        self.exit.clone()
    }

    pub fn spawn<F, R>(&self, future: F) -> Result<JoinHandle<R>, Error>
    where
        F: Future<Output = R> + 'static,
        R: 'static,
    {
        if !self.exit.load(Acquire) {
            let (s, r) = oneshot::channel();
            let future = async move {
                let _ = s.send(future.await);
            };

            let task = Task::new(future);
            let id = task.id;
            task.state.store(SPAWNED, Release);

            assert!(
                self.tasks.lock().unwrap().insert(task.id, task).is_none(),
                "task with same ID already in tasks"
            );

            self.task_queue.push(id).expect("queue full");

            self.notifier.wake_by_ref(); // Executor thread is sleeping since driver_entry, and could be asleep if all spanwed tasks have completed already

            Ok(Box::pin(async { r.await.unwrap() }))
        } else {
            Err(Error::INSUFFICIENT_RESOURCES)
        }
    }

    fn run_ready_tasks(&self) {
        // destructure `self` to avoid borrow checker errors
        let Self {
            tasks,
            task_queue,
            waker_cache,
            notifier,
            exit,
        } = self;

        'queue: while let Some(task_id) = task_queue.pop() {
            {
                let mut guard = tasks.lock().unwrap();
                let Some(task) = guard.get_mut(&task_id) else {
                    continue;
                };

                let _ = task
                    .state
                    .compare_exchange(SPAWNED, IN_PROGRESS, Release, Acquire);
                let waker = waker_cache.entry(task_id).or_insert_with(|| {
                    TaskWaker::new(task_id, task_queue.clone(), notifier.clone())
                });
                let mut context = Context::from_waker(waker.value());

                match task.poll(&mut context) {
                    Poll::Ready(()) => {}
                    Poll::Pending => {
                        continue 'queue;
                    }
                }
            }
            COUNTER.fetch_add(1, SeqCst);
            // task done -> remove it and its cached waker
            self.tasks
                .lock()
                .unwrap()
                .remove(&task_id)
                .unwrap()
                .state
                .store(COMPLETED, Release);
            self.waker_cache.remove(&task_id);
        }
    }

    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        let notifier = self.notifier.clone();
        let waker = TaskWaker::new(TaskId::new(), self.task_queue.clone(), notifier.clone());
        let mut cx = Context::from_waker(&waker);

        pin_mut!(future);

        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }

            self.run_ready_tasks();

            if self.task_queue.is_empty() {
                notifier.wait();
            }
        }
    }

    pub fn run(&self) {
        loop {
            if self.exit.load(Acquire) {
                self.tasks.lock().unwrap().clear();

                for _ in 0..self.task_queue.len() {
                    self.task_queue.pop();
                }
                self.waker_cache.clear();
                //println!("quit now {}", COUNTER.load(Acquire));
                return;
            }
            self.run_ready_tasks();

            if self.task_queue.is_empty() {
                self.notifier.wait();
            }
        }
    }
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TaskWaker {
    task_id: TaskId,
    task_queue: Arc<ArrayQueue<TaskId>>,
    notifier: Arc<Notifier>,
}

impl TaskWaker {
    fn wake_task(&self) {
        match self.task_queue.push(self.task_id) {
            Ok(_) => self.notifier.clone().into_waker().wake(),
            Err(_) => {
                panic!()
            }
        }
    }

    fn new(
        task_id: TaskId,
        task_queue: Arc<ArrayQueue<TaskId>>,
        notifier: Arc<Notifier>,
    ) -> Waker {
        Waker::from(Arc::new(TaskWaker {
            task_id,
            task_queue,
            notifier,
        }))
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_task();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_task();
    }
}

pub static EVENT_MAP: OnceLock<SyncUnsafeCell<Option<DashMap<Event, Waker>>>> = OnceLock::new();

#[inline]
pub fn init_event_map() {
    EVENT_MAP.get_or_init(|| SyncUnsafeCell::new(Some(DashMap::new())));
}

#[inline]
pub fn get_event_map() -> &'static DashMap<Event, Waker> {
    unsafe {
        EVENT_MAP
            .get_or_init(|| SyncUnsafeCell::new(Some(DashMap::new())))
            .get()
            .as_ref()
            .unwrap_unchecked()
            .as_ref()
            .unwrap_unchecked()
    }
}

pub fn deinit_event_map() {
    get_event_map();
    unsafe {
        *EVENT_MAP.get().unwrap_unchecked().get() = None;
    }
}

pub mod naive {
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::future::Future;
    use core::mem;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    use cooked_waker::IntoWaker;
    pub use cooked_waker::WakeRef;

    use crate::sync::condvar::Condvar;
    use crate::sync::fast_mutex::FastMutex;

    impl WakeRef for Notifier {
        fn wake_by_ref(&self) {
            let was_notified = {
                let mut guard = self.was_notified.lock().unwrap();
                mem::replace(&mut *guard, true)
            };

            if !was_notified {
                self.cv.notify_one();
            }
        }
    }

    #[derive(Debug)]
    pub struct Yield {
        pub yielded: bool,
    }

    impl Future for Yield {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    #[derive(Default)]
    pub struct Notifier {
        was_notified: Arc<FastMutex<bool>>,
        cv: Condvar,
    }

    impl Notifier {
        fn wait(&self) {
            let mut was_notified = self.was_notified.lock().unwrap();

            while !*was_notified {
                drop(was_notified);
                was_notified = self.cv.wait(self.was_notified.lock().unwrap()).unwrap();
            }

            *was_notified = false;
        }
    }

    unsafe impl Sync for Notifier {}

    unsafe impl Send for Notifier {}


    pub fn run_future<F: Future>(future: F) -> F::Output {
        let mut future = future;
        // Shadow the original binding so that it can't be directly accessed
        // ever again.
        #[allow(unused_mut)]
            let mut future = unsafe { Pin::new_unchecked(&mut future) };

        let notifier = Arc::new(Notifier::default());
        let waker = notifier.clone().into_waker();
        let mut cx = Context::from_waker(&waker);

        loop {
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(output) => {
                    return output;
                }
                Poll::Pending => {
                    notifier.wait();
                }
            }
        }
    }

    pub fn run_futures<F: Future>(mut future: Vec<F>) -> Vec<<F as Future>::Output> {
        let notifier = Arc::new(Notifier::default());
        let waker = notifier.clone().into_waker();
        let mut cx = Context::from_waker(&waker);

        let mut idx = vec![];
        let total = future.len();
        let mut res = vec![];

        loop {
            if idx.len() == total {
                break;
            }
            for i in 0..total {
                if idx.contains(&i) {
                    continue;
                }
                // Shadow the original binding so that it can't be directly accessed
                // ever again.
                #[allow(unused_mut)]
                    let mut future = unsafe { Pin::new_unchecked(&mut future[i]) };
                match future.poll(&mut cx) {
                    Poll::Ready(output) => {
                        idx.push(i);
                        res.push(output);
                    }
                    Poll::Pending => {
                        notifier.wait();
                    }
                }
            }
        }
        res
    }}
