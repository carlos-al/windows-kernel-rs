# Getting Started: Building and Running the Driver
## Prerequisites
- Windows Driver Kit (WDK): Follow steps 1-3 on the Microsoft
  documentation to install the WDK:
  https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

- LLVM: Download and install LLVM from this release page:   
  https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.1/LLVM-17.0.1-win64.exe



## Build Instructions:



- Clone the repository:

      git clone <repository-url>
- Configure Build:

      Open driver/Makefile.toml. Ensure the
      VC_BUILD_DIR variable points to the correct Visual Studio build tools
      directory. You should be able to use Visual Studio versions other
      than 2022 but YMMV.

- Build & Sign:


       cargo install cargo-make  
       rustup default nightly  
       cargo make sign

Important Note: This project was last built and tested with rustc 1.80.0-nightly (1ba35e9bb 2024-05-25). Newer nightly versions might have changes that could cause compilation errors.


# What is this?


This project is a continuation of S.J.R. van Schaik's work, which is documented on [this series](https://codentium.com/guides/windows-dev/windows-drivers-in-rust-prerequisites/) and the source code found on [here](https://github.com/StephanvanSchaik/windows-kernel-rs). As a Rust newcomer, I spent a few weeks familiarizing myself with the API implementation and building a rootkit driver to learn the ropes.

The initial focus was on creating the `sync::wsk` and `sync::berk` modules. The wsk module provides basic interactions with the Windows Sockets Kernel (WSK) subsystem, and the berk module builds a Berkeley sockets-like API on top of it.

Rust's limitations in the kernel context, such as the lack of C++--style exception handling and try blocks, posed challenges. For example, `MmProbeAndLockPages` can throw exceptions, and while workarounds exist, even the official Microsoft repository for Windows kernel development acknowledges this as an ongoing issue (with no response to date).

After implementing basic send/receive functionality, I reimplemented Rust's std `Thread` for the kernel environment. This custom implementation allows threads to be parked and unparked, accessed by ID, and handles object references without triggering Driver Verifier issues. It also ensures no memory leaks occur during driver loading or unloading, which is critical in kernel-mode development.

Inspired by the WSK's support for asynchronous operations, I took on the challenge of incorporating asynchronous I/O into an executor. While resources like the [Rust Async Book](https://rust-lang.github.io/async-book/) provided an initial foundation, they left many questions unanswered. Nathan West's [talk](https://www.youtube.com/watch?v=HrxwOUVzyDU) proved invaluable, although the final implementation in this project diverges and his example is included in a non-public module.

Implementing the async executor was more complex than anticipated. It required reimplementing missing types like `Condvar` and the channel API, which are essential for asynchronous communication. Additionally, the absence of Thread-Local Storage (TLS) in the Windows kernel posed a challenge that required creative solutions. To address this, the `thread_local` crate was adapted for the kernel environment, along with libraries like `parking_lot`, `dashmap`, and `scc`.

A major pain point throughout the development process was resolving memory leaks, particularly during driver unload. Careful attention to resource management and leak detection within tools like Driver Verifier was put.

Development on this project was paused on September 24th, at which point the core asynchronous executor and time-related futures from Nathan West's video had been successfully replicated. However, the final implementation in this repository diverges significantly from that initial reference.

Interestingly, Microsoft released their windows-drivers-rs repository https://github.com/microsoft/windows-drivers-rs on the 22nd. While this is a promising development, there are outstanding issues, like structured exception handling and the lack of specialized memory allocators, that are crucial for robust kernel-mode development in Rust.

Key resources that informed the design of the final executor include Phil Opp's  https://os.phil-opp.com/async-await/, Stjepang's (smol author) articles on [building](https://archive.softwareheritage.org/browse/content/sha1_git:c5dc3d72b157695b71b6fd62fb9e26e532bda418/?branch=HEAD&origin_url=https://github.com/stjepang/stjepang.github.io&path=_posts/2020-01-25-build-your-own-block-on.md&snapshot=8d270d1547a6c7aaa5d633da9190127b72a81cd4) [custom](https://archive.ph/n1PK9) executors, and the source code of established asynchronous Rust projects such as tokio, async_std, and smol. Following a forced hiatus in development, additional refinements were made over a couple of weeks in December to reach the current state of the repository.


# Examples


The following code snippet demonstrates how to perform an asynchronous network request using the driver:
```rust
    use windows_kernel::asynk::executor::{spawn};
    use windows_kernel::asynk::berk::{TcpSocket, TcpStream};
    use windows_kernel::sync::berk::Berk;
    use windows_kernel::{println, Error};

    async fn handle_connection(mut socket: TcpStream) {
        let mut buf = vec![0; 1024];
        let mut send_buffer = b"GET /uuid HTTP/1.1\r\n\
            Host: httpbin.org\r\n\
            Connection: keep-alive\r\n\
            \r\n"
        .to_owned();
    
        let n = socket
            .send(send_buffer.as_mut_slice())
            .await
            .unwrap_or_else(|e| {
                println!("send fail {:?}", e);
                0
            });
    
        let n = socket
            .recv_all(buf.as_mut_slice())
            .await
            .unwrap_or_else(|e| {
                println!("recv fail {:?}", e);
                0
            });
        socket.close().await;
    }

    pub async fn async_request_executor(
        berk: Arc<Option<Berk>>,
        berk_status: Arc<AtomicBool>,
    ) -> Result<(), Error> {
        if berk_status
            .compare_exchange(false, false, SeqCst, SeqCst)
            .is_ok()
        {
            Err(Error::INSUFFICIENT_RESOURCES)
        } else {
            for i in 0..10000 {
              spawn(handle_connection(
              TcpSocket::new_v4(berk.clone(), berk_status.clone())
              .await?
              .connect("127.0.0.1", "8080")
              .await?,
              ));
            }

        Ok(())
        }
    }
```


In this example, an asynchronous TCP socket is created, connected to the specified address, and used to send and receive data. The `berk` and `berk_status` parameters are used to manage the underlying network stack and its state.


# Async environment



## Key Components & High-Level Overview



- **(Single-threaded) Executor**:  
  `tasks`: A map to store tasks identified by a unique TaskId.   
  `task_queue`: A queue of TaskIds indicating which tasks are ready to be polled.   
  `waker_cache`: A cache of Waker objects used to wake up tasks when events occur.   
  `notifier`: Used to wake the executor itself when there are new tasks to run.   
  `exit`: An atomic flag to signal the executor to shut down.

- **Task**:  
  Represents an asynchronous operation to be executed. Contains a Future object that encapsulates the async logic.

- **Delay** (and other Futures):  
  A Future implementation for time-based delays. Uses a `KTimer`  to trigger a wake-up after a specified duration.

- **TaskWaker**:  
  Implements the Wake trait to wake up a task. Stores the TaskId, task_queue, and notifier to re-queue the task and wake the executor if needed.

- **Event Map**:  
  A global mapping structure that associates kernel events ) with corresponding Wakers.




## How It Works (Step-by-Step)



- **Initialization**:  
  When the driver loads (`driver_entry`), the executor is created. It relies on the ability to spawn a thread to
  manage the task execution. If this thread creation fails, the driver loading itself will fail.




- **Task Spawning**:   
  `spawn()` takes a `Future`, creates a `Task` to
  wrap it, and adds it to the tasks map. The `TaskId` is pushed onto the
  `task_queue`.



- **Executor Loop**:  
  The executor runs an infinite loop:  
  If the exit flag is set, the loop terminates. `run_ready_tasks` is called to poll ready tasks from the `task_queue`. If the queue is   empty, the executor waits for a notification.


- **Polling Tasks**:    
  `run_ready_tasks` pops tasks from the `task_queue`  
  For each task, it creates a `TaskWaker` (if not already cached) and a `Context` to poll the task's `Future`. If the `Future` is ready (`Poll::Ready`), it's removed from the tasks map and `waker_cache`. If   
  the Future is pending (`Poll::Pending`), the task is skipped for now.



- **Waiting for Events**:
  If a task's `Future` is waiting for an event (like a timer), it will return `Poll::Pending`.
  In the case of `Delay`, the first poll will register the `Task`'s `Waker` with an `Event` map associated with the `KeTimer`. When the timer expires, it triggers a kernel-mode DPC (Deferred Procedure Call). The DPC schedules a work item to call `notify`. `notify` looks up the `Waker` for the `Event` and wakes the corresponding task.



- **Task Wake-up**:
  When a `TaskWaker` is woken:
  It pushes the associated `TaskId` back onto the `task_queue`.
  It wakes the `Executor` through the `notifier`, causing it to re-poll the `Task`.



## Under the Hood

The executor is created when the driver starts and will cause the driver to fail to load if it cannot create the thread it needs to run on. It continuously runs a loop where it first checks if it has been signaled to stop. If not, it executes all tasks that are ready to proceed and then waits (sleeps) until new tasks are available or events occur that make existing tasks ready.

Tasks can be added to the executor from any part of the code using `asynk::executor::spawn()`. If the executor has been signaled to quit, this function will return an error. Otherwise, it returns a `JoinHandle`, which allows you to wait for the task to finish and get its result. This `JoinHandle` provides a consistent way to work with the results of all futures, regardless of the specific type of data they produce. Internally, the executor transforms the `Future` given to `spawn()` into a `Task`, which is stored in its `tasks` collection. A `Task` includes an ID, its state, and the underlying future.
The `JoinHandle` acts as a bridge between the spawned future and the code that's waiting for its result. It uses a one-shot channel to send the result of the future to a receiver, which is then stored in the `JoinHandle`. When you `.await` on the `JoinHandle`, you're essentially waiting for the result to be sent over this channel.

```rust
    pub fn spawn<F, R>(&self, original_future: F) -> JoinHandle<R>
        where
            F: Future<Output = R> + 'static,
            R: 'static,
        {
            let (s, r) = oneshot::channel();
            let future = async move {
                let _ = s.send(original_future.await);
            };
            let task = Task::new(future);
            ...
            self.tasks.lock().unwrap().insert(task.id, task);
            self.task_queue.push(id);
            ...
            return Box::pin(async { r.await.unwrap() });
        }
```

This spawn function is part of the `Executor` struct (but can be called without holding a reference to the global executor via `asynk::executor::spawn()`).

```rust
    pub struct Executor {
        tasks: RecursiveMutex<BTreeMap<TaskId, Task>>,
        task_queue: Arc<ArrayQueue<TaskId>>,
        waker_cache: DashMap<TaskId, Waker>,
        notifier: Arc<Notifier>,
        exit: Arc<AtomicBool>,
    }
```



The `Delay` future is a way to pause the execution of a task for a specific duration. It's implemented using a kernel timer (`KTimer`). When polled for the first time, it registers an event on a map that associates events with wakers. This event is linked to the `Waker` of the `Task`  containing the `Delay` future. When the timer expires, it triggers a chain of events that eventually leads to the waker being called, which re-adds the task to the executor's queue.

```rust
    pub struct Delay {
        timer: KeTimer,
        duration: Duration,
        pending: bool,
    }
    
    #[must_use]
    pub fn sleep_until(duration: Duration) -> Delay {
        let mut delay = Delay {
            timer: KeTimer::new(),
            pending: false,
            duration,
        };
        delay
    }
    
    impl Future for Delay {
        type Output = ();
        
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.get_mut();
        
                if !this.pending {
                    get_event_map().insert(Event::KTimer( this.timer.timer.as_mut() as _), cx.waker().clone());
        
                    let _ = this.timer.set(this.duration);
                    this.pending = true;
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            }
    }
```

In essence, the `Delay` future gets polled twice: once initially, where it sets up the timer and registers the `Event`, and then again after the timer expires, where it signals that it's ready to continue. This two-step process allows the executor to manage other tasks while waiting for the timer to elapse.

```rust
    struct KeTimer {
        timer: Box<KTIMER>,
        dpc: Box<KDPC>,
    }
    
    impl KeTimer {
        fn new() -> Self {
            let mut timer: Box<KTIMER> = Box::new(_KTIMER {...});
            let mut dpc = Box::new(KDPC {...});

            unsafe {
                KeInitializeTimer(timer.as_mut() as _);
                KeInitializeDpc(
                    dpc.as_mut() as _,
                    Some(timer_dpc),
                    timer.as_mut() as *mut _ as _,
                )
            };
    
            Self { timer, dpc }
        }
    
        fn set(&mut self, due_time: Duration) -> Result<(), Error> {
            let res = unsafe {
                KeSetTimer(
                    self.timer.as_mut() as _,
                    _LARGE_INTEGER {
                        QuadPart: -(due_time.as_nanos() as i64 / 100) as LONGLONG,
                    },
                    self.dpc.as_mut() as _,
                )
            };
            if res == TRUE {
                return Err(Error::SINGLE_STEP); // already set
            }
            Ok(())
        }
    }

    unsafe extern "C" fn timer_dpc(
        dpc: *mut KDPC,
        context: PVOID,
        _SystemArgument1: PVOID,
        _SystemArgument2: PVOID,
    ) {
        let workitem = IoAllocateWorkItem(__DEVICE.unwrap_unchecked());
        IoQueueWorkItemEx(
            workitem,
            Some(notify),
            DelayedWorkQueue,
            context,
        );
    }
```


The code also includes a `KeTimer` struct for managing kernel timers. It has methods to initialize and set timers. When a timer is set, you can optionally provide a Deferred Procedure Call (DPC) routine. If you do, this routine gets added to the system's DPC queue to be executed after the timer expires.

However, due to the constraints of the asynchronous environment, the code uses a `WorkItem` instead of a DPC to notify the executor. This is because DPCs run at a high interrupt level, while work items allow the notification to happen at a lower level.

```rust
    unsafe extern "C" fn notify(
        _device_object: PVOID,
        completion_event: PVOID,
        workitem: PIO_WORKITEM,
    ) {
        IoFreeWorkItem(workitem);

        let event = Event::KTimer(completion_event as PKTIMER);
        match EVENT_MAP.get().unwrap_unchecked().get().as_ref() {
            None => {}
            Some(map) => match map.as_ref().unwrap_unchecked().get(&event) {
                None => {}
                Some(waker) => waker.value().wake_by_ref(),
            },
        }
    }
```


There's also a `notify` function that handles the notification process. It takes the `Event` stored during the initial poll of the `Delay` future and calls its associated `Waker`. This happens when the timer expires (or as soon as the DPC and work item can run), leading to the task's `TaskId` being put back into the executor's `task_queue`.

```rust
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
```

To be able to requeue a task, our `TaskWaker` stores the associated `TaskId`, an Arc of the same `task_queue` held by the executor, and a `notifier` which, if asleep, awakens the executor.
Implementing the `Wake` trait makes it so that our `TaskWaker` can be passed to `Context::from_waker()`

The executor's loop is as follows

```rust
    fn run(&self) {
        loop {
            if self.exit.load(Acquire) {
                [...cleanup...]
                return;
            }
            self.run_ready_tasks();

            if self.task_queue.is_empty() {
                self.notifier.wait();
            }
        }
    }
```    

This `notifier` is the same as the one each `TaskWaker` has.


```rust
    fn run_ready_tasks(&self) {
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
            } // drop guard
            // task done -> remove it and its cached waker
            self.tasks
                .lock()
                .unwrap()
                .remove(&task_id);
            self.waker_cache.remove(&task_id);
        }
    }
```

For each `TaskId` popped from the queue, a `TaskWaker` is instantiated if not already present on the `waker_cache`. a `Context` is created and then the `Task` polled. If it is still pending, another task is popped, of if none queued the function returns.

