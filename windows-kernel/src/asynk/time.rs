use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::ptr::null_mut;
use core::task::{Context, Poll};
use core::time::Duration;

use pin_project::pin_project;

use windows_kernel_sys::base::{_DISPATCHER_HEADER, _DISPATCHER_HEADER__bindgen_ty_1, _DISPATCHER_HEADER__bindgen_ty_1__bindgen_ty_2, _KDPC__bindgen_ty_1, _KTIMER, _LARGE_INTEGER, _LIST_ENTRY, _SINGLE_LIST_ENTRY, _ULARGE_INTEGER, KDPC, KTIMER, LONGLONG, PIO_WORKITEM, PKTIMER, PRKEVENT, PVOID, TRUE};
use windows_kernel_sys::base::_WORK_QUEUE_TYPE::DelayedWorkQueue;
use windows_kernel_sys::netio::{KeCancelTimer, KeInitializeDpc, KeInitializeTimer, KeSetTimer};
use windows_kernel_sys::ntoskrnl::{IoAllocateWorkItem, IoFreeWorkItem, IoQueueWorkItemEx};

use crate::{__DEVICE, Error};
use crate::asynk::executor::{EVENT_MAP, get_event_map};
use crate::asynk::wsk::Event;

struct KeTimer {
    timer: Box<KTIMER>,
    dpc: Box<KDPC>,
}

impl KeTimer {
    fn new() -> Self {
        let mut timer: Box<KTIMER> = Box::new(_KTIMER {
            Header: _DISPATCHER_HEADER {
                __bindgen_anon_1: _DISPATCHER_HEADER__bindgen_ty_1 {
                    __bindgen_anon_2: _DISPATCHER_HEADER__bindgen_ty_1__bindgen_ty_2 {
                        Type: 0,
                        Signalling: 0,
                        Size: 0,
                        Reserved1: 0,
                    },
                },
                SignalState: 0,
                WaitListHead: _LIST_ENTRY {
                    Flink: null_mut(),
                    Blink: null_mut(),
                },
            },
            DueTime: _ULARGE_INTEGER { QuadPart: 0 },
            TimerListEntry: _LIST_ENTRY {
                Flink: null_mut(),
                Blink: null_mut(),
            },
            Dpc: null_mut(),
            Processor: 0,
            TimerType: 0,
            Period: 0,
        });

        let mut dpc = Box::new(KDPC {
            __bindgen_anon_1: _KDPC__bindgen_ty_1 {
                TargetInfoAsUlong: 0,
            },
            DpcListEntry: _SINGLE_LIST_ENTRY { Next: null_mut() },
            ProcessorHistory: 0,
            DeferredRoutine: None,
            DeferredContext: null_mut(),
            SystemArgument1: null_mut(),
            SystemArgument2: null_mut(),
            DpcData: null_mut(),
        });

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

impl Drop for Delay {
    fn drop(&mut self) {
        let res = unsafe { KeCancelTimer(self.timer.timer.as_mut() as *mut _) };
    }
}

#[pin_project]
pub struct Timeout<F> {
    #[pin]
    pub future: F,

    #[pin]
    pub delay: Delay,
}

pub fn timeout<F: Future>(future: F, duration: Duration) -> Timeout<F> {
    Timeout {
        future,
        delay: sleep_until(duration),
    }
}

impl<F: Future> Future for Timeout<F> {
    type Output = Option<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        match this.future.poll(cx) {
            Poll::Ready(output) => Poll::Ready(Some(output)),
            Poll::Pending => match this.delay.poll(cx) {
                Poll::Ready(()) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}


mod channel {
    use alloc::collections::binary_heap::PeekMut;
    use alloc::collections::BinaryHeap;
    use alloc::sync::Arc;
    use core::cmp::Reverse;
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll, Waker};
    use core::time::Duration;

    use hashbrown::HashMap;

    use crate::{Mutex, println};
    use crate::sync::mpmc::{RecvTimeoutError, TryRecvError};
    use crate::sync::mpsc::{channel, Receiver, Sender};
    use crate::sync::once_lock::OnceLock;
    use crate::sync::thread;
    use crate::sync::thread::Thread;
    use crate::sync::time::Instant;

    #[derive(Debug)]
    pub struct Delay {
        deadline: Instant,
        state: DelayState,
    }

    #[derive(Debug)]
    enum DelayState {
        New,
        Waiting { signal: Receiver<()>, id: u64 },
    }

    impl Future for Delay {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();

            match this.state {
                DelayState::New => {
                    let (notify, signal) = channel::<()>();
                    let id = uid::IdU64::<()>::new().get();
                    let message = Message::New {
                        notify,
                        waker: cx.waker().clone(),
                        deadline: this.deadline,
                        id,
                    };

                    this.state = DelayState::Waiting { signal, id };

                    sleeper_thread_channel(false).send(message).unwrap();
                    Poll::Pending
                }
                DelayState::Waiting { ref signal, id } => match signal.try_recv() {
                    Ok(()) => Poll::Ready(()),
                    Err(TryRecvError::Disconnected) => {
                        panic!(":(")
                    }
                    Err(TryRecvError::Empty) => {
                        let message = Message::Polled {
                            waker: cx.waker().clone(),
                            id,
                        };
                        sleeper_thread_channel(false).send(message).unwrap();
                        Poll::Pending
                    }
                },
            }
        }
    }


    #[derive(Debug)]
    pub enum Message {
        New {
            deadline: Instant,
            waker: Waker,
            notify: Sender<()>,
            id: u64,
        },
        Polled {
            waker: Waker,
            id: u64,
        },
    }

    pub fn kill_sleeper_channel() {
        sleeper_thread_channel(true);
    }

    fn sleeper_thread_channel<'a>(kill_flag: bool) -> &'a Sender<Message> {
        static CHANNEL: OnceLock<Sender<Message>> = OnceLock::new();
        static SIGNAL: OnceLock<Arc<Mutex<bool>>> = OnceLock::new();
        static mut ID: Option<Arc<Mutex<Thread>>> = None;
        let c1 = SIGNAL.get_or_init(|| Arc::new(Mutex::new(false))).clone();

        if kill_flag {
            let signal = c1.clone();
            let mut guard = signal.lock().unwrap();

            *guard = true;
            drop(guard);

            unsafe {
                ID = None;
            }
        }

        CHANNEL.get_or_init(|| {
            let (sender, receiver) = channel::<Message>();
            unsafe {
                Thread::spawn(move || {
                    ID = Some(Arc::new(Mutex::new(thread::current())));
                    // A BinaryHeap would store its contents in order from "bigger" -> "smaller"
                    // We reverse-order Instant to pop the timer with the least pending time when polling for events in the loop
                    let mut timers: BinaryHeap<(Reverse<Instant>, u64)> = BinaryHeap::new();
                    let mut wakers: HashMap<u64, (Waker, Sender<()>)> = HashMap::new();

                    let mut i = 0;
                    loop {
                        println!("iter{i}");

                        let guard = c1.lock().unwrap();
                        if *guard {
                            drop(guard);
                            break;
                        }
                        drop(guard);
                        i += 1;
                        let now = Instant::now();

                        let next_event = loop {
                            match timers.peek_mut() {
                                None => {
                                    break None;
                                }
                                Some(slot) => {
                                    // The given Instant is past already
                                    if slot.0.0 <= now {
                                        let (_, id) = PeekMut::pop(slot);
                                        if let Some((waker, sender)) = wakers.remove(&id) {
                                            if let Ok(()) = sender.send(()) {
                                                waker.wake();
                                            }
                                        }
                                        // Still need to wait for the Instant to be current
                                    } else {
                                        break Some(slot.0.0);
                                    }
                                }
                            }
                        };

                        let message = match next_event {
                            None => receiver.recv().unwrap(),
                            Some(deadline) => match receiver.recv_deadline(deadline) {
                                Ok(message) => message,
                                Err(RecvTimeoutError::Timeout) => {
                                    continue;
                                }
                                Err(RecvTimeoutError::Disconnected) => {
                                    panic!(":(")
                                }
                            },
                        };

                        match message {
                            Message::New {
                                deadline,
                                waker,
                                notify,
                                id,
                            } => {
                                timers.push((Reverse(deadline), id));
                                wakers.insert(id, (waker, notify));
                            }
                            Message::Polled { waker, id } => {
                                if let Some((old_waker, _)) = wakers.get_mut(&id) {
                                    *old_waker = waker;
                                }
                            }
                        }
                    }
                })
                    .unwrap();
            }

            sender
        })
    }

    fn sleep_until(deadline: Instant) -> Delay {
        Delay {
            deadline,
            state: DelayState::New,
        }
    }

    pub fn sleep(duration: Duration) -> Delay {
        sleep_until(Instant::now() + duration)
    }
}

