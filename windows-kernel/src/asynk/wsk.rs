use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_ulong, c_void};
use core::fmt::Formatter;
use core::future::Future;
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{addr_of_mut, null, null_mut};
use core::sync::atomic::Ordering::{Relaxed, SeqCst};
use core::sync::atomic::{AtomicBool, AtomicU32};
use core::task::{Context, Poll};

use windows_kernel_sys::base::_EVENT_TYPE::SynchronizationEvent;
use windows_kernel_sys::base::_LOCK_OPERATION::IoWriteAccess;
use windows_kernel_sys::base::_WORK_QUEUE_TYPE::DelayedWorkQueue;
use windows_kernel_sys::base::{ANSI_STRING, FALSE, IO_NO_INCREMENT, KPRIORITY, KPROCESSOR_MODE, NTSTATUS, PIO_WORKITEM, PRKEVENT, PUNICODE_STRING, PVOID, SIZE_T, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL, TRUE, ULONG, UNICODE_STRING, USHORT, _DEVICE_OBJECT, _IRP, PKTIMER};
use windows_kernel_sys::netio::WSK_CONTROL_SOCKET_TYPE::{WskGetOption, WskIoctl};
use windows_kernel_sys::netio::{
    AddrInfoexW, ADDRESS_FAMILY, ADDRINFOA, ADDRINFOEXW, AF_INET, IN_ADDR, IN_ADDR_0, PADDRINFOEXW,
    PWSK_PROVIDER_BASIC_DISPATCH, PWSK_PROVIDER_CONNECTION_DISPATCH,
    PWSK_PROVIDER_DATAGRAM_DISPATCH, PWSK_PROVIDER_LISTEN_DISPATCH, PWSK_SOCKET,
    SIO_WSK_SET_REMOTE_ADDRESS, SIO_WSK_SET_SENDTO_ADDRESS, SOCKADDR, SOCKADDR_IN, SOCK_DGRAM,
    SOCK_STREAM, SOL_SOCKET, SO_TYPE, WSK_BUF, WSK_CONTROL_SOCKET_TYPE, WSK_FLAG_CONNECTION_SOCKET,
    WSK_FLAG_DATAGRAM_SOCKET, WSK_FLAG_LISTEN_SOCKET, WSK_INFINITE_WAIT,
};
use windows_kernel_sys::ntoskrnl::{
    IoAllocateIrp, IoAllocateMdl, IoAllocateWorkItem, IoFreeIrp, IoFreeWorkItem, IoQueueWorkItemEx,
    IoReuseIrp, IoSetCompletionRoutine, KeInitializeEvent, KeResetEvent, KeSetEvent,
    MmProbeAndLockPages, MmUnlockPages, RtlAnsiStringToUnicodeString, RtlFreeAnsiString,
    RtlFreeUnicodeString, RtlInitAnsiString, RtlInitUnicodeString, RtlUnicodeStringToAnsiString,
};

use crate::asynk::executor::{get_event_map, EVENT_MAP};
use crate::asynk::berk::new_addrinfoexw;
use crate::mdl::AccessMode::KernelMode;
use crate::string::create_unicode_string;
use crate::sync::berk::Berk;
use crate::sync::wsk::{AddrInfo, Buffer, KSocket, KSocketAsyncContext, Wsk};
use crate::{println, Error, Mutex, __DEVICE};

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Hash)]
pub enum Event {
    KEvent(PRKEVENT),
    KTimer(PKTIMER)// Both KEVENT and KTIMER share enough fields 
}

unsafe impl Send for Event {}

unsafe impl Sync for Event {}

impl core::fmt::Debug for Event {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Event::KEvent(event) => { unsafe { write!(f, "Event: {}", (**event).Header.SignalState) }}
            Event::KTimer(timer) => { unsafe { write!(f, "Event: {}", (**timer).Header.SignalState) }}
        }
    }
}

impl<'a, 'b> Drop for SendFuture<'a, 'b> {
    fn drop(&mut self) {
        unsafe {
            MmUnlockPages(self.wsk_buffer.Mdl);
        }
    }
}

impl<'a, 'b> Drop for ReceiveFuture<'a, 'b> {
    fn drop(&mut self) {
        unsafe {
            MmUnlockPages(self.wsk_buffer.Mdl);
        }
    }
}

fn async_context_allocate(context: &mut KSocketAsyncContext) -> Result<(), Error> {
    unsafe {
        KeInitializeEvent(&mut context.completion_event, SynchronizationEvent, FALSE);
    }

    unsafe {
        context.irp = IoAllocateIrp(1, FALSE);
    }
    if context.irp.is_null() {
        return Err(Error::INSUFFICIENT_RESOURCES);
    }

    unsafe {
        IoSetCompletionRoutine(
            context.irp,
            Some(async_context_completion_routine),
            addr_of_mut!(context.completion_event).cast(),
            TRUE,
            TRUE,
            TRUE,
        );
    }

    Ok(())
}

fn async_context_free(context: &mut KSocketAsyncContext) {
    unsafe { IoFreeIrp(context.irp) }
}

fn async_context_reset(context: &mut KSocketAsyncContext) {
    delist(Event::KEvent(&mut context.completion_event as PRKEVENT));
    unsafe {
        KeResetEvent(&mut context.completion_event);
        IoReuseIrp(context.irp, STATUS_UNSUCCESSFUL);
        IoSetCompletionRoutine(
            context.irp,
            Some(async_context_completion_routine),
            addr_of_mut!(context.completion_event).cast(),
            TRUE,
            TRUE,
            TRUE,
        );
    }
}

unsafe extern "C" fn async_context_completion_routine(
    device_object: *mut _DEVICE_OBJECT,
    _irp: *mut _IRP,
    completion_event: *mut c_void,
) -> i32 {
    KeSetEvent(completion_event.cast(), IO_NO_INCREMENT as KPRIORITY, FALSE);
    // let workitem = IoAllocateWorkItem(__MOD.as_ref().unwrap()._device.as_raw_mut());
    let workitem = IoAllocateWorkItem(__DEVICE.unwrap_unchecked());
    IoQueueWorkItemEx(workitem, Some(notify), DelayedWorkQueue, completion_event);

    0xC000_0016_u32 as i32
}

pub(crate) unsafe extern "C" fn notify(
    _device_object: PVOID,
    completion_event: PVOID,
    workitem: PIO_WORKITEM,
) {
    IoFreeWorkItem(workitem);

    let event = Event::KEvent(completion_event as PRKEVENT);
    match EVENT_MAP.get().unwrap_unchecked().get().as_ref() {
        None => {}
        Some(map) => match map.as_ref().unwrap_unchecked().get(&event) {
            None => {}
            Some(waker) => waker.value().wake_by_ref(),
        },
    }
}

#[inline]
fn delist(completion_event: Event) {
    get_event_map().remove(&completion_event);
}

struct AddrInfoFuture<'a, 'b> {
    pending: bool,
    context: KSocketAsyncContext,
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    node_name: PUNICODE_STRING,
    service_name: PUNICODE_STRING,
    hints: &'a mut AddrInfo,
    result: &'b mut Box<PADDRINFOEXW>,
}

impl<'a, 'b> Future for AddrInfoFuture<'a, 'b> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.pending {
            let status = unsafe { (*this.context.irp).IoStatus.__bindgen_anon_1.Status };
            async_context_free(&mut this.context);
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        } else {
            this.context = KSocketAsyncContext::new();
            async_context_allocate(&mut this.context)?;

            return match this
                .berk_status
                .compare_exchange(false, false, SeqCst, SeqCst)
            {
                Ok(_) => Poll::Ready(Err(Error::INSUFFICIENT_RESOURCES)),
                Err(_) => {
                    if let Some(berk) = this.berk.as_ref() {
                        let function = unsafe { (*(berk.wsk.provider.Dispatch)).WskGetAddressInfo };

                        if let AddrInfo::AddrInfoExW(mut hints) = *this.hints {
                            let prkevent = &mut this.context.completion_event as PRKEVENT;
                            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

                            let status = unsafe {
                                function.unwrap()(
                                    berk.wsk.provider.Client,
                                    this.node_name,
                                    this.service_name,
                                    0,
                                    null(),
                                    &mut hints as *mut _ as PADDRINFOEXW,
                                    &mut **this.result,
                                    null_mut(),
                                    null_mut(),
                                    this.context.irp,
                                )
                            };
                            if status != 0 && status != 0x00000103 {
                                delist(Event::KEvent(prkevent as PRKEVENT));
                                return Poll::Ready(Err(Error::from_ntstatus(status)));
                            }

                            if status == 0 {
                                delist(Event::KEvent(prkevent as PRKEVENT));
                                return Poll::Ready(Ok(()));
                            }

                            this.pending = true;
                            Poll::Pending
                        } else {
                            async_context_free(&mut this.context);
                            Poll::Ready(Err(Error::UNSUCCESSFUL))
                        }
                    } else {
                        Poll::Ready(Err(Error::INSUFFICIENT_RESOURCES))
                    }
                }
            };
        }
    }
}

pub async fn get_addr_info(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    node_name: PUNICODE_STRING,
    service_name: PUNICODE_STRING,
    hints: &mut AddrInfo,
) -> Result<Box<PADDRINFOEXW>, Error> {
    let mut context = KSocketAsyncContext::new();
    //async_context_allocate(&mut context)?;

    let mut result = Box::new(null_mut());

    match (AddrInfoFuture {
        pending: false,
        context,
        berk,
        berk_status,
        node_name,
        service_name,
        hints,
        result: &mut result,
    })
    .await
    {
        Ok(_) => Ok(result),
        Err(e) => Err(e),
    }
}

pub fn free_addr_info(berk: Mutex<Wsk>, addr_info: &mut AddrInfoexW) {
    let function = unsafe { (*(berk.lock().unwrap().provider.Dispatch)).WskFreeAddressInfo };
    unsafe { function.unwrap()(berk.lock().unwrap().provider.Client, addr_info) }
}

struct CreateSocketFuture<'a> {
    pending: bool,
    socket: &'a mut Box<KSocket>,
    berk: &'a Berk,
    berk_status: Arc<AtomicBool>,
    address_family: ADDRESS_FAMILY,
    socket_type: u8,
    protocol: u32,
    flags: u8,
}

impl<'a> Future for CreateSocketFuture<'a> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if !this.pending {
            let function = unsafe { (*(this.berk.wsk.provider.Dispatch)).WskSocket };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status: NTSTATUS = unsafe {
                function.unwrap()(
                    this.berk.wsk.provider.Client,
                    this.address_family,
                    this.socket_type as USHORT,
                    this.protocol,
                    this.flags as ULONG,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    this.socket.async_context.irp,
                )
            };

            if status != 0 && status != 0x0000_0103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                this.socket.wsk_socket = unsafe { *this.socket.async_context.irp }
                    .IoStatus
                    .Information as PWSK_SOCKET;
                this.socket.wsk_dispatch = unsafe { *(*this.socket.wsk_socket).Dispatch };
            } else {
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            Poll::Ready(Ok(()))
        }
    }
}

pub async fn create_socket(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    address_family: ADDRESS_FAMILY,
    socket_type: u8,
    protocol: u32,
    flags: u8,
) -> Result<Box<KSocket>, Error> {
    return match berk_status.compare_exchange(false, false, SeqCst, SeqCst) {
        Ok(_) => Err(Error::INSUFFICIENT_RESOURCES),
        Err(_) => {
            let mut new_socket = new_ksocket();
            new_socket.socket_type = socket_type;
            async_context_allocate(&mut new_socket.async_context)?;
            if let Some(berk) = berk.as_ref() {
                match (CreateSocketFuture {
                    pending: false,
                    socket: &mut new_socket,
                    berk,
                    berk_status,
                    address_family,
                    socket_type,
                    protocol,
                    flags,
                })
                .await
                {
                    Ok(_) => Ok(new_socket),
                    Err(e) => Err(e),
                }
            } else {
                Err(Error::INSUFFICIENT_RESOURCES)
            }
        }
    };
}

fn new_ksocket() -> Box<KSocket> {
    Box::new(KSocket {
        wsk_socket: null_mut(),
        socket_type: 0xff,
        send_timeout: WSK_INFINITE_WAIT,
        recv_timeout: WSK_INFINITE_WAIT,
        wsk_dispatch: null_mut(),
        async_context: KSocketAsyncContext::new(),
    })
}

pub async fn create_connection_socket(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    address_family: ADDRESS_FAMILY,
    socket_type: u8,
    protocol: u32,
) -> Result<Box<KSocket>, Error> {
    create_socket(
        berk,
        berk_status,
        address_family,
        socket_type,
        protocol,
        WSK_FLAG_CONNECTION_SOCKET,
    )
    .await
}

pub async fn create_listen_socket(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    address_family: ADDRESS_FAMILY,
    socket_type: u8,
    protocol: u32,
) -> Result<Box<KSocket>, Error> {
    create_socket(
        berk,
        berk_status,
        address_family,
        socket_type,
        protocol,
        WSK_FLAG_LISTEN_SOCKET,
    )
    .await
}

pub async fn create_datagram_socket(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    address_family: ADDRESS_FAMILY,
    socket_type: u8,
    protocol: u32,
) -> Result<Box<KSocket>, Error> {
    create_socket(
        berk,
        berk_status,
        address_family,
        socket_type,
        protocol,
        WSK_FLAG_DATAGRAM_SOCKET,
    )
    .await
}

struct CloseFuture<'a> {
    pending: bool,
    socket: &'a mut KSocket,
}

impl<'a> Future for CloseFuture<'a> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_BASIC_DISPATCH))
                    .WskCloseSocket
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = function(this.socket.wsk_socket, this.socket.async_context.irp);

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

pub async fn close_socket(socket: &mut KSocket) -> Result<(), Error> {
    async_context_reset(&mut socket.async_context);

    match (CloseFuture {
        pending: false,
        socket,
    })
    .await
    {
        Ok(_) => {
            async_context_free(&mut socket.async_context);
            println!("always here");
            Ok(())
        }
        Err(e) => {
            async_context_free(&mut socket.async_context);
            println!("never here");
            Err(e)
        }
    }
}

struct DisconnectFuture<'a> {
    pending: bool,
    socket: &'a mut KSocket,
}

impl<'a> Future for DisconnectFuture<'a> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH))
                    .WskDisconnect
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            //let status = function(this.socket.wsk_socket, this.socket.async_context.irp);
            let status = unsafe {
                function(
                    this.socket.wsk_socket,
                    null_mut(),
                    0,
                    this.socket.async_context.irp,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

pub async fn disconnect_socket(socket: &mut KSocket) -> Result<(), Error> {
    async_context_reset(&mut socket.async_context);

    match (DisconnectFuture {
        pending: false,
        socket,
    })
    .await
    {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

pub async fn bind(socket: &mut Box<KSocket>, local_address: *mut SOCKADDR) -> Result<(), Error> {
    async_context_reset(&mut socket.async_context);

    BindFuture {
        pending: false,
        socket,
        local_addr: Some(local_address),
    }
    .await
}

struct AcceptFuture<'a, 'b> {
    pending: bool,
    socket: &'a mut KSocket,
    local_address: &'b mut SOCKADDR,
    remote_address: *mut SOCKADDR,
}

impl<'a, 'b> Future for AcceptFuture<'a, 'b> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let accept_fn = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_LISTEN_DISPATCH)).WskAccept
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = unsafe {
                accept_fn(
                    this.socket.wsk_socket as _,
                    0,
                    null_mut(),
                    null_mut(),
                    null_mut(), //this.local_address as *mut _ as _,
                    null_mut(), //this.remote_address as *mut _ as _,
                    this.socket.async_context.irp,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                println!("error {:x}", status);
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                println!("error {:x}", status);
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

pub async fn accept(
    socket: &mut KSocket,
    local_address: &mut SOCKADDR,
    remote_address: *mut SOCKADDR,
) -> Result<Box<KSocket>, Error> {
    async_context_reset(&mut socket.async_context);
    PCCOUNTER.fetch_add(1, Relaxed);

    AcceptFuture {
        pending: false,
        socket,
        local_address,
        remote_address,
    }
    .await?;

    let psocket = (unsafe { *socket.async_context.irp }).IoStatus.Information as PWSK_SOCKET;
    let mut new_socket = Box::new(KSocket {
        wsk_socket: psocket,
        socket_type: socket.socket_type,
        send_timeout: socket.send_timeout,
        recv_timeout: socket.recv_timeout,
        wsk_dispatch: unsafe { *(*psocket).Dispatch },
        async_context: KSocketAsyncContext::new(),
    });
    async_context_allocate(&mut new_socket.async_context)?;
    CCOUNTER.fetch_add(1, Relaxed);

    Ok(new_socket)
}

struct BindFuture<'a> {
    pending: bool,
    socket: &'a mut Box<KSocket>,
    local_addr: Option<*mut SOCKADDR>,
}

impl<'a> Future for BindFuture<'a> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = if this.local_addr.is_none() {
                let mut local_address = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 { S_addr: 0 },
                    },
                    sin_zero: [0; 8],
                };
                let function = unsafe {
                    (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH))
                        .WskBind
                };

                unsafe {
                    function(
                        this.socket.wsk_socket as _,
                        &mut local_address as *mut _ as _,
                        0,
                        this.socket.async_context.irp as _,
                    )
                }
            } else {
                let mut local_address = unsafe { *this.local_addr.unwrap() };
                let function = unsafe {
                    (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH))
                        .WskBind
                };

                unsafe {
                    function(
                        this.socket.wsk_socket as _,
                        &mut local_address as *mut _ as _,
                        0,
                        this.socket.async_context.irp as _,
                    )
                }
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

struct ConnectFuture<'a> {
    pending: bool,
    socket: &'a mut Box<KSocket>,
    remote_address: *mut SOCKADDR,
}

impl<'a> Future for ConnectFuture<'a> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.pending {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        } else {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH))
                    .WskConnect
                    .unwrap()
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = unsafe {
                function(
                    this.socket.wsk_socket as _,
                    this.remote_address as _,
                    0,
                    this.socket.async_context.irp as _,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        }
    }
}

pub static PCCOUNTER: AtomicU32 = AtomicU32::new(0);
pub static CCOUNTER: AtomicU32 = AtomicU32::new(0);

pub async fn connect(
    socket: &mut Box<KSocket>,
    remote_address: *mut SOCKADDR,
) -> Result<(), Error> {
    async_context_reset(&mut socket.async_context);

    match (BindFuture {
        pending: false,
        socket,
        local_addr: None,
    })
    .await
    {
        Ok(_) => {
            async_context_reset(&mut socket.async_context);
            match (ConnectFuture {
                pending: false,
                socket,
                remote_address,
            })
            .await
            {
                Ok(_) => Ok(()),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

struct SendFuture<'a, 'b> {
    pending: bool,
    socket: &'a mut KSocket,
    flags: u32,
    wsk_buffer: &'b mut Buffer,
}

impl<'a, 'b> Future for SendFuture<'a, 'b> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH)).WskSend
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = unsafe {
                function(
                    this.socket.wsk_socket as _,
                    &mut **this.wsk_buffer as _,
                    this.flags as c_ulong,
                    &mut *this.socket.async_context.irp as _,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

struct ReceiveFuture<'a, 'b> {
    pending: bool,
    socket: &'a mut KSocket,
    flags: u32,
    wsk_buffer: &'b mut Buffer,
}

impl<'a, 'b> Future for ReceiveFuture<'a, 'b> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH))
                    .WskReceive
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = unsafe {
                function(
                    this.socket.wsk_socket as _,
                    &mut **this.wsk_buffer as _,
                    this.flags as c_ulong,
                    &mut *this.socket.async_context.irp as _,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }
            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

pub static SRCOUNTER: AtomicU32 = AtomicU32::new(0);
pub static PSRCOUNTER: AtomicU32 = AtomicU32::new(0);

pub async fn send_recv(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    send: bool,
) -> Result<(), Error> {
    let mut wsk_buffer = new_wsk_buf(buffer, length);
    //TODO: "try block"
    unsafe {
        MmProbeAndLockPages(wsk_buffer.Mdl, KernelMode as KPROCESSOR_MODE, IoWriteAccess);
        //TODO: out to futues
    }

    async_context_reset(&mut socket.async_context);
    PSRCOUNTER.fetch_add(1, Relaxed);

    if send {
        SendFuture {
            pending: false,
            socket,
            flags,
            wsk_buffer: &mut wsk_buffer,
        }
        .await?
    } else {
        ReceiveFuture {
            pending: false,
            socket,
            flags,
            wsk_buffer: &mut wsk_buffer,
        }
        .await?
    };

    SRCOUNTER.fetch_add(1, Relaxed);

    unsafe {
        *length = (*socket.async_context.irp).IoStatus.Information as usize;
    }

    Ok(())
}

struct SendToFuture<'a, 'b, 'c> {
    pending: bool,
    socket: &'a mut KSocket,
    wsk_buffer: &'b mut Buffer,
    flags: u32,
    remote_address: &'c mut SOCKADDR,
}

impl<'a, 'b, 'c> Future for SendToFuture<'a, 'b, 'c> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_DATAGRAM_DISPATCH)).WskSendTo
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = unsafe {
                function(
                    this.socket.wsk_socket as _,
                    &mut **this.wsk_buffer as _,
                    this.flags as c_ulong,
                    this.remote_address as _,
                    0,
                    null_mut() as _,
                    &mut *this.socket.async_context.irp as _,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

struct ReceiveFromFuture<'a, 'b, 'c> {
    pending: bool,
    socket: &'a mut KSocket,
    wsk_buffer: &'b mut Buffer,
    flags: u32,
    remote_address: &'c mut SOCKADDR,
}

impl<'a, 'b, 'c> Future for ReceiveFromFuture<'a, 'b, 'c> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_DATAGRAM_DISPATCH))
                    .WskReceiveFrom
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = unsafe {
                function(
                    this.socket.wsk_socket as _,
                    &mut **this.wsk_buffer as _,
                    this.flags as c_ulong,
                    this.remote_address as _,
                    null_mut() as _,
                    null_mut() as _,
                    null_mut() as _,
                    &mut *this.socket.async_context.irp as _,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

pub async fn send_recv_udp(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    remote_address: &mut SOCKADDR,
    send: bool,
) -> Result<(), Error> {
    let mut wsk_buffer = new_wsk_buf(buffer, length);

    //TODO: "try block"
    //TODO tiene sentido el buff / len parametreo? igual con la 2º parte ta mas claro
    unsafe {
        MmProbeAndLockPages(wsk_buffer.Mdl, KernelMode as KPROCESSOR_MODE, IoWriteAccess);
    }

    async_context_reset(&mut socket.async_context);

    if send {
        match (SendToFuture {
            pending: false,
            socket,
            flags,
            wsk_buffer: &mut wsk_buffer,
            remote_address,
        })
        .await
        {
            Ok(_) => {}
            Err(e) => {
                unsafe {
                    MmUnlockPages(wsk_buffer.Mdl);
                }
                return Err(e);
            }
        }
    } else {
        match (ReceiveFromFuture {
            pending: false,
            socket,
            flags,
            wsk_buffer: &mut wsk_buffer,
            remote_address,
        })
        .await
        {
            Ok(_) => {}
            Err(e) => {
                unsafe {
                    MmUnlockPages(wsk_buffer.Mdl);
                }
                return Err(e);
            }
        }
    };

    unsafe {
        *length = *(((*(socket.async_context.irp)).IoStatus.Information) as *const u64) as usize
    }

    unsafe {
        MmUnlockPages(wsk_buffer.Mdl);
    }

    Ok(())
}

fn new_wsk_buf(buffer: &mut [u8], length: &mut usize) -> Buffer {
    Buffer {
        inner: WSK_BUF {
            Mdl: unsafe {
                IoAllocateMdl(
                    buffer.as_ptr() as _,
                    buffer.len() as ULONG,
                    FALSE,
                    FALSE,
                    null_mut() as _,
                )
            },
            Offset: 0,
            Length: *length as SIZE_T,
        },
    }
}

pub async fn send(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<(), Error> {
    Box::pin(send_recv(socket, buffer, length, flags, true)).await
}

pub async fn recv(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<(), Error> {
    Box::pin(send_recv(socket, buffer, length, flags, false)).await
}

pub async fn send_to(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    remote_address: &mut SOCKADDR,
) -> Result<(), Error> {
    send_recv_udp(socket, buffer, length, flags, remote_address, true).await
}

pub async fn recv_from(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    remote_address: &mut SOCKADDR,
) -> Result<(), Error> {
    send_recv_udp(socket, buffer, length, flags, remote_address, false).await
}

struct ControlFuture<'a, 'b, 'c, 'd, 'e, 'f> {
    pending: bool,
    socket: &'a mut Box<KSocket>,
    request_type: WSK_CONTROL_SOCKET_TYPE,
    control_code: &'b i32,
    option_level: &'c i32,
    in_buffer: *mut u8,
    in_length: &'d mut u32,
    out_buffer: *mut u8,
    out_length: &'e mut u32,
    out_length_returned: &'f mut u32,
}

impl<'a, 'b, 'c, 'd, 'e, 'f> Future for ControlFuture<'a, 'b, 'c, 'd, 'e, 'f> {
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if !this.pending {
            let function = unsafe {
                (*((*this.socket.wsk_socket).Dispatch as PWSK_PROVIDER_BASIC_DISPATCH))
                    .WskControlSocket
            };

            let prkevent = &mut this.socket.async_context.completion_event as PRKEVENT;
            get_event_map().insert(Event::KEvent(prkevent as PRKEVENT), cx.waker().clone());

            let status = unsafe {
                function(
                    this.socket.wsk_socket as _,
                    this.request_type.clone(),
                    *this.control_code as ULONG,
                    *this.option_level as ULONG,
                    *this.in_length as _,
                    this.in_buffer as _,
                    *this.out_length as _,
                    this.out_buffer as _,
                    this.out_length_returned as *mut _ as _,
                    &mut *this.socket.async_context.irp as _,
                )
            };

            if status != 0 && status != 0x00000103 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Err(Error::from_ntstatus(status)));
            }

            if status == 0 {
                delist(Event::KEvent(prkevent as PRKEVENT));
                return Poll::Ready(Ok(()));
            }

            this.pending = true;
            Poll::Pending
        } else {
            let status = unsafe {
                (*this.socket.async_context.irp)
                    .IoStatus
                    .__bindgen_anon_1
                    .Status
            };
            if status == 0 {
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(Error::from_ntstatus(status)))
            }
        }
    }
}

// TODO: control_client()
pub async fn control_socket(
    socket: &mut Box<KSocket>,
    socket_type: u8,
    request_type: WSK_CONTROL_SOCKET_TYPE,
    control_code: &i32,
    option_level: &i32,
    in_buffer: *mut u8,
    in_length: &mut u32,
    out_buffer: *mut u8,
    out_length: &mut u32,
    out_length_returned: &mut u32,
) -> Result<(), Error> {
    if request_type == WskGetOption && *option_level == SOL_SOCKET && *control_code == SO_TYPE {
        if *out_length != size_of::<i32>() as u32 {
            return Err(Error::from_ntstatus(STATUS_INVALID_PARAMETER));
        }

        *out_length_returned = *out_length;

        if socket_type == WSK_FLAG_DATAGRAM_SOCKET {
            unsafe {
                *(out_buffer as *mut i32) = SOCK_DGRAM;
            }
        } else {
            unsafe {
                *(out_buffer as *mut i32) = SOCK_STREAM;
            }
        }
    } else if request_type == WskIoctl
        && (*control_code as u32 == SIO_WSK_SET_REMOTE_ADDRESS
            || *control_code as u32 == SIO_WSK_SET_SENDTO_ADDRESS)
    {
        if socket_type != WSK_FLAG_DATAGRAM_SOCKET {
            return Err(Error::from_ntstatus(STATUS_INVALID_PARAMETER));
        }
        let addr = in_buffer as *mut SOCKADDR;
        bind(socket, addr).await?;
    }

    async_context_reset(&mut socket.async_context);

    return (ControlFuture {
        pending: false,
        socket,
        request_type,
        control_code,
        option_level,
        in_buffer,
        in_length,
        out_buffer,
        out_length,
        out_length_returned,
    })
    .await;
}

pub(crate) fn addr_info_to_addr_info_ex(
    addr_info: *mut ADDRINFOA,
    addr_info_ex: &mut *mut ADDRINFOEXW,
) -> Result<(), Error> {
    if addr_info.is_null() {
        *addr_info_ex = null_mut();
        return Ok(());
    }

    let result = new_addrinfoexw();
    match result {
        AddrInfo::AddrInfoExW(mut result) => {
            unsafe {
                result.ai_flags = (*addr_info).ai_flags;
                result.ai_family = (*addr_info).ai_family;
                result.ai_socktype = (*addr_info).ai_socktype;
                result.ai_protocol = (*addr_info).ai_protocol;
                result.ai_addrlen = (*addr_info).ai_addrlen;
            }

            let mut ansi_name: ANSI_STRING = ANSI_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: null_mut(),
            };
            let mut unicode_name: UNICODE_STRING = create_unicode_string(&[0, 0]);
            let mut status: NTSTATUS = 0;

            unsafe {
                if !(*addr_info).ai_canonname.is_null() {
                    RtlInitAnsiString(&mut ansi_name, (*addr_info).ai_canonname as _);

                    status = RtlAnsiStringToUnicodeString(&mut unicode_name, &mut ansi_name, TRUE);
                }
                if status != 0 {
                    return Err(Error::from_ntstatus(status));
                }

                result.ai_canonname = unicode_name.Buffer;
            }
            unsafe {
                result.ai_addr = (*addr_info).ai_addr;
            }

            let next_addr_info = new_addrinfoexw();
            match next_addr_info {
                AddrInfo::AddrInfoExW(mut next_addr_info) => {
                    match unsafe {
                        addr_info_to_addr_info_ex(
                            (*addr_info).ai_next,
                            &mut (&mut next_addr_info as *mut _),
                        )
                    } {
                        Ok(..) => {}
                        Err(e) => unsafe {
                            RtlFreeAnsiString(&mut ansi_name);
                            return Err(e);
                        },
                    }
                    result.ai_next = &mut next_addr_info as _;

                    *addr_info_ex = &mut result as _;
                }
                _ => return Err(Error::ILLEGAL_INSTRUCTION),
            }
        }
        _ => return Err(Error::ILLEGAL_INSTRUCTION),
    }

    Ok(())
}

fn addr_info_ex_to_addr_info(
    addr_info_ex: *mut ADDRINFOEXW,
    addr_info: &mut *mut ADDRINFOA,
) -> Result<(), Error> {
    if addr_info_ex.is_null() {
        *addr_info = null_mut();
        return Ok(());
    }

    let mut result = Box::new(ADDRINFOA {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_canonname: null_mut(),
        ai_addr: null_mut(),
        ai_next: null_mut(),
    });

    unsafe {
        result.ai_flags = (*addr_info_ex).ai_flags;
        result.ai_family = (*addr_info_ex).ai_family;
        result.ai_socktype = (*addr_info_ex).ai_socktype;
        result.ai_protocol = (*addr_info_ex).ai_protocol;
        result.ai_addrlen = (*addr_info_ex).ai_addrlen;
    }

    let mut ansi_name: ANSI_STRING = ANSI_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: null_mut(),
    };
    let mut unicode_name: UNICODE_STRING = create_unicode_string(&[0, 0]);
    let mut status: NTSTATUS = 0;
    unsafe {
        if !(*addr_info_ex).ai_canonname.is_null() {
            RtlInitUnicodeString(&mut unicode_name, (*addr_info_ex).ai_canonname as _);
            status = RtlUnicodeStringToAnsiString(&mut ansi_name, &unicode_name, TRUE);
        }
    }
    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }

    result.ai_canonname = ansi_name.Buffer as _;
    unsafe {
        result.ai_addr = (*addr_info_ex).ai_addr;
    }

    let next_addr_info = new_addrinfoa();

    if let AddrInfo::AddrInfoA(mut next_addr_info) = next_addr_info {
        match unsafe {
            addr_info_ex_to_addr_info(
                (*addr_info_ex).ai_next,
                &mut (&mut next_addr_info as *mut _),
            )
        } {
            Ok(..) => {}
            Err(e) => unsafe {
                RtlFreeAnsiString(&mut ansi_name);
                return Err(e);
            },
        }
        result.ai_next = &mut next_addr_info as _;

        *addr_info = &mut *result as _;
    }

    Ok(())
}

pub fn new_addrinfoa() -> AddrInfo {
    AddrInfo::AddrInfoA(ADDRINFOA {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_canonname: null_mut(),
        ai_addr: null_mut(),
        ai_next: null_mut(),
    })
}

pub(crate) fn free_addr_info_a(addr_info: ADDRINFOA) -> Result<(), Error> {
    if !addr_info.ai_next.is_null() {
        unsafe {
            free_addr_info_a(*addr_info.ai_next)?;
        }
    }
    if !addr_info.ai_canonname.is_null() {
        let mut ansi_name: ANSI_STRING = ANSI_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: null_mut(),
        };
        unsafe {
            RtlInitAnsiString(&mut ansi_name, addr_info.ai_canonname as *mut _);
            RtlFreeAnsiString(&mut ansi_name);
        }
    }
    Ok(())
}

pub(crate) fn free_addr_info_ex(addr_info: ADDRINFOEXW) -> Result<(), Error> {
    if !addr_info.ai_next.is_null() {
        unsafe {
            free_addr_info_ex(*addr_info.ai_next)?;
        }
    }
    if !addr_info.ai_canonname.is_null() {
        let mut unicode_name: UNICODE_STRING = create_unicode_string(&[0, 0]);

        unsafe {
            RtlInitUnicodeString(&mut unicode_name, addr_info.ai_canonname as *mut _);
            RtlFreeUnicodeString(&mut unicode_name);
        }
    }
    Ok(())
}
