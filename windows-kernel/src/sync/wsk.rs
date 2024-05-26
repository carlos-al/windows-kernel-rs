use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_ulong, c_void};
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr::{addr_of, addr_of_mut, null, null_mut};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::SeqCst;

use windows_kernel_sys::base::_EVENT_TYPE::SynchronizationEvent;
use windows_kernel_sys::base::_KWAIT_REASON::Executive;
use windows_kernel_sys::base::_LOCK_OPERATION::IoWriteAccess;
use windows_kernel_sys::base::_MODE::KernelMode;
use windows_kernel_sys::base::{
    _DISPATCHER_HEADER__bindgen_ty_1, _DISPATCHER_HEADER__bindgen_ty_1__bindgen_ty_7, FALSE,
    IO_NO_INCREMENT, KEVENT, KPRIORITY, KPROCESSOR_MODE, NTSTATUS, PIRP, PUNICODE_STRING, PVOID,
    SIZE_T, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL, TRUE, ULONG, _DEVICE_OBJECT,
    _DISPATCHER_HEADER, _IRP, _KEVENT, _LIST_ENTRY,
};
use windows_kernel_sys::netio::WSK_CONTROL_SOCKET_TYPE::{WskGetOption, WskIoctl};
use windows_kernel_sys::netio::{
    AddrInfoexW, WskCaptureProviderNPI, WskDeregister, WskRegister, WskReleaseProviderNPI,
    ADDRESS_FAMILY, ADDRINFOA, ADDRINFOEXW, AF_INET, IN_ADDR, IN_ADDR_0, PADDRINFOEXW,
    PWSK_PROVIDER_BASIC_DISPATCH, PWSK_PROVIDER_CONNECTION_DISPATCH,
    PWSK_PROVIDER_DATAGRAM_DISPATCH, PWSK_PROVIDER_LISTEN_DISPATCH, PWSK_SOCKET,
    SIO_WSK_SET_REMOTE_ADDRESS, SIO_WSK_SET_SENDTO_ADDRESS, SOCKADDR, SOCKADDR_IN, SOCK_DGRAM,
    SOCK_STREAM, SOL_SOCKET, SO_TYPE, WSK_BUF, WSK_CLIENT_DISPATCH, WSK_CLIENT_NPI,
    WSK_CONTROL_SOCKET_TYPE, WSK_FLAG_CONNECTION_SOCKET, WSK_FLAG_DATAGRAM_SOCKET,
    WSK_FLAG_LISTEN_SOCKET, WSK_INFINITE_WAIT, WSK_PROVIDER_NPI, WSK_REGISTRATION,
};
use windows_kernel_sys::ntoskrnl::{
    IoAllocateIrp, IoAllocateMdl, IoFreeIrp, IoFreeMdl, IoReuseIrp, IoSetCompletionRoutine,
    KeInitializeEvent, KeResetEvent, KeSetEvent, KeWaitForSingleObject, MmProbeAndLockPages,
    MmUnlockPages,
};
use windows_kernel_sys::MAKE_WSK_VERSION;

use crate::sync::berk::Berk;
use crate::{Error, Mutex};

#[repr(C)]
pub struct KSocketAsyncContext {
    pub(crate) completion_event: KEVENT,
    pub(crate) irp: PIRP,
}

impl KSocketAsyncContext {
    pub fn new() -> Self {
        KSocketAsyncContext {
            completion_event: _KEVENT {
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
            },
            irp: null_mut(),
        }
    }
}

enum WskDispatch {
    Connection(PWSK_PROVIDER_CONNECTION_DISPATCH),
    Listen(PWSK_PROVIDER_LISTEN_DISPATCH),
    Datagram(PWSK_PROVIDER_DATAGRAM_DISPATCH),
    // #[cfg(NTDDI_VERSION >= NTDDI_WIN10_RS2)]
    // Stream(PWSK_PROVIDER_STREAM_DISPATCH),
}

#[repr(C)]
pub struct KSocket {
    pub(crate) wsk_socket: PWSK_SOCKET,
    pub(crate) socket_type: u8,
    pub(crate) send_timeout: u32,
    pub(crate) recv_timeout: u32,
    pub(crate) wsk_dispatch: PVOID,
    pub(crate) async_context: KSocketAsyncContext,
}

pub struct Buffer {
    pub(crate) inner: WSK_BUF,
}

impl Deref for Buffer {
    type Target = WSK_BUF;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            IoFreeMdl(self.inner.Mdl);
        }
    }
}

pub struct Wsk {
    pub dispatch: Box<WSK_CLIENT_DISPATCH>,
    pub client: Box<WSK_CLIENT_NPI>,
    pub registration: Box<WSK_REGISTRATION>,
    pub provider: Box<WSK_PROVIDER_NPI>,
    state: AtomicBool,
}

unsafe impl Sync for Wsk {}

unsafe impl Send for Wsk {}

impl Wsk {
    pub fn initialize() -> Result<Wsk, Error> {
        let dispatch: Box<WSK_CLIENT_DISPATCH> = Box::new(WSK_CLIENT_DISPATCH {
            Version: MAKE_WSK_VERSION!(1, 0),
            Reserved: 0,
            WskClientEvent: None,
        });

        let mut client: Box<WSK_CLIENT_NPI> = Box::new(WSK_CLIENT_NPI {
            ClientContext: null_mut(),
            Dispatch: &*dispatch,
        });

        let mut registration: Box<WSK_REGISTRATION> = Box::new(WSK_REGISTRATION {
            ReservedRegistrationState: 0,
            ReservedRegistrationContext: null_mut(),
            ReservedRegistrationLock: 0,
        });
        let mut provider: Box<WSK_PROVIDER_NPI> = Box::new(WSK_PROVIDER_NPI {
            Client: null_mut(),
            Dispatch: null_mut(),
        });

        let status = unsafe { WskRegister(&mut *client, &mut *registration) };
        if status != 0 {
            return Err(Error::from_ntstatus(status));
        }

        let status = unsafe { WskCaptureProviderNPI(&mut *registration, 0xffff, &mut *provider) };
        if status != 0 {
            return Err(Error::from_ntstatus(status));
        }
        let state = AtomicBool::new(true);

        let wsk = Wsk {
            dispatch,
            client,
            registration,
            provider,
            state,
        };
        Ok(wsk)
    }
    pub fn destroy(&self) {
        unsafe {
            // WskDeregister will wait to return until all of the following have completed:
            //
            //     All captured instances of the provider NPI are released.
            //     Any outstanding calls to functions pointed to by WSK_PROVIDER_DISPATCH members have returned.
            //     All sockets are closed.
            WskReleaseProviderNPI(addr_of!(*self.registration).cast_mut());
            WskDeregister(addr_of!(*self.registration).cast_mut());
        }
    }
}

pub type SockFd = usize;

pub enum AddrInfo {
    AddrInfoA(ADDRINFOA),
    AddrInfoExW(ADDRINFOEXW),
    SockAddrIn(SOCKADDR_IN),
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
    unsafe {
        KeResetEvent(&mut context.completion_event);
        IoReuseIrp(context.irp, STATUS_UNSUCCESSFUL);
        IoSetCompletionRoutine(
            context.irp,
            Some(async_context_completion_routine),
            addr_of_mut!(context.completion_event).cast::<c_void>(),
            TRUE,
            TRUE,
            TRUE,
        );
    }
}

#[allow(clippy::cast_possible_wrap)]
unsafe extern "C" fn async_context_completion_routine(
    _device_object: *mut _DEVICE_OBJECT,
    _irp: *mut _IRP,
    completion_event: *mut c_void,
) -> i32 {
    KeSetEvent(completion_event.cast(), IO_NO_INCREMENT as KPRIORITY, FALSE);
    0xC000_0016_u32 as i32
}

fn async_context_wait_for_completion(
    context: &mut KSocketAsyncContext,
    status: &mut NTSTATUS,
) -> NTSTATUS {
    if *status == NTSTATUS::from(0x0000_0103) {
        //pending
        unsafe {
            KeWaitForSingleObject(
                addr_of_mut!(context.completion_event).cast::<c_void>(),
                Executive,
                KernelMode as KPROCESSOR_MODE,
                FALSE,
                null_mut(),
            );
        }
        unsafe {
            *status = (*context.irp).IoStatus.__bindgen_anon_1.Status;
        }
    }
    *status
}

pub fn get_addr_info(
    berk: &Arc<Option<Berk>>,
    berk_status: &Arc<AtomicBool>,
    node_name: PUNICODE_STRING,
    service_name: PUNICODE_STRING,
    hints: &mut AddrInfo,
) -> Result<Box<PADDRINFOEXW>, Error> {
    let mut context = KSocketAsyncContext::new();
    async_context_allocate(&mut context)?;

    let mut result = Box::new(null_mut());

    let result_ref = &mut *result;

    return match berk_status.compare_exchange(false, false, SeqCst, SeqCst) {
        Ok(_) => Err(Error::INSUFFICIENT_RESOURCES),
        Err(_) => {
            if let Some(berk) = berk.as_ref() {
                let function = unsafe { (*(berk.wsk.provider.Dispatch)).WskGetAddressInfo };

                if let AddrInfo::AddrInfoExW(mut hints) = *hints {
                    let mut status = unsafe {
                        function.unwrap()(
                            berk.wsk.provider.Client,
                            node_name,
                            service_name,
                            0,
                            null(),
                            addr_of_mut!(hints).cast::<AddrInfoexW>(),
                            result_ref,
                            null_mut(),
                            null_mut(),
                            context.irp,
                        )
                    };

                    async_context_wait_for_completion(&mut context, &mut status);
                    async_context_free(&mut context);

                    Ok(result)
                } else {
                    async_context_free(&mut context);
                    Err(Error::UNSUCCESSFUL)
                }
            } else {
                Err(Error::INSUFFICIENT_RESOURCES)
            }
        }
    };
}

pub fn free_addr_info(berk: &Mutex<Wsk>, addr_info: &mut AddrInfoexW) {
    let function = unsafe { (*(berk.lock().unwrap().provider.Dispatch)).WskFreeAddressInfo };
    unsafe { function.unwrap()(berk.lock().unwrap().provider.Client, addr_info) }
}

pub fn create_socket(
    berk: &Arc<Option<Berk>>,
    berk_status: &Arc<AtomicBool>,
    address_family: ADDRESS_FAMILY,
    socket_type: u8,
    protocol: u32,
    flags: u8,
) -> Result<Box<KSocket>, Error> {
    return match berk_status.compare_exchange(false, false, SeqCst, SeqCst) {
        Ok(_) => Err(Error::INSUFFICIENT_RESOURCES),
        Err(_) => {
            if let Some(berk) = berk.as_ref() {
                let mut new_socket = new_ksocket();
                new_socket.socket_type = socket_type;
                async_context_allocate(&mut new_socket.async_context)?;
                let function = unsafe { (*(berk.wsk.provider.Dispatch)).WskSocket };

                let mut status: NTSTATUS = unsafe {
                    function.unwrap()(
                        berk.wsk.provider.Client,
                        address_family,
                        u16::from(socket_type),
                        protocol,
                        u32::from(flags),
                        null_mut(),
                        null_mut(),
                        null_mut(),
                        null_mut(),
                        null_mut(),
                        new_socket.async_context.irp,
                    )
                };

                async_context_wait_for_completion(&mut new_socket.async_context, &mut status);
                if status == 0 {
                    new_socket.wsk_socket = unsafe { *new_socket.async_context.irp }
                        .IoStatus
                        .Information as PWSK_SOCKET;
                    new_socket.wsk_dispatch = unsafe { *(*new_socket.wsk_socket).Dispatch };
                } else {
                    return Err(Error::from_ntstatus(status));
                }

                Ok(new_socket)
            } else {
                Err(Error::INSUFFICIENT_RESOURCES)
            }
        }
    };
}

#[allow(clippy::unnecessary_box_returns)]
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

pub fn create_connection_socket(
    berk: &Arc<Option<Berk>>,
    berk_status: &Arc<AtomicBool>,
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
}

pub fn create_listen_socket(
    berk: &Arc<Option<Berk>>,
    berk_status: &Arc<AtomicBool>,
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
}

pub fn create_datagram_socket(
    berk: &Arc<Option<Berk>>,
    berk_status: &Arc<AtomicBool>,
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
}

pub fn disconnect_socket(socket: &mut KSocket) -> Result<(), Error> {
    //async_context_reset(&mut socket.async_context); TODO: Creating a new context for every close is required `just` to cancel an in-progress irp , can you make it just for the ones that need canceling? i.e if close has been called explicitly by socket users, you could assume all pending irps have been completed and avoid this extra allocation
    let mut new = KSocketAsyncContext::new();
    async_context_allocate(&mut new)?;

    let function = unsafe {
        (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH)).WskDisconnect
    };
    let mut status = unsafe { function(socket.wsk_socket, null_mut(), 0, new.irp) };

    async_context_wait_for_completion(&mut new, &mut status);
    async_context_free(&mut new);
    //async_context_free(&mut socket.async_context);

    Ok(())
}

pub fn close_socket(socket: &mut KSocket) -> Result<(), Error> {
    //async_context_reset(&mut socket.async_context); TODO: Creating a new context for every close is required `just` to cancel an in-progress irp , can you make it just for the ones that need canceling? i.e if close has been called explicitly by socket users, you could assume all pending irps have been completed and avoid this extra allocation
    let mut new = KSocketAsyncContext::new();
    async_context_allocate(&mut new)?;

    let function = unsafe {
        (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_BASIC_DISPATCH)).WskCloseSocket
    };
    let mut status = function(socket.wsk_socket, new.irp);

    async_context_wait_for_completion(&mut new, &mut status);
    async_context_free(&mut new);
    async_context_free(&mut socket.async_context);

    Ok(())
}

pub fn bind(socket: &mut Box<KSocket>, local_address: *mut SOCKADDR) -> Result<(), Error> {
    async_context_reset(&mut socket.async_context);

    let function =
        unsafe { (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_LISTEN_DISPATCH)).WskBind };

    let mut status = unsafe {
        function(
            socket.wsk_socket.cast(),
            local_address,
            0,
            socket.async_context.irp,
        )
    };
    async_context_wait_for_completion(&mut socket.async_context, &mut status);
    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }

    Ok(())
}

pub fn accept(
    socket: &mut KSocket,
    local_address: &mut SOCKADDR,
    remote_address: *mut SOCKADDR,
) -> Result<Box<KSocket>, Error> {
    async_context_reset(&mut socket.async_context);

    let accept_fn =
        unsafe { (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_LISTEN_DISPATCH)).WskAccept };
    let mut status = unsafe {
        accept_fn(
            socket.wsk_socket.cast(),
            0,
            null_mut(),
            null_mut(),
            (local_address as *mut SOCKADDR).cast(),
            remote_address.cast(),
            socket.async_context.irp,
        )
    };
    async_context_wait_for_completion(&mut socket.async_context, &mut status);
    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }

    let returned_socket =
        (unsafe { *socket.async_context.irp }).IoStatus.Information as PWSK_SOCKET;
    let mut new_socket = Box::new(KSocket {
        wsk_socket: returned_socket,
        socket_type: socket.socket_type,
        send_timeout: socket.send_timeout,
        recv_timeout: socket.recv_timeout,
        wsk_dispatch: unsafe { *(*returned_socket).Dispatch },
        async_context: KSocketAsyncContext::new(),
    });
    async_context_allocate(&mut new_socket.async_context)?;

    Ok(new_socket)
}

pub fn connect(socket: &mut Box<KSocket>, remote_address: *mut SOCKADDR) -> Result<(), Error> {
    async_context_reset(&mut socket.async_context);

    let mut local_address = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 { S_addr: 0 },
        },
        sin_zero: [0; 8],
    };
    let function =
        unsafe { (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH)).WskBind };

    let mut status = unsafe {
        function(
            socket.wsk_socket.cast(),
            addr_of_mut!(local_address).cast(),
            0,
            socket.async_context.irp,
        )
    };
    async_context_wait_for_completion(&mut socket.async_context, &mut status);
    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }

    async_context_reset(&mut socket.async_context);

    let function = unsafe {
        (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH))
            .WskConnect
            .unwrap()
    };
    let mut status = unsafe {
        function(
            socket.wsk_socket,
            remote_address,
            0,
            socket.async_context.irp,
        )
    };

    async_context_wait_for_completion(&mut socket.async_context, &mut status);
    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
pub fn send_recv(
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
    }

    async_context_reset(&mut socket.async_context);

    let mut status: NTSTATUS = if send {
        let function = unsafe {
            (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH)).WskSend
        };
        unsafe {
            function(
                socket.wsk_socket,
                &mut *wsk_buffer as _,
                flags as c_ulong,
                socket.async_context.irp,
            )
        }
    } else {
        let function = unsafe {
            (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_CONNECTION_DISPATCH)).WskReceive
        };
        unsafe {
            function(
                socket.wsk_socket,
                &mut *wsk_buffer as _,
                flags as c_ulong,
                socket.async_context.irp,
            )
        }
    };

    async_context_wait_for_completion(&mut socket.async_context, &mut status);
    if status == 0 {
        unsafe {
            *length = (*socket.async_context.irp).IoStatus.Information as usize;
        }
    }

    unsafe {
        MmUnlockPages(wsk_buffer.Mdl);
    }
    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }

    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
pub fn send_recv_udp(
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

    let mut status: NTSTATUS = if send {
        let function = unsafe {
            (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_DATAGRAM_DISPATCH)).WskSendTo
        };
        unsafe {
            function(
                socket.wsk_socket,
                &mut *wsk_buffer as _,
                flags as c_ulong,
                remote_address as _,
                0,
                null_mut(),
                socket.async_context.irp,
            )
        }
    } else {
        let function = unsafe {
            (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_DATAGRAM_DISPATCH)).WskReceiveFrom
        };
        unsafe {
            function(
                socket.wsk_socket,
                &mut *wsk_buffer as _,
                flags as c_ulong,
                remote_address as _,
                null_mut(),
                null_mut(),
                null_mut(),
                socket.async_context.irp,
            )
        }
    };
    async_context_wait_for_completion(&mut socket.async_context, &mut status);
    if status == 0 {
        unsafe {
            *length = *((*(socket.async_context.irp)).IoStatus.Information as *const u64) as usize;
        }
    }

    unsafe {
        MmUnlockPages(wsk_buffer.Mdl);
    }

    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }
    Ok(())
}

#[allow(clippy::cast_possible_truncation)]
fn new_wsk_buf(buffer: &mut [u8], length: &mut usize) -> Buffer {
    Buffer {
        inner: WSK_BUF {
            Mdl: unsafe {
                IoAllocateMdl(
                    buffer.as_ptr() as _,
                    buffer.len() as ULONG,
                    FALSE,
                    FALSE,
                    null_mut(),
                )
            },
            Offset: 0,
            Length: *length as SIZE_T,
        },
    }
}

pub fn send(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<(), Error> {
    send_recv(socket, buffer, length, flags, true)
}

pub fn recv(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<(), Error> {
    send_recv(socket, buffer, length, flags, false)
}

pub fn send_to(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    remote_address: &mut SOCKADDR,
) -> Result<(), Error> {
    send_recv_udp(socket, buffer, length, flags, remote_address, true)
}

pub fn recv_from(
    socket: &mut KSocket,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    remote_address: &mut SOCKADDR,
) -> Result<(), Error> {
    send_recv_udp(socket, buffer, length, flags, remote_address, false)
}

// TODO: control_client()
#[allow(clippy::cast_possible_truncation)]
pub fn control_socket(
    socket: &mut Box<KSocket>,
    socket_type: u8,
    request_type: WSK_CONTROL_SOCKET_TYPE,
    control_code: &u32,
    option_level: &u32,
    in_buffer: *mut u8,
    in_length: &mut u32,
    out_buffer: *mut u8,
    out_length: &mut u32,
    out_length_returned: &mut u32,
) -> Result<(), Error> {
    if request_type == WskGetOption
        && *option_level == SOL_SOCKET as u32
        && *control_code == SO_TYPE as u32
    {
        if *out_length as usize != size_of::<i32>() {
            return Err(Error::from_ntstatus(STATUS_INVALID_PARAMETER));
        }

        *out_length_returned = *out_length;

        if socket_type == WSK_FLAG_DATAGRAM_SOCKET {
            unsafe {
                *out_buffer = SOCK_DGRAM as u8;
            }
        } else {
            unsafe {
                *out_buffer = SOCK_STREAM as u8;
            }
        }
    } else if request_type == WskIoctl
        && (*control_code == SIO_WSK_SET_REMOTE_ADDRESS
            || *control_code == SIO_WSK_SET_SENDTO_ADDRESS)
    {
        if socket_type != WSK_FLAG_DATAGRAM_SOCKET {
            return Err(Error::from_ntstatus(STATUS_INVALID_PARAMETER));
        }
        let addr = in_buffer as *mut SOCKADDR;
        bind(socket, addr)?;
    }

    async_context_reset(&mut socket.async_context);

    let function = unsafe {
        (*((*socket.wsk_socket).Dispatch as PWSK_PROVIDER_BASIC_DISPATCH)).WskControlSocket
    };

    let mut status = unsafe {
        function(
            socket.wsk_socket,
            request_type,
            *control_code as ULONG,
            *option_level as ULONG,
            *in_length as _,
            in_buffer.cast(),
            *out_length as _,
            out_buffer.cast(),
            (out_length_returned as *mut u32).cast(),
            socket.async_context.irp,
        )
    };
    async_context_wait_for_completion(&mut socket.async_context, &mut status);
    if status != 0 {
        return Err(Error::from_ntstatus(status));
    }

    Ok(())
}
