use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::sync::Arc;
use core::mem::size_of;
use core::ptr::{addr_of_mut, null_mut};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::SeqCst;

use futures::Stream;

use windows_kernel_sys::base::{ANSI_STRING, NTSTATUS, PUNICODE_STRING, TRUE, UNICODE_STRING};
use windows_kernel_sys::netio::WSK_CONTROL_SOCKET_TYPE::{WskGetOption, WskIoctl, WskSetOption};
use windows_kernel_sys::netio::{
    ADDRESS_FAMILY, ADDRINFOEXW, AF_INET, AF_UNSPEC, AI_CANONNAME, IN_ADDR, IN_ADDR_0, IPPROTO_TCP,
    PADDRINFOEXW, SOCKADDR, SOCKADDR_IN, SOCK_STREAM, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO,
    WINSOCK_SOCKET_TYPE, WSK_FLAG_INVALID_SOCKET,
};
use windows_kernel_sys::ntoskrnl::{
    RtlAnsiStringToUnicodeString, RtlFreeUnicodeString, RtlInitAnsiString,
};

use crate::asynk::wsk;
use crate::asynk::wsk::{disconnect_socket, new_addrinfoa};
use crate::string::create_unicode_string;
use crate::sync::berk::Berk;
use crate::sync::wsk::{AddrInfo, KSocket};
use crate::{println, Error};

pub async fn get_addr_info(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    node: *mut u8,
    service: *mut u8,
    hints: &mut AddrInfo,
    result: &mut Box<PADDRINFOEXW>,
) -> Result<(), Error> {
    let mut node_ansi_name: ANSI_STRING = ANSI_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: null_mut(),
    };
    let mut node_unicode_name: UNICODE_STRING = create_unicode_string(&[0, 0]);
    let mut node_name: PUNICODE_STRING = null_mut();
    let mut status: NTSTATUS;

    if !node.is_null() {
        unsafe {
            RtlInitAnsiString(&mut node_ansi_name, node as _);
            status =
                RtlAnsiStringToUnicodeString(&mut node_unicode_name, &mut node_ansi_name, TRUE);
        }
        if status != 0 {
            return Err(Error::from_ntstatus(status));
        }
        node_name = &mut node_unicode_name;
    }

    let mut service_ansi_name: ANSI_STRING = ANSI_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: null_mut(),
    };
    let mut service_unicode_name: UNICODE_STRING = create_unicode_string(&[0, 0]);
    let mut service_name: PUNICODE_STRING = null_mut();

    if !service.is_null() {
        unsafe {
            RtlInitAnsiString(&mut service_ansi_name, service as _);
            status = RtlAnsiStringToUnicodeString(
                &mut service_unicode_name,
                &mut service_ansi_name,
                TRUE,
            );
        }

        if status != 0 {
            unsafe {
                RtlFreeUnicodeString(&mut node_unicode_name);
            }
            return Err(Error::from_ntstatus(status));
        }
        service_name = &mut service_unicode_name;
    }

    let mut hints_exw = new_addrinfoexw();
    match (hints, &mut hints_exw) {
        (AddrInfo::AddrInfoA(hints), AddrInfo::AddrInfoExW(mut hints_exw)) => {
            match wsk::addr_info_to_addr_info_ex(hints, &mut (&mut hints_exw as *mut _)) {
                Ok(_) => {}
                Err(e) => unsafe {
                    RtlFreeUnicodeString(&mut node_unicode_name);
                    RtlFreeUnicodeString(&mut service_unicode_name);
                    return Err(e);
                },
            };
        }
        _ => {
            return Err(Error::ILLEGAL_INSTRUCTION);
        }
    }

    match wsk::get_addr_info(
        berk,
        berk_status,
        node_name as _,
        service_name as _,
        &mut hints_exw,
    )
    .await
    {
        Ok(r) => *result = r,
        Err(e) => unsafe {
            RtlFreeUnicodeString(&mut node_unicode_name);
            RtlFreeUnicodeString(&mut service_unicode_name);
            return Err(e);
        },
    };
    if let AddrInfo::AddrInfoExW(Hints) = hints_exw {
        unsafe {
            RtlFreeUnicodeString(&mut node_unicode_name);
            RtlFreeUnicodeString(&mut service_unicode_name);
        }
        wsk::free_addr_info_ex(Hints)?;
    }

    Ok(())
}

pub fn free_addr_info(addr_info: AddrInfo) -> Result<(), Error> {
    match addr_info {
        AddrInfo::AddrInfoA(addr_info) => wsk::free_addr_info_a(addr_info)?,
        AddrInfo::AddrInfoExW(addr_info) => wsk::free_addr_info_ex(addr_info)?,
        _ => {}
    }

    Ok(())
}

pub async fn socket_connection(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    domain: ADDRESS_FAMILY,
    type_of: WINSOCK_SOCKET_TYPE,
    protocol: i32,
) -> Result<Box<KSocket>, Error> {
    let socket =
        wsk::create_connection_socket(berk, berk_status, domain, type_of as u8, protocol as u32)
            .await?;
    Ok(socket)
}

pub async fn socket_listen(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    domain: ADDRESS_FAMILY,
    type_of: i32,
    protocol: i32,
) -> Result<Box<KSocket>, Error> {
    let socket = match protocol {
        0 => {
            wsk::create_listen_socket(
                berk,
                berk_status,
                domain as ADDRESS_FAMILY,
                type_of as u8,
                IPPROTO_TCP as u32,
            )
            .await?
        }
        _ => {
            wsk::create_listen_socket(
                berk,
                berk_status,
                domain as ADDRESS_FAMILY,
                type_of as u8,
                protocol as u32,
            )
            .await?
        }
    };

    Ok(socket)
}

pub async fn socket_datagram(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    domain: i32,
    type_of: i32,
    protocol: i32,
) -> Result<Box<KSocket>, Error> {
    let socket = wsk::create_datagram_socket(
        berk,
        berk_status,
        domain as ADDRESS_FAMILY,
        type_of as u8,
        protocol as u32,
    )
    .await?;

    Ok(socket)
}

pub async fn connect(socket: &mut Box<KSocket>, addr: *mut SOCKADDR) -> Result<(), Error> {
    wsk::connect(socket, addr).await?;
    Ok(())
}

pub async fn bind(
    socket: &mut Box<KSocket>,
    addr: &mut SOCKADDR,
    _addr_len: usize,
) -> Result<(), Error> {
    wsk::bind(socket, addr).await?;
    Ok(())
}

pub async fn accept(socket: &mut Box<KSocket>, addr: *mut SOCKADDR) -> Result<Box<KSocket>, Error> {
    let new_socket = wsk::accept(
        socket,
        &mut SOCKADDR {
            sa_family: 0,
            sa_data: [0; 14],
        },
        addr,
    )
    .await?;

    Ok(new_socket)
}

pub async fn send(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<usize, Error> {
    Box::pin(wsk::send(socket, buffer, length, flags)).await?;
    Ok(*length)
}

pub async fn send_to(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    addr: &mut SOCKADDR,
    _addr_len: usize,
) -> Result<usize, Error> {
    Box::pin(wsk::send_to(socket, buffer, length, flags, addr)).await?;
    Ok(*length)
}

pub async fn recv(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<usize, Error> {
    Box::pin(wsk::recv(socket, buffer, length, flags)).await?;
    Ok(*length)
}

pub async fn recv_from(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    addr: &mut SOCKADDR,
    addr_len: &mut usize,
) -> Result<usize, Error> {
    wsk::send_to(socket, buffer, length, flags, addr).await?;
    *addr_len = size_of::<SOCKADDR>();
    Ok(*length)
}

pub async fn close_socket(socket: &mut Box<KSocket>) -> Result<(), Error> {
    wsk::close_socket(socket).await?;

    Ok(())
}

pub async fn ioctl(
    socket: &mut Box<KSocket>,
    control_code: &i32,
    in_buffer: *mut u8,
    in_length: &mut u32,
    out_buffer: *mut u8,
    out_length: &mut u32,
    out_length_returned: &mut u32,
) -> Result<(), Error> {
    *out_length_returned = 0;

    if socket.socket_type == WSK_FLAG_INVALID_SOCKET {
        return Err(Error::NOT_IMPLEMENTED);
    }
    wsk::control_socket(
        socket,
        socket.socket_type,
        WskIoctl,
        control_code,
        &0,
        in_buffer,
        in_length,
        out_buffer,
        out_length,
        out_length_returned,
    )
    .await?;

    Ok(())
}

//TODO : send/recv/from/to with timeouts

pub async fn set_socket_opt(
    socket: &mut Box<KSocket>,
    option_level: i32,
    option_name: i32,
    in_buffer: *mut u8,
    in_length: &mut u32,
) -> Result<(), Error> {
    if socket.socket_type == WSK_FLAG_INVALID_SOCKET {
        return Err(Error::NOT_IMPLEMENTED);
    }

    if option_level == SOL_SOCKET && (option_name == SO_SNDTIMEO || option_name == SO_RCVTIMEO) {
        if *in_length != size_of::<u32>() as u32 || in_buffer.is_null() {
            return Err(Error::INVALID_PARAMETER);
        }
        if option_name == SO_SNDTIMEO {
            unsafe {
                socket.send_timeout = *(in_buffer as *mut u32);
            }
        }
        if option_name == SO_RCVTIMEO {
            unsafe {
                socket.send_timeout = *(in_buffer as *mut u32);
            }
        }
    }

    wsk::control_socket(
        socket,
        socket.socket_type,
        WskSetOption,
        &option_name,
        &option_level,
        in_buffer,
        in_length,
        null_mut(),
        &mut 0,
        &mut 0,
    )
    .await?;

    Ok(())
}

pub async fn get_socket_opt(
    socket: &mut Box<KSocket>,
    option_level: i32,
    option_name: i32,
    out_buffer: *mut u8,
    out_length: &mut u32,
) -> Result<(), Error> {
    if socket.socket_type == WSK_FLAG_INVALID_SOCKET {
        return Err(Error::NOT_IMPLEMENTED);
    }

    if option_level == SOL_SOCKET && (option_name == SO_SNDTIMEO || option_name == SO_RCVTIMEO) {
        if *out_length != size_of::<u32>() as u32 || out_buffer.is_null() {
            return Err(Error::INVALID_PARAMETER);
        }
        if option_name == SO_SNDTIMEO {
            unsafe {
                *(out_buffer as *mut u32) = socket.send_timeout;
            }
        }
        if option_name == SO_RCVTIMEO {
            unsafe {
                *(out_buffer as *mut u32) = socket.recv_timeout;
            }
        }
        *out_length = size_of::<u32>() as u32; // redundant
    }

    wsk::control_socket(
        socket,
        socket.socket_type,
        WskGetOption,
        &option_name,
        &option_level,
        null_mut(),
        &mut 0,
        out_buffer,
        &mut out_length.clone(),
        out_length,
    )
    .await?;

    Ok(())
}

pub fn new_addrinfoexw() -> AddrInfo {
    AddrInfo::AddrInfoExW(ADDRINFOEXW {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_canonname: null_mut() as _,
        ai_addr: null_mut() as _,
        ai_blob: null_mut() as _,
        ai_bloblen: 0,
        ai_provider: null_mut() as _,
        ai_next: null_mut() as _,
    })
}

pub fn new_sockaddr_in() -> AddrInfo {
    AddrInfo::SockAddrIn(SOCKADDR_IN {
        sin_family: 0,
        sin_port: 0,
        sin_addr: IN_ADDR {
            S_un: IN_ADDR_0 { S_addr: 0x00000000 },
        },
        sin_zero: [0; 8],
    })
}

pub struct TcpSocket {
    socket: Box<KSocket>,
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
}

pub struct TcpStream {
    socket: Box<KSocket>,
    async_closed: AtomicBool,
}

pub struct TcpListener {
    socket: Box<KSocket>,
    addr: AddrInfo,
    async_closed: AtomicBool,
}

impl TcpStream {
    pub async fn send(&mut self, send_buffer: &mut [u8]) -> Result<usize, Error> {
        Box::pin(send(
            &mut self.socket,
            send_buffer,
            &mut send_buffer.len(),
            0,
        ))
        .await
    }
    pub async fn recv_all(&mut self, recv_buffer: &mut [u8]) -> Result<usize, Error> {
        Box::pin(recv(
            &mut self.socket,
            recv_buffer,
            &mut recv_buffer.len(),
            0,
        ))
        .await
    }

    fn sync_close(&mut self) {
        let _ = crate::sync::wsk::close_socket(self.socket.as_mut());
    }

    fn sync_disconnect(&mut self) {
        let _ = crate::sync::wsk::disconnect_socket(self.socket.as_mut());
    }

    pub async fn close(mut self) {
        Box::pin(disconnect_socket(&mut self.socket)).await.unwrap();
        Box::pin(close_socket(&mut self.socket)).await.unwrap();
        self.async_closed.store(true, SeqCst);
    }

    pub async fn disconnect(&mut self) {
        Box::pin(disconnect_socket(&mut self.socket)).await.unwrap();
    }
}

unsafe impl Send for TcpStream {}

impl TcpSocket {
    pub async fn new_v4(
        berk: Arc<Option<Berk>>,
        berk_status: Arc<AtomicBool>,
    ) -> Result<TcpSocket, Error> {
        let mut socket = Box::pin(socket_connection(
            berk.clone(),
            berk_status.clone(),
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
        ))
        .await?;

        Ok(TcpSocket {
            socket,
            berk,
            berk_status,
        })
    }
    pub async fn connect(mut self, addr: &str, port: &str) -> Result<TcpStream, Error> {
        let mut hints = new_addrinfoa();
        let mut res = Box::new(null_mut()) as Box<PADDRINFOEXW>;

        if let AddrInfo::AddrInfoA(mut hints) = hints {
            hints.ai_flags |= AI_CANONNAME as i32;
            hints.ai_family = AF_UNSPEC as i32;
            hints.ai_socktype = SOCK_STREAM;
        }

        let address = CString::new(addr).expect("KO");
        let address_ptr = address.as_ptr() as *mut u8;
        let port = CString::new(port).expect("KO");
        let port_ptr = port.as_ptr() as *mut u8;
        Box::pin(get_addr_info(
            self.berk.clone(),
            self.berk_status.clone(),
            address_ptr,
            port_ptr,
            &mut hints,
            &mut res,
        ))
        .await?;

        let addr: &mut SOCKADDR;
        if res.is_null() || (*res).is_null() || unsafe { (**res).ai_addr.is_null() } {
            return Err(Error::UNSUCCESSFUL);
        }

        unsafe {
            addr = &mut *(**res).ai_addr as &mut _;
        }

        Box::pin(connect(&mut self.socket, addr)).await?;

        Ok(TcpStream {
            socket: self.socket,
            async_closed: AtomicBool::new(false),
        })
    }
}

impl TcpListener {
    pub async fn bind(
        berk: Arc<Option<Berk>>,
        berk_status: Arc<AtomicBool>,
        address: &str,
        port: &str,
    ) -> Result<TcpListener, Error> {
        let mut socket = Box::pin(socket_listen(
            berk.clone(),
            berk_status.clone(),
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
        ))
        .await?;

        let addr = new_sockaddr_in();
        if let AddrInfo::SockAddrIn(mut addr) = addr {
            addr.sin_port = htons(port.parse::<u16>().unwrap());
            addr.sin_family = AF_INET;
            addr.sin_addr.S_un.S_addr = 0;

            Box::pin(bind(
                &mut socket,
                unsafe { &mut *(addr_of_mut!(addr).cast::<SOCKADDR>()) as &mut _ },
                0,
            ))
            .await?;
        }

        Ok(TcpListener {
            socket,
            addr,
            async_closed: AtomicBool::new(false),
        })
    }

    pub async fn accept(&mut self) -> Result<TcpStream, Error> {
        let new_socket =
            match Box::pin(accept(&mut self.socket, addr_of_mut!(self.addr).cast())).await {
                Ok(sock) => sock,
                Err(e) => {
                    println!("falied as {:?}", e);
                    return Err(e);
                }
            };

        Ok(TcpStream {
            socket: new_socket,
            async_closed: AtomicBool::new(false),
        })
    }
    fn sync_close(&mut self) {
        let _ = crate::sync::wsk::close_socket(self.socket.as_mut());
    }
    fn sync_disconnect(&mut self) {
        let _ = crate::sync::wsk::disconnect_socket(self.socket.as_mut());
    }

    pub fn as_stream<'a>(&'a mut self) -> impl Stream<Item = Result<TcpStream, Error>> + 'a {
        futures::stream::unfold(self, |listener| async {
            let stream = listener.accept().await;
            Some((stream, listener))
        })
    }

    pub async fn close(mut self) {
        Box::pin(close_socket(&mut self.socket)).await.unwrap();
        self.async_closed.store(true, SeqCst);
    }

    pub async fn disconnect(&mut self) {
        Box::pin(disconnect_socket(&mut self.socket)).await.unwrap();
    }
}

fn inet_addr(ip_str: &str) -> Option<u32> {
    let mut result = 0u32;
    let mut shift = 24;

    for octet_str in ip_str.split('.') {
        if let Ok(octet) = octet_str.parse::<u8>() {
            result |= u32::from(octet) << shift;
            shift -= 8;
        } else {
            return None; // Invalid octet
        }
    }

    Some(result)
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if !self.async_closed.load(SeqCst) {
            //TODO: proper sync
            self.sync_disconnect();
            self.sync_close();
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if !self.async_closed.load(SeqCst) {
            //TODO: proper sync
            //self.sync_disconnect();
            self.sync_close();
        }
    }
}

fn htons(hostshort: u16) -> u16 {
    hostshort.to_be()
}
