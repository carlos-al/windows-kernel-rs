use alloc::boxed::Box;
use alloc::ffi::CString;
use alloc::sync::Arc;
use core::mem::size_of;
use core::ptr::{addr_of_mut, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};

use futures::Stream;

use windows_kernel_sys::base::{ANSI_STRING, NTSTATUS, PUNICODE_STRING, TRUE, UNICODE_STRING};
use windows_kernel_sys::netio::WSK_CONTROL_SOCKET_TYPE::{WskGetOption, WskIoctl, WskSetOption};
use windows_kernel_sys::netio::{
    htons, ADDRESS_FAMILY, ADDRINFOA, ADDRINFOEXW, AF_INET, AF_UNSPEC, AI_CANONNAME, IN_ADDR,
    IN_ADDR_0, IPPROTO_TCP, PADDRINFOEXW, SOCKADDR, SOCKADDR_IN, SOCK_STREAM, SOL_SOCKET,
    SO_RCVTIMEO, SO_SNDTIMEO, WINSOCK_SOCKET_TYPE, WSK_FLAG_INVALID_SOCKET,
};
use windows_kernel_sys::ntoskrnl::{
    RtlAnsiStringToUnicodeString, RtlFreeAnsiString, RtlFreeUnicodeString, RtlInitAnsiString,
    RtlInitUnicodeString, RtlUnicodeStringToAnsiString,
};

use crate::string::create_unicode_string;
use crate::sync::wsk::{self, AddrInfo, KSocket, Wsk};
use crate::Error;

pub struct Berk {
    pub wsk: Wsk,
}

impl Berk {
    pub fn initialize() -> Result<Self, Error> {
        Ok(Berk {
            wsk: Wsk::initialize()?,
        })
    }
}

fn addr_info_to_addr_info_ex(
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

fn free_addr_info_a(addr_info: ADDRINFOA) -> Result<(), Error> {
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

fn free_addr_info_ex(addr_info: ADDRINFOEXW) -> Result<(), Error> {
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

pub fn get_addr_info(
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
            match addr_info_to_addr_info_ex(hints, &mut (&mut hints_exw as *mut _)) {
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
        &berk,
        &berk_status,
        node_name as _,
        service_name as _,
        &mut hints_exw,
    ) {
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
        free_addr_info_ex(Hints)?;
    }

    Ok(())
}

pub fn free_addr_info(addr_info: AddrInfo) -> Result<(), Error> {
    match addr_info {
        AddrInfo::AddrInfoA(addr_info) => free_addr_info_a(addr_info)?,
        AddrInfo::AddrInfoExW(addr_info) => free_addr_info_ex(addr_info)?,
        _ => {}
    }

    Ok(())
}

pub fn socket_connection(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    domain: ADDRESS_FAMILY,
    type_of: WINSOCK_SOCKET_TYPE,
    protocol: i32,
) -> Result<Box<KSocket>, Error> {
    wsk::create_connection_socket(&berk, &berk_status, domain, type_of as u8, protocol as u32)
}

pub fn socket_listen(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    domain: ADDRESS_FAMILY,
    type_of: i32,
    protocol: i32,
) -> Result<Box<KSocket>, Error> {
    match protocol {
        0 => wsk::create_listen_socket(
            &berk,
            &berk_status,
            domain as ADDRESS_FAMILY,
            type_of as u8,
            IPPROTO_TCP as u32,
        ),
        _ => wsk::create_listen_socket(
            &berk,
            &berk_status,
            domain as ADDRESS_FAMILY,
            type_of as u8,
            protocol as u32,
        ),
    }
}

pub fn socket_datagram(
    berk: Arc<Option<Berk>>,
    berk_status: Arc<AtomicBool>,
    domain: i32,
    type_of: i32,
    protocol: i32,
) -> Result<Box<KSocket>, Error> {
    wsk::create_datagram_socket(
        &berk,
        &berk_status,
        domain as ADDRESS_FAMILY,
        type_of as u8,
        protocol as u32,
    )
}

pub fn connect(socket: &mut Box<KSocket>, addr: *mut SOCKADDR) -> Result<(), Error> {
    wsk::connect(socket, addr)
}

pub fn bind(socket: &mut Box<KSocket>, addr: &mut SOCKADDR, _addr_len: usize) -> Result<(), Error> {
    wsk::bind(socket, addr)
}

pub fn accept(socket: &mut Box<KSocket>, addr: *mut SOCKADDR) -> Result<Box<KSocket>, Error> {
    let new_socket = wsk::accept(
        socket,
        &mut SOCKADDR {
            sa_family: 0,
            sa_data: [0; 14],
        },
        addr,
    )?;

    Ok(new_socket)
}

pub fn send(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<usize, Error> {
    wsk::send(socket, buffer, length, flags)?;

    Ok(*length)
}

pub fn send_to(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    addr: &mut SOCKADDR,
    _addr_len: usize,
) -> Result<usize, Error> {
    wsk::send_to(socket, buffer, length, flags, addr)?;

    Ok(*length)
}

pub fn recv(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
) -> Result<usize, Error> {
    wsk::recv(socket, buffer, length, flags)?;

    Ok(*length)
}

pub fn recv_from(
    socket: &mut Box<KSocket>,
    buffer: &mut [u8],
    length: &mut usize,
    flags: u32,
    addr: &mut SOCKADDR,
    addr_len: &mut usize,
) -> Result<usize, Error> {
    wsk::recv_from(socket, buffer, length, flags, addr)?;
    *addr_len = size_of::<SOCKADDR>();

    Ok(*length)
}

pub fn close_socket(socket: &mut Box<KSocket>) -> Result<(), Error> {
    wsk::close_socket(socket)
}

pub fn ioctl(
    socket: &mut Box<KSocket>,
    control_code: &u32,
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
}

//TODO : send/recv/from/to with timeouts

pub fn set_socket_opt(
    socket: &mut Box<KSocket>,
    option_level: u32,
    option_name: u32,
    in_buffer: *mut u8,
    in_length: &mut u32,
) -> Result<(), Error> {
    if socket.socket_type == WSK_FLAG_INVALID_SOCKET {
        return Err(Error::NOT_IMPLEMENTED);
    }

    if option_level == SOL_SOCKET as u32
        && (option_name == SO_SNDTIMEO as u32 || option_name == SO_RCVTIMEO as u32)
    {
        if *in_length != size_of::<u32>() as u32 || in_buffer.is_null() {
            return Err(Error::INVALID_PARAMETER);
        }
        if option_name == SO_SNDTIMEO as u32 {
            unsafe {
                socket.send_timeout = *(in_buffer as *mut u32);
            }
        }
        if option_name == SO_RCVTIMEO as u32 {
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
}

pub fn get_socket_opt(
    socket: &mut Box<KSocket>,
    option_level: u32,
    option_name: u32,
    out_buffer: *mut u8,
    out_length: &mut u32,
) -> Result<(), Error> {
    if socket.socket_type == WSK_FLAG_INVALID_SOCKET {
        return Err(Error::NOT_IMPLEMENTED);
    }

    if option_level == SOL_SOCKET as u32
        && (option_name == SO_SNDTIMEO as u32 || option_name == SO_RCVTIMEO as u32)
    {
        if *out_length != size_of::<u32>() as u32 || out_buffer.is_null() {
            return Err(Error::INVALID_PARAMETER);
        }
        if option_name == SO_SNDTIMEO as u32 {
            unsafe {
                *(out_buffer as *mut u32) = socket.send_timeout;
            }
        }
        if option_name == SO_RCVTIMEO as u32 {
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
    closed: AtomicBool,
}

pub struct TcpListener {
    socket: Box<KSocket>,
    addr: AddrInfo,
    closed: AtomicBool,
}

impl TcpStream {
    pub fn send(&mut self, send_buffer: &mut [u8]) -> Result<usize, Error> {
        send(&mut self.socket, send_buffer, &mut send_buffer.len(), 0)
    }
    pub fn recv_all(&mut self, recv_buffer: &mut [u8]) -> Result<usize, Error> {
        recv(&mut self.socket, recv_buffer, &mut recv_buffer.len(), 0)
    }

    pub fn close(&mut self) {
        let _ = close_socket(&mut self.socket);
        self.closed.store(true, Ordering::Release);
    }
}

//unsafe impl Send for TcpStream {}

impl TcpSocket {
    pub fn new_v4(
        berk: Arc<Option<Berk>>,
        berk_status: Arc<AtomicBool>,
    ) -> Result<TcpSocket, Error> {
        let mut socket = socket_connection(
            berk.clone(),
            berk_status.clone(),
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
        )?;

        Ok(TcpSocket {
            socket,
            berk,
            berk_status,
        })
    }
    pub fn connect(mut self, addr: &str, port: &str) -> Result<TcpStream, Error> {
        let mut hints = crate::asynk::wsk::new_addrinfoa();
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
        get_addr_info(
            self.berk.clone(),
            self.berk_status.clone(),
            address_ptr,
            port_ptr,
            &mut hints,
            &mut res,
        )?;

        let addr: &mut SOCKADDR;
        if res.is_null() || (*res).is_null() || unsafe { (**res).ai_addr.is_null() } {
            return Err(Error::UNSUCCESSFUL);
        }

        unsafe {
            addr = &mut *(**res).ai_addr as &mut _;
        }

        connect(&mut self.socket, addr)?;

        Ok(TcpStream {
            socket: self.socket,
            closed: AtomicBool::new(false),
        })
    }
}

impl TcpListener {
    pub fn bind(
        berk: Arc<Option<Berk>>,
        berk_status: Arc<AtomicBool>,
        address: &str,
        port: &str,
    ) -> Result<TcpListener, Error> {
        let mut socket = socket_listen(
            berk.clone(),
            berk_status.clone(),
            AF_INET,
            SOCK_STREAM,
            IPPROTO_TCP,
        )?;

        let addr = new_sockaddr_in();
        if let AddrInfo::SockAddrIn(mut addr) = addr {
            unsafe {
                addr.sin_port = htons(port.parse::<u16>().unwrap());
            }
            addr.sin_family = AF_INET;
            addr.sin_addr.S_un.S_addr = 0;

            bind(
                &mut socket,
                unsafe { &mut *(addr_of_mut!(addr).cast::<SOCKADDR>()) as &mut _ },
                0,
            )?;
        }

        Ok(TcpListener {
            socket,
            addr,
            closed: AtomicBool::new(false),
        })
    }

    pub fn accept(&mut self) -> Result<TcpStream, Error> {
        let new_socket = accept(&mut self.socket, addr_of_mut!(self.addr).cast())?;

        Ok(TcpStream {
            socket: new_socket,
            closed: AtomicBool::new(false),
        })
    }
    fn close(&mut self) {
        let _ = close_socket(&mut self.socket);
        self.closed.store(true, Ordering::Release);
    }

    pub fn as_stream<'a>(&'a mut self) -> impl Stream<Item = Result<TcpStream, Error>> + 'a {
        futures::stream::unfold(self, |listener| async {
            let stream = listener.accept();
            Some((stream, listener))
        })
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
        if !self.closed.load(Ordering::Acquire) {
            //TODO: proper sync
            self.close();
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if !self.closed.load(Ordering::Acquire) {
            //TODO: proper sync
            self.close();
        }
    }
}
