/*MIT License

Copyright (c) 2021 S.J.R. van Schaik

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub use windows_sys::Win32::Networking::WinSock::*;

use crate::base::*;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct S_un_b {
    pub s_b1: u8,
    pub s_b2: u8,
    pub s_b3: u8,
    pub s_b4: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union S_un {
    pub S_un_b: S_un_b,
    pub S_un_w: S_un_w,
    pub S_addr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct S_un_w {
    pub s_w1: u16,
    pub s_w2: u16,
}

#[repr(C)]
pub struct in_addr {
    pub S_un: S_un,
}

#[repr(C)]
pub union u {
    pub Byte: [u8; 16],
    pub Word: [u16; 8],
}

#[repr(C)]
pub struct in6_addr {
    pub u: u,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union _DL_EUI48 {
    pub Byte: [u8; 6],
    pub Inner: _DL_EUI48_Inner,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct _DL_EUI48_Inner {
    pub Oui: DL_OUI,
    pub Ei48: DL_EI48,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DL_OUI {
    pub Byte: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DL_EI48 {
    pub Byte: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union DL_EUI48 {
    pub Byte: [u8; 6],
    pub Anonymous: DL_EUI48_0,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DL_EUI48_0 {
    pub Oui: DL_OUI,
    pub Ei48: DL_EI48,
}

// Function pointers for the client characteristics
pub type PNPI_CLIENT_ATTACH_PROVIDER_FN = Option<
    unsafe extern "C" fn(
        NmrBindingHandle: HANDLE,
        ClientContext: PVOID,
        ProviderRegistrationInstance: PNPI_REGISTRATION_INSTANCE,
    ) -> NTSTATUS,
>;
pub type PNPI_CLIENT_DETACH_PROVIDER_FN =
    Option<unsafe extern "C" fn(ClientBindingContext: PVOID) -> NTSTATUS>;
pub type PNPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN =
    Option<unsafe extern "C" fn(ClientBindingContext: PVOID)>;
pub type NPIID = GUID;
pub type PNPIID = *mut NPIID;

#[repr(C)]
pub union _NPI_MODULEID_Union {
    pub Guid: GUID,
    pub IfLuid: LUID,
}

#[repr(C)]
pub struct _NPI_MODULEID {
    pub Length: USHORT,
    pub Type: NPI_MODULEID_TYPE,
    pub _Union: _NPI_MODULEID_Union,
}

pub type NPI_MODULEID = _NPI_MODULEID;
pub type PNPI_MODULEID = NPI_MODULEID;

#[repr(C)]
pub struct _NPI_REGISTRATION_INSTANCE {
    pub Version: USHORT,
    pub Size: USHORT,
    pub NpiId: PNPIID,
    pub ModuleId: PNPI_MODULEID,
    pub Number: ULONG,
    pub NpiSpecificCharacteristics: PVOID, // Assuming VOID is an alias for void
}

pub type NPI_REGISTRATION_INSTANCE = _NPI_REGISTRATION_INSTANCE;
pub type PNPI_REGISTRATION_INSTANCE = NPI_REGISTRATION_INSTANCE;

#[repr(C)]
pub struct _NPI_CLIENT_CHARACTERISTICS {
    pub Version: USHORT,
    pub Length: USHORT,
    pub ClientAttachProvider: PNPI_CLIENT_ATTACH_PROVIDER_FN,
    pub ClientDetachProvider: PNPI_CLIENT_DETACH_PROVIDER_FN,
    pub ClientCleanupBindingContext: PNPI_CLIENT_CLEANUP_BINDING_CONTEXT_FN,
    pub ClientRegistrationInstance: NPI_REGISTRATION_INSTANCE,
}

pub type NPI_CLIENT_CHARACTERISTICS = _NPI_CLIENT_CHARACTERISTICS;
pub type PNPI_CLIENT_CHARACTERISTICS = *mut NPI_CLIENT_CHARACTERISTICS;

// Function pointers for the provider characteristics
pub type PNPI_PROVIDER_ATTACH_CLIENT_FN = Option<
    unsafe extern "C" fn(
        NmrBindingHandle: HANDLE,
        ProviderContext: PVOID,
        ClientRegistrationInstance: PNPI_REGISTRATION_INSTANCE,
        ClientBindingContext: PVOID,
        ClientDispatch: *const c_void, // Assuming VOID is an alias for void
        ProviderBindingContext: *mut PVOID,
        ProviderDispatch: *const *const c_void,
    ) -> NTSTATUS,
>;
pub type PNPI_PROVIDER_DETACH_CLIENT_FN =
    Option<unsafe extern "C" fn(ProviderBindingContext: PVOID) -> NTSTATUS>;
pub type PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN =
    Option<unsafe extern "C" fn(ProviderBindingContext: PVOID)>;

#[repr(C)]
pub struct _NPI_PROVIDER_CHARACTERISTICS {
    pub Version: USHORT,
    pub Length: USHORT,
    pub ProviderAttachClient: PNPI_PROVIDER_ATTACH_CLIENT_FN,
    pub ProviderDetachClient: PNPI_PROVIDER_DETACH_CLIENT_FN,
    pub ProviderCleanupBindingContext: PNPI_PROVIDER_CLEANUP_BINDING_CONTEXT_FN,
    pub ProviderRegistrationInstance: NPI_REGISTRATION_INSTANCE,
}

pub type NPI_PROVIDER_CHARACTERISTICS = _NPI_PROVIDER_CHARACTERISTICS;
pub type PNPI_PROVIDER_CHARACTERISTICS = *mut NPI_PROVIDER_CHARACTERISTICS;

pub type PFN_WSK_CLIENT_EVENT = Option<unsafe extern "C" fn()>;

#[repr(C)]
pub struct _WSK_CLIENT_DISPATCH {
    pub Version: USHORT,
    pub Reserved: USHORT,
    pub WskClientEvent: PFN_WSK_CLIENT_EVENT,
}

pub type WSK_CLIENT_DISPATCH = _WSK_CLIENT_DISPATCH;

#[repr(C)]
pub struct _WSK_CLIENT_NPI {
    pub ClientContext: PVOID,
    pub Dispatch: *const WSK_CLIENT_DISPATCH,
}

pub type WSK_CLIENT_NPI = _WSK_CLIENT_NPI;
pub type PWSK_CLIENT_NPI = *mut WSK_CLIENT_NPI;

#[repr(C)]
pub struct _WSK_REGISTRATION {
    pub ReservedRegistrationState: ULONGLONG,
    pub ReservedRegistrationContext: PVOID,
    pub ReservedRegistrationLock: KSPIN_LOCK,
}

pub type WSK_REGISTRATION = _WSK_REGISTRATION;
pub type PWSK_REGISTRATION = *mut WSK_REGISTRATION;

pub type PFN_WSK_SOCKET = Option<
    unsafe extern "C" fn(
        Client: PWSK_CLIENT,
        AddressFamily: ADDRESS_FAMILY,
        SocketType: USHORT,
        Protocol: ULONG,
        Flags: ULONG,
        SocketContext: PVOID,
        Dispatch: *const c_void,
        OwningProcess: PEPROCESS,
        OwningThread: PETHREAD,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        Irp: PIRP,
    ) -> NTSTATUS,
>;

pub type PFN_WSK_RECEIVE_EVENT = Option<
    unsafe extern "C" fn(
        SocketContext: PVOID,
        Flags: ULONG,
        DataIndication: PWSK_DATA_INDICATION,
        BytesIndicated: SIZE_T,
        BytesAccepted: *mut SIZE_T,
    ) -> NTSTATUS,
>;
pub type PFN_WSK_DISCONNECT_EVENT =
    Option<unsafe extern "C" fn(SocketContext: PVOID, IdealBacklogSize: SIZE_T) -> NTSTATUS>;
pub type PFN_WSK_SEND_BACKLOG_EVENT =
    Option<unsafe extern "C" fn(SocketContext: PVOID, Flags: ULONG) -> NTSTATUS>;

#[repr(C)]
pub struct _WSK_BUF {
    pub Mdl: PMDL,
    pub Offset: ULONG,
    pub Length: SIZE_T,
}

pub type WSK_BUF = _WSK_BUF;
pub type PWSK_BUF = *mut _WSK_BUF;

#[repr(C)]
pub struct _WSK_DATA_INDICATION {
    pub Next: *mut _WSK_DATA_INDICATION,
    pub Buffer: WSK_BUF,
}

pub type WSK_DATA_INDICATION = _WSK_DATA_INDICATION;
pub type PWSK_DATA_INDICATION = *mut _WSK_DATA_INDICATION;

#[repr(C)]
pub struct _WSK_CLIENT_CONNECTION_DISPATCH {
    pub WskReceiveEvent: PFN_WSK_RECEIVE_EVENT,
    pub WskDisconnectEvent: PFN_WSK_DISCONNECT_EVENT,
    pub WskSendBacklogEvent: PFN_WSK_SEND_BACKLOG_EVENT,
}

pub type WSK_CLIENT_CONNECTION_DISPATCH = _WSK_CLIENT_CONNECTION_DISPATCH;

pub type PFN_WSK_SOCKET_CONNECT = Option<
    unsafe extern "C" fn(
        Client: PWSK_CLIENT,
        SocketType: USHORT,
        Protocol: ULONG,
        LocalAddress: PSOCKADDR,
        RemoteAddress: PSOCKADDR,
        Flags: ULONG,
        SocketContext: PVOID,
        Dispatch: *const WSK_CLIENT_CONNECTION_DISPATCH,
        OwningProcess: PEPROCESS,
        OwningThread: PETHREAD,
        SecurityDescriptor: PSECURITY_DESCRIPTOR,
        Irp: PIRP,
    ) -> NTSTATUS,
>;
pub type PFN_WSK_CONTROL_CLIENT = Option<
    unsafe extern "C" fn(
        Client: PWSK_CLIENT,
        ControlCode: ULONG,
        InputSize: SIZE_T,
        InputBuffer: PVOID,
        OutputSize: SIZE_T,
        OutputBuffer: PVOID,
        OutputSizeReturned: *mut SIZE_T,
        Irp: PIRP,
    ) -> NTSTATUS,
>;
pub type PFN_WSK_GET_ADDRESS_INFO = Option<
    unsafe extern "C" fn(
        Client: PWSK_CLIENT,
        NodeName: PUNICODE_STRING,
        ServiceName: PUNICODE_STRING,
        NameSpace: ULONG,
        Provider: *const GUID,
        Hints: PADDRINFOEXW,
        Result: *mut PADDRINFOEXW,
        OwningProcess: PEPROCESS,
        OwningThread: PETHREAD,
        Irp: PIRP,
    ) -> NTSTATUS,
>;
pub type PFN_WSK_FREE_ADDRESS_INFO =
    Option<unsafe extern "C" fn(Client: PWSK_CLIENT, AddrInfo: PADDRINFOEXW)>;

#[repr(C)]
pub struct AddrInfoexW {
    pub ai_flags: i32,
    pub ai_family: i32,
    pub ai_socktype: i32,
    pub ai_protocol: i32,
    pub ai_addrlen: usize,
    pub ai_canonname: PWSTR,
    pub ai_addr: *mut SOCKADDR,
    pub ai_blob: PVOID,
    pub ai_bloblen: usize,
    pub ai_provider: LPGUID,
    pub ai_next: *mut AddrInfoexW,
}

pub type PADDRINFOEXW = *mut AddrInfoexW;
pub type PSOCKADDR = *mut SOCKADDR;

pub type PFN_WSK_GET_NAME_INFO = Option<
    unsafe extern "C" fn(
        Client: PWSK_CLIENT,
        SockAddr: PSOCKADDR,
        SockAddrLength: ULONG,
        NodeName: PUNICODE_STRING,
        ServiceName: PUNICODE_STRING,
        Flags: ULONG,
        OwningProcess: PEPROCESS,
        OwningThread: PETHREAD,
        Irp: PIRP,
    ) -> NTSTATUS,
>;

#[repr(C)]
pub struct _WSK_PROVIDER_DISPATCH {
    pub Version: USHORT,
    pub Reserved: USHORT,
    pub WskSocket: PFN_WSK_SOCKET,
    pub WskSocketConnect: PFN_WSK_SOCKET_CONNECT,
    pub WskControlClient: PFN_WSK_CONTROL_CLIENT,
    pub WskGetAddressInfo: PFN_WSK_GET_ADDRESS_INFO,
    pub WskFreeAddressInfo: PFN_WSK_FREE_ADDRESS_INFO,
    pub WskGetNameInfo: PFN_WSK_GET_NAME_INFO,
}

pub type WSK_PROVIDER_DISPATCH = _WSK_PROVIDER_DISPATCH;
pub type PWSK_PROVIDER_DISPATCH = *mut WSK_PROVIDER_DISPATCH;

pub type PWSK_CLIENT = PVOID;

#[repr(C)]
pub struct _WSK_PROVIDER_NPI {
    pub Client: PWSK_CLIENT,
    pub Dispatch: *const WSK_PROVIDER_DISPATCH,
}

pub type WSK_PROVIDER_NPI = _WSK_PROVIDER_NPI;
pub type PWSK_PROVIDER_NPI = *mut WSK_PROVIDER_NPI;

#[repr(C)]
pub struct _WSK_PROVIDER_CHARACTERISTICS {
    pub HighestVersion: USHORT,
    pub LowestVersion: USHORT,
}

pub type WSK_PROVIDER_CHARACTERISTICS = _WSK_PROVIDER_CHARACTERISTICS;
pub type PWSK_PROVIDER_CHARACTERISTICS = *mut WSK_PROVIDER_CHARACTERISTICS;

#[repr(C)]
pub struct WSK_PROVIDER_BASIC_DISPATCH {
    pub WskControlSocket: PFN_WSK_CONTROL_SOCKET,
    pub WskCloseSocket: PFN_WSK_CLOSE_SOCKET,
}

#[derive(Clone, Eq, PartialEq)]
#[repr(C)]
pub enum WSK_CONTROL_SOCKET_TYPE {
    WskSetOption = 0,
    WskGetOption = 1,
    WskIoctl = 2,
    WskControlMax = 3,
}

pub type PWSK_CONTROL_SOCKET_TYPE = *mut WSK_CONTROL_SOCKET_TYPE;

#[repr(C)]
pub struct WSK_SOCKET {
    pub Dispatch: *const PVOID,
}

// Define a pointer type for WSK_SOCKET
pub type PWSK_SOCKET = *mut WSK_SOCKET;

type PFN_WSK_CLOSE_SOCKET = extern "system" fn(Socket: PWSK_SOCKET, Irp: PIRP) -> NTSTATUS;
type PFN_WSK_CONTROL_SOCKET = extern "system" fn(
    Socket: PWSK_SOCKET,
    RequestType: WSK_CONTROL_SOCKET_TYPE,
    ControlCode: ULONG,
    Level: ULONG,
    InputSize: SIZE_T,
    InputBuffer: PVOID,
    OutputSize: SIZE_T,
    OutputBuffer: PVOID,
    OutputSizeReturned: *mut SIZE_T,
    Irp: PIRP,
) -> NTSTATUS;

pub type PWSK_PROVIDER_BASIC_DISPATCH = *mut WSK_PROVIDER_BASIC_DISPATCH;

pub type PFN_WSK_BIND = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    LocalAddress: PSOCKADDR,
    Flags: ULONG,
    Irp: PIRP,
) -> NTSTATUS;

pub type PFN_WSK_ACCEPT = unsafe extern "C" fn(
    ListenSocket: PWSK_SOCKET,
    Flags: c_ulong,
    AcceptSocketContext: *mut c_void,
    AcceptSocketDispatch: *const WSK_CLIENT_CONNECTION_DISPATCH,
    LocalAddress: PSOCKADDR,
    RemoteAddress: PSOCKADDR,
    Irp: PIRP,
) -> NTSTATUS;

pub type PFN_WSK_INSPECT_COMPLETE =
    unsafe extern "C" fn(socketContext: *mut c_void, status: i32, bytesTransferred: usize) -> ();

pub type PFN_WSK_GET_LOCAL_ADDRESS = unsafe extern "C" fn(
    socketContext: *mut c_void,
    socket: *mut c_void,
    localAddress: *mut *const c_void,
    remoteAddress: *mut *const c_void,
) -> ();

// Define the struct
pub struct WSK_PROVIDER_LISTEN_DISPATCH {
    pub Basic: WSK_PROVIDER_BASIC_DISPATCH,
    pub WskBind: PFN_WSK_BIND,
    pub WskAccept: PFN_WSK_ACCEPT,
    pub WskInspectComplete: PFN_WSK_INSPECT_COMPLETE,
    pub WskGetLocalAddress: PFN_WSK_GET_LOCAL_ADDRESS,
}

pub type PWSK_PROVIDER_LISTEN_DISPATCH = *mut WSK_PROVIDER_LISTEN_DISPATCH;

type PFN_WSK_CONNECT = Option<
    unsafe extern "C" fn(
        Socket: PWSK_SOCKET,
        RemoteAddress: PSOCKADDR,
        Flags: c_ulong,
        Irp: PIRP,
    ) -> NTSTATUS,
>;

type PFN_WSK_GET_REMOTE_ADDRESS =
    unsafe extern "C" fn(Socket: PWSK_SOCKET, RemoteAddress: PSOCKADDR, Irp: PIRP) -> NTSTATUS;

type PFN_WSK_SEND = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    Buffer: PWSK_BUF,
    Flags: c_ulong,
    Irp: PIRP,
) -> NTSTATUS;

type PFN_WSK_RECEIVE = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    Buffer: PWSK_BUF,
    Flags: c_ulong,
    Irp: PIRP,
) -> NTSTATUS;

type PFN_WSK_DISCONNECT = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    Buffer: PWSK_BUF,
    Flags: c_ulong,
    Irp: PIRP,
) -> NTSTATUS;

type PFN_WSK_RELEASE_DATA_INDICATION_LIST =
    unsafe extern "C" fn(Socket: PWSK_SOCKET, DataIndication: PWSK_DATA_INDICATION) -> NTSTATUS;

type PFN_WSK_CONNECT_EX = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    RemoteAddress: PSOCKADDR,
    Buffer: PWSK_BUF,
    Flags: c_ulong,
    Irp: PIRP,
) -> NTSTATUS;

type PFN_WSK_SEND_EX = unsafe extern "C" fn(
    socketContext: *mut c_void,
    socket: *mut c_void,
    sendFlags: i32,
    sendSegmentArray: *mut c_void,
    sendSegmentCount: usize,
    bytesSent: *mut usize,
    irp: *mut c_void,
) -> i32;

type PFN_WSK_RECEIVE_EX = unsafe extern "C" fn(
    socketContext: *mut c_void,
    socket: *mut c_void,
    receiveFlags: i32,
    receiveSegmentArray: *mut c_void,
    receiveSegmentCount: usize,
    bytesReceived: *mut usize,
    irp: *mut c_void,
) -> i32;

#[repr(C)]
pub struct WSK_PROVIDER_CONNECTION_DISPATCH {
    pub Basic: WSK_PROVIDER_BASIC_DISPATCH,
    pub WskBind: PFN_WSK_BIND,
    pub WskConnect: PFN_WSK_CONNECT,
    pub WskGetLocalAddress: PFN_WSK_GET_LOCAL_ADDRESS,
    pub WskGetRemoteAddress: PFN_WSK_GET_REMOTE_ADDRESS,
    pub WskSend: PFN_WSK_SEND,
    pub WskReceive: PFN_WSK_RECEIVE,
    pub WskDisconnect: PFN_WSK_DISCONNECT,
    pub WskRelease: PFN_WSK_RELEASE_DATA_INDICATION_LIST,
    pub WskConnectEx: PFN_WSK_CONNECT_EX,
    pub WskSendEx: PFN_WSK_SEND_EX,
    pub WskReceiveEx: PFN_WSK_RECEIVE_EX,
}

pub type PWSK_PROVIDER_CONNECTION_DISPATCH = *mut WSK_PROVIDER_CONNECTION_DISPATCH;

pub type PCMSGHDR = *mut CMSGHDR;

pub type PFN_WSK_SEND_TO = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    Buffer: PWSK_BUF,
    Flags: c_ulong,
    RemoteAddress: PSOCKADDR,
    ControlInfoLength: c_ulong,
    ControlInfo: PCMSGHDR,
    Irp: PIRP,
) -> NTSTATUS;

pub type PFN_WSK_RECEIVE_FROM = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    Buffer: PWSK_BUF,
    Flags: c_ulong,
    RemoteAddress: PSOCKADDR,
    ControlLength: *mut c_ulong,
    ControlInfo: PCMSGHDR,
    ControlFlags: *mut c_ulong,
    Irp: PIRP,
) -> NTSTATUS;

pub type PFN_WSK_RELEASE_DATAGRAM_INDICATION_LIST = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    DatagramIndication: PWSK_DATAGRAM_INDICATION,
) -> NTSTATUS;

#[repr(C)]
pub struct WSK_DATAGRAM_INDICATION {
    pub Next: *mut WSK_DATAGRAM_INDICATION,
    pub Buffer: WSK_BUF,
    pub ControlInfo: PCMSGHDR,
    pub ControlInfoLength: c_ulong,
    pub RemoteAddress: PSOCKADDR,
}

#[repr(C)]
pub struct WSK_BUF_LIST {
    pub Next: *mut WSK_BUF_LIST,
    pub Buffer: WSK_BUF,
}

pub type PWSK_BUF_LIST = *mut WSK_BUF_LIST;

pub type PWSK_DATAGRAM_INDICATION = *mut WSK_DATAGRAM_INDICATION;
pub type PFN_WSK_SEND_MESSAGES = unsafe extern "C" fn(
    Socket: PWSK_SOCKET,
    BufferList: PWSK_BUF_LIST,
    Flags: c_ulong,
    RemoteAddress: PSOCKADDR,
    ControlInfoLength: c_ulong,
    ControlInfo: PCMSGHDR,
    Irp: PIRP,
) -> NTSTATUS;

#[repr(C)]
pub struct WSK_PROVIDER_DATAGRAM_DISPATCH {
    pub Basic: WSK_PROVIDER_BASIC_DISPATCH,
    pub WskBind: PFN_WSK_BIND,
    pub WskSendTo: PFN_WSK_SEND_TO,
    pub WskReceiveFrom: PFN_WSK_RECEIVE_FROM,
    pub WskRelease: PFN_WSK_RELEASE_DATAGRAM_INDICATION_LIST,
    pub WskGetLocalAddress: PFN_WSK_GET_LOCAL_ADDRESS,
    pub WskSendMessages: PFN_WSK_SEND_MESSAGES,
}

pub type PWSK_PROVIDER_DATAGRAM_DISPATCH = *mut WSK_PROVIDER_DATAGRAM_DISPATCH;

pub const WSK_FLAG_AT_DISPATCH_LEVEL: u8 = 0x00000008;
pub const WSK_FLAG_RELEASE_ASAP: u8 = 0x00000002;
pub const WSK_FLAG_ENTIRE_MESSAGE: u8 = 0x00000004;
pub const WSK_FLAG_ABORTIVE: u8 = 0x00000001;
pub const WSK_FLAG_BASIC_SOCKET: u8 = 0x00000000;
pub const WSK_FLAG_LISTEN_SOCKET: u8 = 0x00000001;
pub const WSK_FLAG_CONNECTION_SOCKET: u8 = 0x00000002;
pub const WSK_FLAG_DATAGRAM_SOCKET: u8 = 0x00000004;
pub const WSK_FLAG_INVALID_SOCKET: u8 = 0x000000ff;

pub const WSK_TRANSPORT_LIST_QUERY: u32 = 2;
pub const WSK_TRANSPORT_LIST_CHANGE: u32 = 3;
pub const WSK_CACHE_SD: u32 = 4;
pub const WSK_RELEASE_SD: u32 = 5;
pub const WSK_TDI_DEVICENAME_MAPPING: u32 = 6;
pub const WSK_SET_STATIC_EVENT_CALLBACKS: u32 = 7;
pub const WSK_TDI_BEHAVIOR: u32 = 8;
pub const WSK_TDI_BEHAVIOR_BYPASS_TDI: u32 = 0x00000001;

pub const SO_WSK_SECURITY: u32 = WSK_SO_BASE + 1;
pub const SO_WSK_EVENT_CALLBACK: u32 = WSK_SO_BASE + 2;

pub const WSK_EVENT_RECEIVE_FROM: u32 = 0x00000100;
pub const WSK_EVENT_ACCEPT: u32 = 0x00000200;
pub const WSK_EVENT_SEND_BACKLOG: u32 = 0x00000010;
pub const WSK_EVENT_RECEIVE: u32 = 0x00000040;
pub const WSK_EVENT_DISCONNECT: u32 = 0x00000080;
pub const WSK_EVENT_DISABLE: u32 = 0x80000000;

macro_rules! _WSAIOW {
    ($x:expr, $y:expr) => {
        IOC_IN | ($x) | ($y)
    };
}

macro_rules! _WSAIOR {
    ($x:expr, $y:expr) => {
        IOC_OUT | ($x) | ($y)
    };
}

macro_rules! _WSAIORW {
    ($x:expr, $y:expr) => {
        IOC_INOUT | ($x) | ($y)
    };
}

pub const SIO_WSK_SET_REMOTE_ADDRESS: u32 = _WSAIOW!(IOC_WSK, 0x1);
pub const SIO_WSK_REGISTER_EXTENSION: u32 = _WSAIORW!(IOC_WSK, 0x2);
pub const SIO_WSK_QUERY_IDEAL_SEND_BACKLOG: u32 = _WSAIOR!(IOC_WSK, 0x3);
pub const SIO_WSK_QUERY_RECEIVE_BACKLOG: u32 = _WSAIOR!(IOC_WSK, 0x4);
pub const SIO_WSK_QUERY_INSPECT_ID: u32 = _WSAIOR!(IOC_WSK, 0x5);
pub const SIO_WSK_SET_SENDTO_ADDRESS: u32 = _WSAIOW!(IOC_WSK, 0x6);

pub const IOC_WSK: u32 = 251_658_240u32;

pub const WSK_FLAG_NODELAY: u32 = 0x00000002;
pub const WSK_FLAG_WAITALL: u32 = 0x00000002;
pub const WSK_FLAG_DRAIN: u32 = 0x00000004;

pub const WSK_NO_WAIT: u32 = 0;
pub const WSK_INFINITE_WAIT: u32 = 0xffffffff;

#[macro_export]
macro_rules! MAKE_WSK_VERSION {
    ($mj:expr, $mn:expr) => {
        (($mj as u16) << 8) | ($mn as u16 & 0xff)
    };
}
#[macro_export]
macro_rules! WSK_MAJOR_VERSION {
    ($v:expr) => {
        ($v >> 8) as u8
    };
}
#[macro_export]
macro_rules! WSK_MINOR_VERSION {
    ($v:expr) => {
        ($v & 0xff) as u8
    };
}

include!(concat!(env!("OUT_DIR"), "/netio.rs"));
