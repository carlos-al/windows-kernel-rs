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
use core::ops::Deref;

use bitflags::bitflags;

use windows_kernel_sys::base::_MM_PAGE_PRIORITY as MM_PAGE_PRIORITY;
use windows_kernel_sys::base::{IO_NO_INCREMENT, IO_STACK_LOCATION, IRP, STATUS_SUCCESS};
use windows_kernel_sys::ntoskrnl::{IoCompleteRequest, IoGetCurrentIrpStackLocation};
use windows_kernel_sys::ntoskrnl::{
    MmGetMdlByteCount, MmGetMdlByteOffset, MmGetSystemAddressForMdlSafe,
};

use crate::error::Error;
use crate::ioctl::{ControlCode, RequiredAccess, TransferMethod};
use crate::user_ptr::UserPtr;

bitflags! {
    pub struct IrpFlags: u32 {
        const NOCACHE = windows_kernel_sys::base::IRP_NOCACHE;
        const PAGING_IO = windows_kernel_sys::base::IRP_PAGING_IO;
        const MOUNT_COMPLETION =  windows_kernel_sys::base::IRP_MOUNT_COMPLETION;
        const SYNCHRONOUS_API = windows_kernel_sys::base::IRP_SYNCHRONOUS_API;
        const ASSOCIATED_IRP = windows_kernel_sys::base::IRP_ASSOCIATED_IRP;
        const BUFFERED_IO = windows_kernel_sys::base::IRP_BUFFERED_IO;
        const DEALLOCATE_BUFFER = windows_kernel_sys::base::IRP_DEALLOCATE_BUFFER;
        const INPUT_OPERATION = windows_kernel_sys::base::IRP_INPUT_OPERATION;
        const SYNCHRONOUS_PAGING_IO = windows_kernel_sys::base::IRP_SYNCHRONOUS_PAGING_IO;
        const CREATE_OPERATION = windows_kernel_sys::base::IRP_CREATE_OPERATION;
        const READ_OPERATION = windows_kernel_sys::base::IRP_READ_OPERATION;
        const WRITE_OPERATION = windows_kernel_sys::base::IRP_WRITE_OPERATION;
        const CLOSE_OPERATION = windows_kernel_sys::base::IRP_CLOSE_OPERATION;
        const DEFER_IO_COMPLETION = windows_kernel_sys::base::IRP_DEFER_IO_COMPLETION;
        const OB_QUERY_NAME = windows_kernel_sys::base::IRP_OB_QUERY_NAME;
        const HOLD_DEVICE_QUEUE = windows_kernel_sys::base::IRP_HOLD_DEVICE_QUEUE;
        const UM_DRIVER_INITIATED_IO = windows_kernel_sys::base::IRP_UM_DRIVER_INITIATED_IO;
    }
}

pub struct IoRequest {
    irp: *mut IRP,
}

impl IoRequest {
    pub unsafe fn from_raw(irp: *mut IRP) -> Self {
        Self { irp }
    }

    pub fn irp(&self) -> &IRP {
        unsafe { &*self.irp }
    }

    pub fn irp_mut(&self) -> &mut IRP {
        unsafe { &mut *self.irp }
    }

    pub fn flags(&self) -> IrpFlags {
        IrpFlags::from_bits(self.irp().Flags).unwrap_or(IrpFlags::empty())
    }

    pub fn stack_location(&self) -> &IO_STACK_LOCATION {
        unsafe { &*IoGetCurrentIrpStackLocation(self.irp_mut()) }
    }

    pub fn major(&self) -> u8 {
        self.stack_location().MajorFunction
    }

    pub(crate) fn complete(&self, value: Result<u32, Error>) {
        let irp = self.irp_mut();

        match value {
            Ok(value) => {
                irp.IoStatus.Information = value as _;
                irp.IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
            }
            Err(error) => {
                irp.IoStatus.Information = 0;
                irp.IoStatus.__bindgen_anon_1.Status = error.to_ntstatus();
            }
        }

        unsafe {
            IoCompleteRequest(irp, IO_NO_INCREMENT as _);
        }
    }
}

pub struct ReadRequest {
    pub(crate) inner: IoRequest,
}

impl Deref for ReadRequest {
    type Target = IoRequest;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ReadRequest {
    pub fn user_ptr(&self) -> UserPtr {
        let stack_location = self.stack_location();
        let irp = self.irp();

        // 2 ways to get ptr to user memory whether direct/buffered IO
        let (ptr, size) = if !irp.MdlAddress.is_null() {
            let ptr = unsafe {
                // Convert MDL to virtual memory space
                MmGetSystemAddressForMdlSafe(
                    irp.MdlAddress,
                    MM_PAGE_PRIORITY::HighPagePriority as _,
                )
            };

            let size = unsafe { MmGetMdlByteCount(irp.MdlAddress) } as usize;

            (ptr, size)
        } else if !unsafe { irp.AssociatedIrp.SystemBuffer }.is_null() {
            let ptr = unsafe { irp.AssociatedIrp.SystemBuffer };
            let size = unsafe { stack_location.Parameters.Read }.Length as usize;

            (ptr, size)
        } else {
            (core::ptr::null_mut(), 0)
        };

        unsafe { UserPtr::new_buffered(ptr, 0, size) }
    }

    pub fn offset(&self) -> i64 {
        let stack_location = self.stack_location();
        let irp = self.irp();

        if !irp.MdlAddress.is_null() {
            (unsafe { MmGetMdlByteOffset(irp.MdlAddress) }) as i64
        } else if !unsafe { irp.AssociatedIrp.SystemBuffer }.is_null() {
            unsafe { stack_location.Parameters.Read.ByteOffset.QuadPart }
        } else {
            0
        }
    }
}

impl Into<IoRequest> for ReadRequest {
    fn into(self) -> IoRequest {
        self.inner
    }
}

pub struct WriteRequest {
    pub(crate) inner: IoRequest,
}

impl Deref for WriteRequest {
    type Target = IoRequest;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl WriteRequest {
    pub fn user_ptr(&self) -> UserPtr {
        let stack_location = self.stack_location();
        let irp = self.irp();

        let (ptr, size) = if !irp.MdlAddress.is_null() {
            let ptr = unsafe {
                MmGetSystemAddressForMdlSafe(
                    irp.MdlAddress,
                    MM_PAGE_PRIORITY::HighPagePriority as _,
                )
            };

            let size = unsafe { MmGetMdlByteCount(irp.MdlAddress) } as usize;

            (ptr, size)
        } else if !unsafe { irp.AssociatedIrp.SystemBuffer }.is_null() {
            let ptr = unsafe { irp.AssociatedIrp.SystemBuffer };
            let size = unsafe { stack_location.Parameters.Write }.Length as usize;

            (ptr, size)
        } else {
            (core::ptr::null_mut(), 0)
        };

        unsafe { UserPtr::new_buffered(ptr, size, 0) }
    }

    pub fn offset(&self) -> i64 {
        let stack_location = self.stack_location();
        let irp = self.irp();

        if !irp.MdlAddress.is_null() {
            (unsafe { MmGetMdlByteOffset(irp.MdlAddress) }) as i64
        } else if !unsafe { irp.AssociatedIrp.SystemBuffer }.is_null() {
            unsafe { stack_location.Parameters.Write.ByteOffset.QuadPart }
        } else {
            0
        }
    }
}

impl Into<IoRequest> for WriteRequest {
    fn into(self) -> IoRequest {
        self.inner
    }
}

pub struct IoControlRequest {
    pub(crate) inner: IoRequest,
}

impl Deref for IoControlRequest {
    type Target = IoRequest;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl IoControlRequest {
    pub fn control_code(&self) -> ControlCode {
        let stack_location = self.stack_location();

        unsafe {
            stack_location
                .Parameters
                .DeviceIoControl
                .IoControlCode
                .into()
        }
    }

    pub fn function(&self) -> (RequiredAccess, u32) {
        let code = self.control_code();

        (code.required_access(), code.number())
    }

    pub fn user_ptr(&self) -> UserPtr {
        let stack_location = self.stack_location();
        let irp = self.irp();

        let system_buffer = unsafe { irp.AssociatedIrp.SystemBuffer };

        let mdl_address = if !irp.MdlAddress.is_null() {
            unsafe {
                MmGetSystemAddressForMdlSafe(
                    irp.MdlAddress,
                    MM_PAGE_PRIORITY::HighPagePriority as _,
                )
            }
        } else {
            core::ptr::null_mut()
        };

        let input_size =
            unsafe { stack_location.Parameters.DeviceIoControl.InputBufferLength } as usize;
        let output_size =
            unsafe { stack_location.Parameters.DeviceIoControl.OutputBufferLength } as usize;

        match self.control_code().transfer_method() {
            TransferMethod::Buffered => unsafe {
                UserPtr::new_buffered(system_buffer, input_size, output_size)
            },
            TransferMethod::InputDirect => unsafe {
                UserPtr::new_direct(mdl_address, system_buffer, output_size, input_size)
            },
            TransferMethod::OutputDirect => unsafe {
                UserPtr::new_direct(system_buffer, mdl_address, input_size, output_size)
            },
            TransferMethod::Neither => unsafe { UserPtr::new_neither() },
        }
    }
}

impl Into<IoRequest> for IoControlRequest {
    fn into(self) -> IoRequest {
        self.inner
    }
}
