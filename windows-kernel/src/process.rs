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
use bitflags::bitflags;

use windows_kernel_sys::base::{
    CLIENT_ID, HANDLE, KAPC_STATE, OBJECT_ATTRIBUTES, PACCESS_TOKEN, PEPROCESS,
};
use windows_kernel_sys::ntoskrnl::{KeStackAttachProcess, KeUnstackDetachProcess};
use windows_kernel_sys::ntoskrnl::{
    ObDereferenceObject, ObReferenceObject, PsDereferencePrimaryToken, PsReferencePrimaryToken,
};
use windows_kernel_sys::ntoskrnl::{PsGetCurrentProcess, PsLookupProcessByProcessId};
use windows_kernel_sys::ntoskrnl::{ZwClose, ZwOpenProcess};

use crate::error::{Error, IntoResult};

pub type ProcessId = usize;

#[derive(Clone, Debug)]
pub struct Process {
    pub process: PEPROCESS,
    from_pid: bool,
}

impl Process {
    pub fn as_ptr(&self) -> PEPROCESS {
        self.process
    }

    pub fn current() -> Self {
        let process = unsafe { PsGetCurrentProcess() };
        let from_pid = false;
        Self { process, from_pid }
    }

    pub fn by_id(process_id: ProcessId) -> Result<Self, Error> {
        let mut process = core::ptr::null_mut();
        let from_pid = true;

        unsafe { PsLookupProcessByProcessId(process_id as _, &mut process) }.into_result()?;
        Ok(Self { process, from_pid })
    }

    pub fn id(&self) -> ProcessId {
        let handle = unsafe { windows_kernel_sys::ntoskrnl::PsGetProcessId(self.process) };

        handle as _
    }

    pub fn from_raw(process: PEPROCESS) -> Self {
        let from_pid = false;

        Self { process, from_pid }
    }

    pub fn attach(&self) -> ProcessAttachment {
        unsafe { ProcessAttachment::attach(self.process) }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.from_pid {
            unsafe {
                ObDereferenceObject(self.process as _);
            }
        }
    }
}

pub struct ProcessAttachment {
    process: PEPROCESS,
    state: KAPC_STATE,
}

impl ProcessAttachment {
    pub unsafe fn attach(process: PEPROCESS) -> Self {
        let mut state: KAPC_STATE = core::mem::zeroed();

        ObReferenceObject(process as _);
        KeStackAttachProcess(process, &mut state);

        Self { process, state }
    }
}

impl Drop for ProcessAttachment {
    fn drop(&mut self) {
        unsafe {
            KeUnstackDetachProcess(&mut self.state);
            ObDereferenceObject(self.process as _);
        }
    }
}

bitflags! {
    pub struct ProcessAccess: u32 {
        const ALL_ACCESS = windows_kernel_sys::base::PROCESS_ALL_ACCESS;
    }
}

pub struct ZwProcess {
    pub(crate) handle: HANDLE,
}

impl ZwProcess {
    pub fn open(id: ProcessId, access: ProcessAccess) -> Result<Self, Error> {
        let mut attrs: OBJECT_ATTRIBUTES = unsafe { core::mem::zeroed() };
        attrs.Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;

        let mut client_id = CLIENT_ID {
            UniqueProcess: id as _,
            UniqueThread: core::ptr::null_mut(),
        };

        let mut handle = core::ptr::null_mut();

        unsafe { ZwOpenProcess(&mut handle, access.bits(), &mut attrs, &mut client_id) }
            .into_result()?;

        Ok(Self { handle })
    }
}

impl Drop for ZwProcess {
    fn drop(&mut self) {
        unsafe {
            ZwClose(self.handle);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Token {
    pub token: PACCESS_TOKEN,
}

impl Token {
    pub fn by_token(eprocess: PEPROCESS) -> Option<Self> {
        let token = unsafe { PsReferencePrimaryToken(eprocess) };
        if !token.is_null() {
            Some(Self { token })
        } else {
            None
        }
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        if !self.token.is_null() {
            unsafe { PsDereferencePrimaryToken(self.token) }
        }
    }
}
