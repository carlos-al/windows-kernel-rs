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
use crate::error::Error;
use crate::memory::MemoryCaching;

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    KernelMode = windows_kernel_sys::base::_MODE::KernelMode,
    UserMode = windows_kernel_sys::base::_MODE::UserMode,
}

pub struct MemoryDescriptorList {
    raw: *mut windows_kernel_sys::base::MDL,
}

unsafe impl Send for MemoryDescriptorList {}

unsafe impl Sync for MemoryDescriptorList {}

impl MemoryDescriptorList {
    pub fn new(addr: *mut core::ffi::c_void, size: usize) -> Result<Self, Error> {
        use windows_kernel_sys::ntoskrnl::IoAllocateMdl;

        let raw = unsafe {
            IoAllocateMdl(
                addr,
                size as _,
                false as _,
                false as _,
                core::ptr::null_mut(),
            )
        };

        if raw.is_null() {
            return Err(Error::INSUFFICIENT_RESOURCES);
        }

        Ok(Self { raw })
    }

    pub fn build_for_non_paged_pool(&mut self) {
        use windows_kernel_sys::ntoskrnl::MmBuildMdlForNonPagedPool;

        unsafe {
            MmBuildMdlForNonPagedPool(self.raw);
        }
    }

    pub fn map_locked_pages(
        self,
        access: AccessMode,
        caching: MemoryCaching,
        desired_addr: Option<*mut core::ffi::c_void>,
    ) -> Result<LockedMapping, Error> {
        use windows_kernel_sys::ntoskrnl::MmMapLockedPagesSpecifyCache;

        let ptr = unsafe {
            MmMapLockedPagesSpecifyCache(
                self.raw,
                access as _,
                caching as _,
                desired_addr.unwrap_or(core::ptr::null_mut()),
                false as _,
                0,
            )
        };

        Ok(LockedMapping { raw: self.raw, ptr })
    }
}

impl Drop for MemoryDescriptorList {
    fn drop(&mut self) {
        use windows_kernel_sys::ntoskrnl::IoFreeMdl;

        unsafe {
            IoFreeMdl(self.raw);
        }
    }
}

pub struct LockedMapping {
    raw: *mut windows_kernel_sys::base::MDL,
    ptr: *mut core::ffi::c_void,
}

unsafe impl Send for LockedMapping {}

unsafe impl Sync for LockedMapping {}

impl LockedMapping {
    pub fn ptr(&self) -> *mut core::ffi::c_void {
        self.ptr
    }

    pub fn unlock(self) -> MemoryDescriptorList {
        use windows_kernel_sys::ntoskrnl::MmUnmapLockedPages;

        unsafe {
            MmUnmapLockedPages(self.ptr, self.raw);
        }

        MemoryDescriptorList { raw: self.raw }
    }
}

impl Drop for LockedMapping {
    fn drop(&mut self) {
        use windows_kernel_sys::ntoskrnl::{IoFreeMdl, MmUnmapLockedPages};

        unsafe {
            MmUnmapLockedPages(self.ptr, self.raw);
            IoFreeMdl(self.raw);
        }
    }
}
