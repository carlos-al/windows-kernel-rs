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
//! This module provides an allocator to use with the [`alloc`] crate. You can define your own
//! global allocator with the `#[global_allocator]` attribute when not using the `alloc` feature,
//! in case you want to specify your own tag to use with [`ExAllocatePool2`] and
//! [`ExAllocatePoolWithTag`].

use core::alloc::{GlobalAlloc, Layout};

use windows_kernel_sys::base::_POOL_TYPE as POOL_TYPE;
use windows_kernel_sys::ntoskrnl::{ExAllocatePool2, ExAllocatePoolWithTag, ExFreePool};

use crate::sync::once_lock::OnceLock;
use crate::version::VersionInfo;

/// The version of Microsoft Windows that is currently running. This is used by
/// [`KernelAllocator`] to determine whether to use [`ExAllocatePool2`] or
/// [`ExAllocatePoolWithTag`].
static VERSION_INFO: OnceLock<VersionInfo> = OnceLock::new();

#[inline]
fn get_VERSION_INFO() -> &'static VersionInfo {
    VERSION_INFO.get_or_init(|| VersionInfo::query().unwrap())
}

/// Represents a kernel allocator that relies on the `ExAllocatePool` family of functions to
/// allocate and free memory for the `alloc` crate.
pub struct KernelAllocator {
    /// The 32-bit tag to use for the pool, this is usually derived from a quadruplet of ASCII
    /// bytes, e.g. by invoking `u32::from_ne_bytes(*b"rust")`.
    tag: u32,
}

impl KernelAllocator {
    /// Sets up a new kernel allocator with the 32-bit tag specified. The tag is usually derived
    /// from a quadruplet of ASCII bytes, e.g. by invoking `u32::from_ne_bytes(*b"rust")`.
    pub const fn new(tag: u32) -> Self {
        Self { tag }
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    /// Uses [`ExAllocatePool2`] on Microsoft Windows 10.0.19041 and later, and
    /// [`ExAllocatePoolWithTag`] on older versions of Microsoft Windows to allocate memory.
    /// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/updating-deprecated-exallocatepool-calls
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let use_ex_allocate_pool2 = get_VERSION_INFO().major() > 10
            || (get_VERSION_INFO().major() == 10 && get_VERSION_INFO().build_number() == 19041);

        let ptr = if use_ex_allocate_pool2 {
            ExAllocatePool2(POOL_TYPE::NonPagedPool as _, layout.size() as u64, self.tag)
        } else {
            ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, layout.size() as u64, self.tag)
        };

        if ptr.is_null() {
            panic!("[kernel-alloc] failed to allocate pool.");
        }

        ptr as _
    }

    /// Uses [`ExFreePool`] to free allocated memory.
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        ExFreePool(ptr as _)
    }
}
