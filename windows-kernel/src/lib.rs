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
#![no_std]
#![feature(alloc_error_handler)]
#![feature(never_type)]
#![feature(strict_provenance)]
#![feature(new_uninit)]
#![feature(get_mut_unchecked)]
#![feature(dropck_eyepatch)]
#![feature(error_in_core)]
#![feature(negative_impls)]
#![feature(hashmap_internals)]
#![feature(hasher_prefixfree_extras)]
#![feature(const_hash)]
#![feature(sync_unsafe_cell)]
#![feature(str_internals)]
#![feature(char_internals)]
#![feature(let_chains)]
#![feature(slice_concat_trait)]
#![feature(maybe_uninit_slice)]
#![feature(maybe_uninit_uninit_array)]
#![feature(pointer_is_aligned)]
#![feature(allocator_api)]
#![feature(core_io_borrowed_buf)]
#![feature(slice_internals)]
#![feature(specialization)]
#![feature(extend_one)]

extern crate alloc;

pub use hashbrown::HashMap;
pub use widestring::U16CString;

use windows_kernel_sys::base::PDEVICE_OBJECT;
pub use windows_kernel_sys::base::{
    DRIVER_OBJECT, IRP_MJ_MAXIMUM_FUNCTION, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING,
};

pub use crate::affinity::{get_cpu_count, get_current_cpu_num, run_on_cpu, run_on_each_cpu};
pub use crate::device::{
    dispatch_device, Access, Completion, Device, DeviceDoFlags, DeviceFlags, DeviceOperations,
    DeviceType, RequestError,
};
pub use crate::driver::Driver;
pub use crate::error::Error;
pub use crate::ioctl::{ControlCode, RequiredAccess, TransferMethod};
pub use crate::request::{IoControlRequest, IoRequest, ReadRequest, WriteRequest};
pub use crate::symbolic_link::SymbolicLink;
pub use crate::sync::Mutex;
pub use crate::user_ptr::UserPtr;

pub mod affinity;
pub mod allocator;
pub mod asynk;
pub mod device;
pub mod driver;
pub mod error;
pub mod headers;
pub mod intrin;
pub mod io;
pub mod ioctl;
pub mod mdl;
pub mod memory;
pub mod perf_counter;
pub mod process;
pub mod request;
pub mod section;
pub mod string;
pub mod symbolic_link;
pub mod sync;
pub mod time;
pub mod user_ptr;
pub mod version;

#[no_mangle]
pub extern "system" fn __CxxFrameHandler3() -> i32 {
    0
}

pub static mut __DEVICE: Option<PDEVICE_OBJECT> = None;

#[macro_export]
macro_rules! kernel_module {
    ($module:ty) => {
        static mut __MOD: Option<$module> = None;

        #[no_mangle]
        pub extern "system" fn driver_entry(
            driver: &mut $crate::DRIVER_OBJECT,
            registry_path: &$crate::UNICODE_STRING,
        ) -> $crate::NTSTATUS {
            unsafe {
                driver.DriverUnload = Some(driver_exit);

                for i in 0..$crate::IRP_MJ_MAXIMUM_FUNCTION {
                    driver.MajorFunction[i as usize] = Some($crate::dispatch_device);
                }
            }

            let driver = unsafe { Driver::from_raw(driver) };

            let registry_path = unsafe { $crate::U16CString::from_ptr_str(registry_path.Buffer) };
            let registry_path = registry_path.to_string_lossy();

            match <$module as $crate::KernelModule>::init(driver, registry_path.as_str()) {
                Ok(m) => {
                    unsafe {
                        __MOD = Some(m);
                    }
                    $crate::asynk::executor::init_executor();
                    match $crate::sync::thread::Thread::spawn(move || {
                        $crate::asynk::executor::get_executor().run()
                    }) {
                        Ok(thread) => {}
                        Err(e) => {
                            $crate::asynk::executor::deinit_executor();
                            return e.to_ntstatus();
                        }
                    }
                    $crate::STATUS_SUCCESS
                }
                Err(e) => e.to_ntstatus(),
            }
        }

        pub unsafe extern "C" fn driver_exit(driver: *mut $crate::DRIVER_OBJECT) {
            let driver = unsafe { Driver::from_raw(driver) };

            {
                $crate::asynk::executor::deinit_event_map();
            }

            {
                $crate::asynk::executor::deinit_executor();
            }
            unsafe {
                {
                    $crate::sync::thread::deinit_THREADS();
                    __DEVICE.take();
                }
            }
            $crate::sync::mpmc::context::deinit_CONTEXT();

            $crate::sync::thread_local::thread_id::deinit();

            match __MOD.take() {
                Some(mut m) => m.cleanup(driver),
                _ => (),
            }
        }
    };
}

pub trait KernelModule: Sized + Sync {
    fn init(driver: Driver, registry_path: &str) -> Result<Self, Error>;
    fn cleanup(self, _driver: Driver) {}
}
