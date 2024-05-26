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
use alloc::boxed::Box;

use widestring::U16CString;

use windows_kernel_sys::base::DRIVER_OBJECT;
use windows_kernel_sys::ntoskrnl::IoCreateDevice;

use crate::device::{
    Access, Device, DeviceDoFlags, DeviceExtension, DeviceFlags, DeviceOperations,
    DeviceOperationsVtable, DeviceType,
};
use crate::error::{Error, IntoResult};
use crate::string::create_unicode_string;

pub struct Driver {
    pub(crate) raw: *mut DRIVER_OBJECT,
}

impl Driver {
    pub unsafe fn from_raw(raw: *mut DRIVER_OBJECT) -> Self {
        Self { raw }
    }

    pub unsafe fn as_raw(&self) -> *const DRIVER_OBJECT {
        self.raw as _
    }

    pub unsafe fn as_raw_mut(&mut self) -> *mut DRIVER_OBJECT {
        self.raw as _
    }

    pub fn create_device<T>(
        &mut self,
        name: &str,
        device_type: DeviceType,
        device_flags: DeviceFlags,
        device_do_flags: DeviceDoFlags,
        access: Access,
        data: T,
    ) -> Result<Device, Error>
    where
        T: DeviceOperations,
    {
        // Box the data.
        let data = Box::new(data);

        // Convert the name to UTF-16 and then create a UNICODE_STRING.
        let name = U16CString::from_str(name).unwrap();
        let mut name = create_unicode_string(name.as_slice());

        // Create the device.
        let mut device = core::ptr::null_mut();

        unsafe {
            IoCreateDevice(
                self.raw,
                core::mem::size_of::<DeviceExtension>() as u32,
                &mut name,
                device_type.into(),
                device_flags.bits(),
                access.is_exclusive() as _,
                &mut device,
            )
        }
        .into_result()?;

        unsafe {
            (*device).Flags |= device_do_flags.bits();
        }

        let device = unsafe { Device::from_raw(device) };

        // Store the boxed data and vtable.
        let extension = device.extension_mut();
        extension.device_type = device_type;
        extension.vtable = &DeviceOperationsVtable::<T>::VTABLE;
        extension.data = Box::into_raw(data) as *mut cty::c_void;

        Ok(device)
    }
}
