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
//! This module provides utilities to query information about the version of Microsoft Windows.

use windows_kernel_sys::base::RTL_OSVERSIONINFOW;
use windows_kernel_sys::ntoskrnl::RtlGetVersion;

use crate::error::{Error, IntoResult};

/// Represents version information for Microsoft Windows.
pub struct VersionInfo {
    version_info: RTL_OSVERSIONINFOW,
}

impl VersionInfo {
    /// Uses [`RtlGetVersion`] to query the version info for Microsoft Windows.
    pub fn query() -> Result<Self, Error> {
        let mut version_info: RTL_OSVERSIONINFOW = unsafe { core::mem::zeroed() };

        version_info.dwOSVersionInfoSize = core::mem::size_of::<RTL_OSVERSIONINFOW>() as u32;

        unsafe { RtlGetVersion(&mut version_info) }.into_result()?;

        Ok(Self { version_info })
    }

    /// Retrieves the major version of Microsoft Windows.
    pub fn major(&self) -> u32 {
        self.version_info.dwMajorVersion
    }

    /// Retrieves the minor version of Microsoft Windows.
    pub fn minor(&self) -> u32 {
        self.version_info.dwMinorVersion
    }

    /// Retrieves the build number of Microsoft Windows.
    pub fn build_number(&self) -> u32 {
        self.version_info.dwBuildNumber
    }
}
