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
use windows_kernel_sys::base::NTSTATUS;
use windows_kernel_sys::base::{
    STATUS_ACCESS_VIOLATION, STATUS_ARRAY_BOUNDS_EXCEEDED, STATUS_BREAKPOINT,
    STATUS_DATATYPE_MISALIGNMENT, STATUS_END_OF_FILE, STATUS_FLOAT_DENORMAL_OPERAND,
    STATUS_FLOAT_DIVIDE_BY_ZERO, STATUS_FLOAT_INEXACT_RESULT, STATUS_FLOAT_INVALID_OPERATION,
    STATUS_FLOAT_OVERFLOW, STATUS_FLOAT_STACK_CHECK, STATUS_FLOAT_UNDERFLOW,
    STATUS_GUARD_PAGE_VIOLATION, STATUS_ILLEGAL_INSTRUCTION, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INTEGER_DIVIDE_BY_ZERO, STATUS_INTEGER_OVERFLOW, STATUS_INVALID_DISPOSITION,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_INVALID_USER_BUFFER,
    STATUS_IN_PAGE_ERROR, STATUS_NONCONTINUABLE_EXCEPTION, STATUS_NOT_IMPLEMENTED,
    STATUS_NO_MEMORY, STATUS_PRIVILEGED_INSTRUCTION, STATUS_SINGLE_STEP, STATUS_STACK_OVERFLOW,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL, STATUS_UNWIND_CONSOLIDATE,
};

#[derive(Clone, Copy, Debug)]
pub struct Error(NTSTATUS);

impl Error {
    pub const GUARD_PAGE_VIOLATION: Error = Error(STATUS_GUARD_PAGE_VIOLATION);
    pub const DATATYPE_MISALIGNMENT: Error = Error(STATUS_DATATYPE_MISALIGNMENT);
    pub const BREAKPOINT: Error = Error(STATUS_BREAKPOINT);
    pub const SINGLE_STEP: Error = Error(STATUS_SINGLE_STEP);
    pub const UNWIND_CONSOLIDATE: Error = Error(STATUS_UNWIND_CONSOLIDATE);
    pub const UNSUCCESSFUL: Error = Error(STATUS_UNSUCCESSFUL);
    pub const NOT_IMPLEMENTED: Error = Error(STATUS_NOT_IMPLEMENTED);
    pub const ACCESS_VIOLATION: Error = Error(STATUS_ACCESS_VIOLATION);
    pub const IN_PAGE_ERROR: Error = Error(STATUS_IN_PAGE_ERROR);
    pub const INVALID_HANDLE: Error = Error(STATUS_INVALID_HANDLE);
    pub const INVALID_PARAMETER: Error = Error(STATUS_INVALID_PARAMETER);
    pub const END_OF_FILE: Error = Error(STATUS_END_OF_FILE);
    pub const NO_MEMORY: Error = Error(STATUS_NO_MEMORY);
    pub const ILLEGAL_INSTRUCTION: Error = Error(STATUS_ILLEGAL_INSTRUCTION);
    pub const NONCONTINUABLE_EXCEPTION: Error = Error(STATUS_NONCONTINUABLE_EXCEPTION);
    pub const INVALID_DISPOSITION: Error = Error(STATUS_INVALID_DISPOSITION);
    pub const ARRAY_BOUNDS_EXCEEDED: Error = Error(STATUS_ARRAY_BOUNDS_EXCEEDED);
    pub const FLOAT_DENORMAL_OPERAND: Error = Error(STATUS_FLOAT_DENORMAL_OPERAND);
    pub const FLOAT_DIVIDE_BY_ZERO: Error = Error(STATUS_FLOAT_DIVIDE_BY_ZERO);
    pub const FLOAT_INEXACT_RESULT: Error = Error(STATUS_FLOAT_INEXACT_RESULT);
    pub const FLOAT_INVALID_OPERATION: Error = Error(STATUS_FLOAT_INVALID_OPERATION);
    pub const FLOAT_OVERFLOW: Error = Error(STATUS_FLOAT_OVERFLOW);
    pub const FLOAT_STACK_CHECK: Error = Error(STATUS_FLOAT_STACK_CHECK);
    pub const FLOAT_UNDERFLOW: Error = Error(STATUS_FLOAT_UNDERFLOW);
    pub const INTEGER_DIVIDE_BY_ZERO: Error = Error(STATUS_INTEGER_DIVIDE_BY_ZERO);
    pub const INTEGER_OVERFLOW: Error = Error(STATUS_INTEGER_OVERFLOW);
    pub const PRIVILEGED_INSTRUCTION: Error = Error(STATUS_PRIVILEGED_INSTRUCTION);
    pub const INSUFFICIENT_RESOURCES: Error = Error(STATUS_INSUFFICIENT_RESOURCES);
    pub const INVALID_USER_BUFFER: Error = Error(STATUS_INVALID_USER_BUFFER);
    pub const STACK_OVERFLOW: Error = Error(STATUS_STACK_OVERFLOW);

    pub fn from_ntstatus(status: NTSTATUS) -> Error {
        Error(status)
    }

    pub fn to_ntstatus(&self) -> NTSTATUS {
        self.0
    }
}

pub trait IntoResult {
    fn into_result(self) -> Result<(), Error>;
}

impl IntoResult for NTSTATUS {
    fn into_result(self) -> Result<(), Error> {
        match self {
            STATUS_SUCCESS => Ok(()),
            status => Err(Error::from_ntstatus(status)),
        }
    }
}
