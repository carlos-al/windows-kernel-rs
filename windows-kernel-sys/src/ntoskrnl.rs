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

use crate::base::*;

pub use self::IoGetCurrentProcess as PsGetCurrentProcess;
pub use self::_ExAcquirePushLockExclusive as ExAcquirePushLockExclusive;
pub use self::_ExAcquirePushLockShared as ExAcquirePushLockShared;
pub use self::_ExInitializeFastMutex as ExInitializeFastMutex;
pub use self::_ExReleasePushLockExclusive as ExReleasePushLockExclusive;
pub use self::_ExReleasePushLockShared as ExReleasePushLockShared;
pub use self::_IoCompleteRequest as IoCompleteRequest;
pub use self::_IoGetCurrentIrpStackLocation as IoGetCurrentIrpStackLocation;
pub use self::_IoGetNextIrpStackLocation as IoGetNextIrpStackLocation;
pub use self::_IoGetRemainingStackSize as IoGetRemainingStackSize;
pub use self::_IoSetCompletionRoutine as IoSetCompletionRoutine;
pub use self::_MmGetMdlByteCount as MmGetMdlByteCount;
pub use self::_MmGetMdlByteOffset as MmGetMdlByteOffset;
pub use self::_MmGetSystemAddressForMdlSafe as MmGetSystemAddressForMdlSafe;
pub use self::_ObDereferenceObject as ObDereferenceObject;
pub use self::_ObReferenceObject as ObReferenceObject;
pub use self::_PsGetCurrentThread as PsGetCurrentThread;

#[link(name = "wrapper_ntoskrnl")]
extern "C" {
    pub fn _ExInitializeFastMutex(mutex: PFAST_MUTEX);
    pub fn _ExAcquirePushLockExclusive(push_lock: PEX_PUSH_LOCK);
    pub fn _ExReleasePushLockExclusive(push_lock: PEX_PUSH_LOCK);
    pub fn _ExAcquirePushLockShared(push_lock: PEX_PUSH_LOCK);
    pub fn _ExReleasePushLockShared(push_lock: PEX_PUSH_LOCK);
    pub fn _IoGetCurrentIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION;
    pub fn _IoGetNextIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION;
    pub fn _IoSetCompletionRoutine(
        irp: PIRP,
        completion_routine: PIO_COMPLETION_ROUTINE,
        context: PVOID,
        invoke_on_success: BOOLEAN,
        invoke_on_error: BOOLEAN,
        invoke_on_cancel: BOOLEAN,
    );
    pub fn _IoCompleteRequest(irp: PIRP, priority_boost: CCHAR);
    pub fn _MmGetMdlByteCount(mdl: PMDL) -> ULONG;
    pub fn _MmGetMdlByteOffset(mdl: PMDL) -> ULONG;
    pub fn _MmGetSystemAddressForMdlSafe(mdl: PMDL, priority: ULONG) -> PVOID;
    pub fn _ObDereferenceObject(p: *mut cty::c_void);
    pub fn _ObReferenceObject(p: *mut cty::c_void);
    pub fn _IoGetRemainingStackSize() -> ULONG_PTR;
    pub fn _PsGetCurrentThread() -> PKTHREAD;
}

include!(concat!(env!("OUT_DIR"), "/ntoskrnl.rs"));
