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
#include "wrapper.h"

void _ExInitializeFastMutex(
	PFAST_MUTEX fast_mutex
) {
	ExInitializeFastMutex(fast_mutex);
}

void _ExAcquirePushLockExclusive(
	PEX_PUSH_LOCK push_lock
) {
	ExAcquirePushLockExclusive(push_lock);
}

void _ExReleasePushLockExclusive(
	PEX_PUSH_LOCK push_lock
) {
	ExReleasePushLockExclusive(push_lock);
}

void _ExAcquirePushLockShared(
	PEX_PUSH_LOCK push_lock
) {
	ExAcquirePushLockShared(push_lock);
}

void _ExReleasePushLockShared(
	PEX_PUSH_LOCK push_lock
) {
	ExReleasePushLockShared(push_lock);
}

PIO_STACK_LOCATION _IoGetCurrentIrpStackLocation(PIRP irp) {
	return IoGetCurrentIrpStackLocation(irp);
}

PIO_STACK_LOCATION _IoGetNextIrpStackLocation(PIRP irp) {
	return IoGetNextIrpStackLocation(irp);
}

void _IoSetCompletionRoutine(
	PIRP irp,
	PIO_COMPLETION_ROUTINE completion_routine, 
	PVOID context,
	BOOLEAN invoke_on_success,
	BOOLEAN invoke_on_error,
	BOOLEAN invoke_on_cancel
) {
	IoSetCompletionRoutine(irp, completion_routine, context, invoke_on_success, invoke_on_error, invoke_on_cancel);
}

void _IoCompleteRequest(
	PIRP irp,
	CCHAR priority_boost
) {
	IoCompleteRequest(irp, priority_boost);
}

ULONG _MmGetMdlByteCount(PMDL mdl) {
	return MmGetMdlByteCount(mdl);
}

ULONG _MmGetMdlByteOffset(PMDL mdl) {
	return MmGetMdlByteOffset(mdl);
}

PVOID _MmGetSystemAddressForMdlSafe(PMDL mdl, ULONG priority) {
	return MmGetSystemAddressForMdlSafe(mdl, priority);
}

void _ObDereferenceObject(PVOID p) {
	ObDereferenceObject(p);
}

void _ObReferenceObject(PVOID p) {
	ObReferenceObject(p);
}

ULONG_PTR _IoGetRemainingStackSize() {
    return IoGetRemainingStackSize();
}

PKTHREAD _PsGetCurrentThread() {
    return PsGetCurrentThread();
}