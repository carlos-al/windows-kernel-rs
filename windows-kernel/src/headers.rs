#![allow(non_snake_case)]
#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

use core::ffi::{c_char, c_long, c_ulonglong};
use core::ptr::null_mut;

use bitflags::bitflags;

use windows_kernel_sys::base::{
    BOOLEAN, CHAR, CLIENT_ID, GUID, HANDLE, KAPC, KINTERRUPT_MODE, KINTERRUPT_POLARITY, KPRIORITY,
    KPROCESSOR_MODE, LARGE_INTEGER, LONG, LPSTR, NTSTATUS, PCONTEXT, PEPROCESS, PKAPC, PKTHREAD,
    POBJECT_TYPE, POHANDLE__, PROCESSINFOCLASS, PVOID, RTL_BALANCED_NODE, SIZE_T,
    SYSTEM_POWER_STATE, TRACEHANDLE, UCHAR, ULONG, ULONG64, ULONGLONG, UNICODE_STRING, USHORT,
    WCHAR, XSAVE_AREA_HEADER, XSAVE_FORMAT, _BUS_HANDLER, _CLIENT_ID, _CM_RESOURCE_LIST,
    _DEBUG_DEVICE_DESCRIPTOR, _DEVICE_OBJECT, _DMA_ADAPTER, _DMA_IOMMU_INTERFACE,
    _DMA_IOMMU_INTERFACE_EX, _DRIVER_OBJECT, _EX_PUSH_LOCK, _FAULT_INFORMATION, _GROUP_AFFINITY,
    _GUID, _IOMMU_DMA_DEVICE, _IOMMU_DMA_DOMAIN, _IOMMU_DMA_LOGICAL_ADDRESS_TOKEN,
    _IOMMU_DMA_LOGICAL_ADDRESS_TOKEN_MAPPED_SEGMENT, _KDEVICE_QUEUE, _KDPC, _KINTERRUPT,
    _LARGE_INTEGER, _LIST_ENTRY, _LOADER_PARAMETER_BLOCK, _MAP_REGISTER_ENTRY, _MDL,
    _PNP_REPLACE_PROCESSOR_LIST, _RTL_BALANCED_NODE, _RTL_BITMAP, _SCATTER_GATHER_LIST,
    _UNICODE_STRING, _WAIT_CONTEXT_BLOCK, _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, _WORK_QUEUE_ITEM,
};
use windows_kernel_sys::{c_uchar, c_ulong, c_ushort, c_void};

#[macro_export]
macro_rules! check_nt_status {
    ($expression:expr) => {{
        let status = $expression;
        if status != 0 {
            println!("c cago");
            return;
        }
    }};
}

#[macro_export]
macro_rules! nt_success {
    ($expression:expr) => {
        $expression == 0
    };
}

extern "system" {
    pub fn KeTestAlertThread(alert_mode: KPROCESSOR_MODE) -> BOOLEAN;
    pub fn KeInitializeApc(
        Apc: PKAPC,
        Thread: PKTHREAD,
        Environment: KAPC_ENVIRONMENT,
        KernelRoutine: PKKERNEL_ROUTINE,
        RundownRoutine: PKRUNDOWN_ROUTINE,
        NormalRoutine: PKNORMAL_ROUTINE,
        ProcessorMode: KPROCESSOR_MODE,
        NormalContext: PVOID,
    );
    pub fn KeInsertQueueApc(
        Apc: *mut KAPC,
        SystemArgument1: PVOID,
        SystemArgument2: PVOID,
        Increment: KPRIORITY,
    ) -> BOOLEAN;
    pub fn ZwQuerySystemInformation(
        SystemInformationClass: SYSTEM_INFORMATION_CLASS,
        SystemInformation: *mut SYSTEM_PROCESS_INFORMATION,
        SystemInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    pub fn PsGetProcessPeb(process: PEPROCESS) -> PPEB;
    pub fn PsIsProcessBeingDebugged(process: PEPROCESS) -> BOOLEAN;
    pub fn ZwQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: PROCESSINFOCLASS,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    pub fn ObGetObjectType(Object: PVOID) -> POBJECT_TYPE;
    pub fn ZwWriteVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut c_void,
        Buffer: *const c_void,
        NumberOfBytesToWrite: c_ulong,
        NumberOfBytesWritten: *mut c_ulong,
    ) -> NTSTATUS;
    pub fn ZwProtectVirtualMemory(
        ProcessHandle: *mut c_void,
        BaseAddress: *mut PVOID,
        ProtectSize: *mut c_ulong,
        NewProtect: c_ulong,
        OldProtect: *mut c_ulong,
    ) -> NTSTATUS;
    pub fn ZwTraceControl(
        FunctionCode: ULONG,
        InBuffer: PVOID,
        InBufferLen: ULONG,
        OutBuffer: PVOID,
        OutBufferLen: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;
    pub fn KeGetCurrentThread() -> PKTHREAD;
    pub fn PsGetProcessImageFileName(Process: PEPROCESS) -> LPSTR;
    pub fn ZwSetSystemInformation(
        SystemInformationClass: SYSTEM_INFORMATION_CLASS,
        SystemInformation: PVOID,
        SystemInformationLength: ULONG,
    ) -> NTSTATUS;
    pub fn RtlLookupFunctionEntry(
        ControlPc: ULONG64,
        ImageBase: *mut ULONG64,
        HistoryTable: *mut UNWIND_HISTORY_TABLE,
    ) -> *mut IMAGE_RUNTIME_FUNCTION_ENTRY;
    pub fn RtlVirtualUnwind(
        Flags: ULONG64,
        ImageBase: ULONG64,
        ControlPc: ULONG64,
        FunctionEntry: *mut IMAGE_RUNTIME_FUNCTION_ENTRY,
        ContextRecord: PCONTEXT,
        HandlerData: *mut PVOID,
        EstablisherFrame: *mut ULONG64,
        ContextPointers: PVOID,
    ) -> PVOID;
}

#[inline]
pub fn NtCurrentProcess() -> HANDLE {
    (-1_isize as *mut c_void) as HANDLE
}

#[inline]
pub fn ZwCurrentProcess() -> HANDLE {
    (-1_isize as *mut c_void) as HANDLE
}

#[allow(non_snake_case)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct KNONVOLATILE_CONTEXT_POINTERS {
    pub Anonymous1: KNONVOLATILE_CONTEXT_POINTERS_0,
    pub Anonymous2: KNONVOLATILE_CONTEXT_POINTERS_1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union KNONVOLATILE_CONTEXT_POINTERS_0 {
    pub FloatingContext: [*mut M128A; 16],
    pub Anonymous: KNONVOLATILE_CONTEXT_POINTERS_0_0,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct KNONVOLATILE_CONTEXT_POINTERS_0_0 {
    pub Xmm0: *mut M128A,
    pub Xmm1: *mut M128A,
    pub Xmm2: *mut M128A,
    pub Xmm3: *mut M128A,
    pub Xmm4: *mut M128A,
    pub Xmm5: *mut M128A,
    pub Xmm6: *mut M128A,
    pub Xmm7: *mut M128A,
    pub Xmm8: *mut M128A,
    pub Xmm9: *mut M128A,
    pub Xmm10: *mut M128A,
    pub Xmm11: *mut M128A,
    pub Xmm12: *mut M128A,
    pub Xmm13: *mut M128A,
    pub Xmm14: *mut M128A,
    pub Xmm15: *mut M128A,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union KNONVOLATILE_CONTEXT_POINTERS_1 {
    pub IntegerContext: [*mut u64; 16],
    pub Anonymous: KNONVOLATILE_CONTEXT_POINTERS_1_0,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct KNONVOLATILE_CONTEXT_POINTERS_1_0 {
    pub Rax: *mut u64,
    pub Rcx: *mut u64,
    pub Rdx: *mut u64,
    pub Rbx: *mut u64,
    pub Rsp: *mut u64,
    pub Rbp: *mut u64,
    pub Rsi: *mut u64,
    pub Rdi: *mut u64,
    pub R8: *mut u64,
    pub R9: *mut u64,
    pub R10: *mut u64,
    pub R11: *mut u64,
    pub R12: *mut u64,
    pub R13: *mut u64,
    pub R14: *mut u64,
    pub R15: *mut u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UNWIND_HISTORY_TABLE {
    pub Count: u32,
    pub LocalHint: u8,
    pub GlobalHint: u8,
    pub Search: u8,
    pub Once: u8,
    pub LowAddress: usize,
    pub HighAddress: usize,
    pub Entry: [UNWIND_HISTORY_TABLE_ENTRY; 12],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct UNWIND_HISTORY_TABLE_ENTRY {
    pub ImageBase: usize,
    pub FunctionEntry: *mut IMAGE_RUNTIME_FUNCTION_ENTRY,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IMAGE_RUNTIME_FUNCTION_ENTRY {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub Anonymous: IMAGE_RUNTIME_FUNCTION_ENTRY_0,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union IMAGE_RUNTIME_FUNCTION_ENTRY_0 {
    pub UnwindInfoAddress: u32,
    pub UnwindData: u32,
}

pub type CONTEXT_FLAGS = u32;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: CONTEXT_FLAGS,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union CONTEXT_0 {
    pub FltSave: XSAVE_FORMAT,
    pub Anonymous: CONTEXT_0_0,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    pub UniqueProcessId: USHORT,
    pub CreatorBackTraceIndex: USHORT,
    pub ObjectTypeIndex: UCHAR,
    pub HandleAttributes: UCHAR,
    pub HandleValue: USHORT,
    pub Object: PVOID,
    pub GrantedAccess: ULONG,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SYSTEM_HANDLE_INFORMATION {
    pub NumberOfHandles: ULONG,
    pub Handles: *const SYSTEM_HANDLE_TABLE_ENTRY_INFO,
}

/// PEB/PE Headers
const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

pub type DWORD = c_ulong;
pub type BOOL = i32;
pub type BYTE = c_uchar;
pub type WORD = c_ushort;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PEB_LDR_DATA {
    Length: ULONG,
    Initialized: BOOL,
    SsHandle: *mut c_void,
    pub InLoadOrderModuleList: _LIST_ENTRY,
    InMemoryOrderModuleList: _LIST_ENTRY,
    InInitializationOrderModuleList: _LIST_ENTRY,
}

pub type PPEB_LDR_DATA = *mut PEB_LDR_DATA;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PEB {
    Reserved1: [BYTE; 2],
    BeingDebugged: BYTE,
    Reserved2: [BYTE; 1],
    Reserved3: [*mut c_void; 2],
    pub Ldr: PPEB_LDR_DATA,
    ProcessParameters: *mut c_void,
    Reserved4: [*mut c_void; 3],
    AtlThunkSListPtr: *mut c_void,
    Reserved5: *mut c_void,
    Reserved6: ULONG,
    Reserved7: *mut c_void,
    Reserved8: ULONG,
    AtlThunkSListPtr32: ULONG,
    Reserved9: [*mut c_void; 45],
    Reserved10: [BYTE; 96],
    PostProcessInitRoutine: *mut c_void,
    Reserved11: [BYTE; 128],
    Reserved12: [*mut c_void; 1],
    SessionId: ULONG,
}

pub type PPEB = *mut PEB;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: _LIST_ENTRY,
    InMemoryOrderLinks: _LIST_ENTRY,
    InInitializationOrderLinks: _LIST_ENTRY,
    // or InProgressLinks: _LIST_ENTRY
    pub DllBase: *mut c_void,
    EntryPoint: *mut c_void,
    SizeOfImage: ULONG,
    FullDllName: _UNICODE_STRING,
    pub BaseDllName: _UNICODE_STRING,
    FlagGroup: [BYTE; 4],
    // or Flags: ULONG
    ObsoleteLoadCount: c_ushort,
    TlsIndex: c_ushort,
    HashLinks: _LIST_ENTRY,
    TimeDateStamp: ULONG,
    EntryPointActivationContext: *mut c_void,
    PatchInformation: *mut c_void,
    DdagNode: *mut c_void,
    NodeModuleLink: _LIST_ENTRY,
    SnapContext: *mut c_void,
    ParentDllBase: *mut c_void,
    SwitchBackContext: *mut c_void,
    BaseAddressIndexNode: RTL_BALANCED_NODE,
    MappingInfoIndexNode: RTL_BALANCED_NODE,
    OriginalBase: u64,
    LoadTime: LARGE_INTEGER,
    BaseNameHashValue: ULONG,
    LoadReason: LDR_DLL_LOAD_REASON,
}

#[repr(C)]
#[derive(Copy, Clone)]
enum LDR_DLL_LOAD_REASON {
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonUnknown = -1,
}

type PLDR_DLL_LOAD_REASON = *mut LDR_DLL_LOAD_REASON;

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    e_magic: WORD,
    e_cblp: WORD,
    e_cp: WORD,
    e_crlc: WORD,
    e_cparhdr: WORD,
    e_minalloc: WORD,
    e_maxalloc: WORD,
    e_ss: WORD,
    e_sp: WORD,
    e_csum: WORD,
    e_ip: WORD,
    e_cs: WORD,
    e_lfarlc: WORD,
    e_ovno: WORD,
    e_res: [WORD; 4],
    e_oemid: WORD,
    e_oeminfo: WORD,
    e_res2: [WORD; 10],
    pub e_lfanew: i32,
}

pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    Machine: WORD,
    pub NumberOfSections: WORD,
    TimeDateStamp: DWORD,
    PointerToSymbolTable: DWORD,
    NumberOfSymbols: DWORD,
    SizeOfOptionalHeader: WORD,
    Characteristics: WORD,
}

type PIMAGE_FILE_HEADER = *mut IMAGE_FILE_HEADER;

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    Size: DWORD,
}

type PIMAGE_DATA_DIRECTORY = *mut IMAGE_DATA_DIRECTORY;

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    MajorLinkerVersion: BYTE,
    MinorLinkerVersion: BYTE,
    SizeOfCode: DWORD,
    SizeOfInitializedData: DWORD,
    SizeOfUninitializedData: DWORD,
    AddressOfEntryPoint: DWORD,
    BaseOfCode: DWORD,
    ImageBase: u64,
    SectionAlignment: DWORD,
    FileAlignment: DWORD,
    MajorOperatingSystemVersion: WORD,
    MinorOperatingSystemVersion: WORD,
    MajorImageVersion: WORD,
    MinorImageVersion: WORD,
    MajorSubsystemVersion: WORD,
    MinorSubsystemVersion: WORD,
    Win32VersionValue: DWORD,
    SizeOfImage: DWORD,
    SizeOfHeaders: DWORD,
    CheckSum: DWORD,
    Subsystem: WORD,
    DllCharacteristics: WORD,
    SizeOfStackReserve: u64,
    SizeOfStackCommit: u64,
    SizeOfHeapReserve: u64,
    SizeOfHeapCommit: u64,
    LoaderFlags: DWORD,
    NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

type PIMAGE_OPTIONAL_HEADER64 = *mut IMAGE_OPTIONAL_HEADER64;

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

type PIMAGE_NT_HEADERS64 = *mut IMAGE_NT_HEADERS64;

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: ULONG,
    TimeDateStamp: ULONG,
    MajorVersion: USHORT,
    MinorVersion: USHORT,
    Name: ULONG,
    Base: ULONG,
    NumberOfFunctions: ULONG,
    pub NumberOfNames: ULONG,
    pub AddressOfFunctions: ULONG,
    pub AddressOfNames: ULONG,
    AddressOfNameOrdinals: ULONG,
}

type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

/// APC headers

pub type KeInitializeApcFn = unsafe extern "system" fn(
    Apc: PKAPC,
    Thread: PKTHREAD,
    Environment: KAPC_ENVIRONMENT,
    KernelRoutine: PKKERNEL_ROUTINE,
    RundownRoutine: PKRUNDOWN_ROUTINE,
    NormalRoutine: PKNORMAL_ROUTINE,
    ProcessorMode: KPROCESSOR_MODE,
    NormalContext: PVOID,
) -> ();

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment = 0,
    AttachedApcEnvironment = 1,
    CurrentApcEnvironment = 2,
    InsertApcEnvironment = 3,
}

pub type KAPC_ENVIRONMENT = _KAPC_ENVIRONMENT;
pub type PKAPC_ENVIRONMENT = *mut _KAPC_ENVIRONMENT;

pub type PKNORMAL_ROUTINE = Option<
    unsafe extern "system" fn(
        NormalContext: PVOID,
        SystemArgument1: PVOID,
        SystemArgument2: PVOID,
    ) -> (),
>;

pub type KKERNEL_ROUTINE = unsafe extern "system" fn(
    Apc: *mut KAPC,
    NormalRoutine: *mut PKNORMAL_ROUTINE,
    NormalContext: *mut PVOID,
    SystemArgument1: *mut PVOID,
    SystemArgument2: *mut PVOID,
) -> ();

pub type PKKERNEL_ROUTINE = Option<KKERNEL_ROUTINE>;

pub type PKRUNDOWN_ROUTINE = Option<unsafe extern "system" fn(Apc: *mut KAPC) -> ()>;

pub type KeInsertQueueApcFn = unsafe extern "system" fn(
    Apc: *mut KAPC,
    SystemArgument1: PVOID,
    SystemArgument2: PVOID,
    Increment: KPRIORITY,
) -> BOOLEAN;

/// Process/Thread info

const SystemProcessInformation: usize = 5;

#[repr(C)]
pub struct VM_COUNTERS {
    PeakVirtualSize: SIZE_T,
    VirtualSize: SIZE_T,
    PageFaultCount: ULONG,
    PeakWorkingSetSize: SIZE_T,
    WorkingSetSize: SIZE_T,
    QuotaPeakPagedPoolUsage: SIZE_T,
    QuotaPagedPoolUsage: SIZE_T,
    QuotaPeakNonPagedPoolUsage: SIZE_T,
    QuotaNonPagedPoolUsage: SIZE_T,
    PagefileUsage: SIZE_T,
    PeakPagefileUsage: SIZE_T,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SYSTEM_THREAD_INFORMATION {
    KernelTime: LARGE_INTEGER,
    UserTime: LARGE_INTEGER,
    CreateTime: LARGE_INTEGER,
    WaitTime: ULONG,
    StartAddress: PVOID,
    pub ClientId: CLIENT_ID,
    Priority: KPRIORITY,
    BasePriority: LONG,
    ContextSwitchCount: ULONG,
    State: ULONG,
    WaitReason: KWAIT_REASON,
}

impl Default for SYSTEM_THREAD_INFORMATION {
    fn default() -> Self {
        Self {
            KernelTime: LARGE_INTEGER { QuadPart: 0 },
            UserTime: LARGE_INTEGER { QuadPart: 0 },
            CreateTime: LARGE_INTEGER { QuadPart: 0 },
            WaitTime: 0,
            StartAddress: null_mut(),
            ClientId: _CLIENT_ID {
                UniqueProcess: null_mut(),
                UniqueThread: null_mut(),
            },
            Priority: 0,
            BasePriority: 0,
            ContextSwitchCount: 0,
            State: 0,
            WaitReason: KWAIT_REASON::Executive,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KWAIT_REASON {
    Executive = 0,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    MaximumWaitReason,
}

#[repr(C)]
pub struct IO_COUNTERS {
    ReadOperationCount: ULONGLONG,
    WriteOperationCount: ULONGLONG,
    OtherOperationCount: ULONGLONG,
    ReadTransferCount: ULONGLONG,
    WriteTransferCount: ULONGLONG,
    OtherTransferCount: ULONGLONG,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: c_ulong,
    pub NumberOfThreads: c_ulong,
    pub WorkingSetPrivateSize: LARGE_INTEGER,
    pub HardFaultCount: c_ulong,
    pub NumberOfThreadsHighWatermark: c_ulong,
    pub CycleTime: u64,
    pub CreateTime: LARGE_INTEGER,
    pub UserTime: LARGE_INTEGER,
    pub KernelTime: LARGE_INTEGER,
    pub ImageName: UNICODE_STRING,
    pub BasePriority: KPRIORITY,
    pub UniqueProcessId: HANDLE,
    pub InheritedFromUniqueProcessId: HANDLE,
    pub HandleCount: c_ulong,
    pub SessionId: c_ulong,
    pub UniqueProcessKey: usize,
    // ULONG_PTR is typically a pointer-sized integer.
    pub PeakVirtualSize: SIZE_T,
    pub VirtualSize: SIZE_T,
    pub PageFaultCount: c_ulong,
    pub PeakWorkingSetSize: SIZE_T,
    pub WorkingSetSize: SIZE_T,
    pub QuotaPeakPagedPoolUsage: SIZE_T,
    pub QuotaPagedPoolUsage: SIZE_T,
    pub QuotaPeakNonPagedPoolUsage: SIZE_T,
    pub QuotaNonPagedPoolUsage: SIZE_T,
    pub PagefileUsage: SIZE_T,
    pub PeakPagefileUsage: SIZE_T,
    pub PrivatePageCount: SIZE_T,
    pub ReadOperationCount: LARGE_INTEGER,
    pub WriteOperationCount: LARGE_INTEGER,
    pub OtherOperationCount: LARGE_INTEGER,
    pub ReadTransferCount: LARGE_INTEGER,
    pub WriteTransferCount: LARGE_INTEGER,
    pub OtherTransferCount: LARGE_INTEGER,
    pub Threads: [SYSTEM_THREAD_INFORMATION; 1], // This is a placeholder; actual usage may vary.
}

impl Default for SYSTEM_PROCESS_INFORMATION {
    fn default() -> Self {
        Self {
            NextEntryOffset: 0,
            NumberOfThreads: 0,
            WorkingSetPrivateSize: LARGE_INTEGER { QuadPart: 0 },
            HardFaultCount: 0,
            NumberOfThreadsHighWatermark: 0,
            CycleTime: 0,
            CreateTime: LARGE_INTEGER { QuadPart: 0 },
            UserTime: LARGE_INTEGER { QuadPart: 0 },
            KernelTime: LARGE_INTEGER { QuadPart: 0 },
            ImageName: UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: null_mut(),
            },
            BasePriority: 0,
            UniqueProcessId: null_mut(),
            InheritedFromUniqueProcessId: null_mut(),
            HandleCount: 0,
            SessionId: 0,
            UniqueProcessKey: 0,
            PeakVirtualSize: 0,
            VirtualSize: 0,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
            PrivatePageCount: 0,
            ReadOperationCount: LARGE_INTEGER { QuadPart: 0 },
            WriteOperationCount: LARGE_INTEGER { QuadPart: 0 },
            OtherOperationCount: LARGE_INTEGER { QuadPart: 0 },
            ReadTransferCount: LARGE_INTEGER { QuadPart: 0 },
            WriteTransferCount: LARGE_INTEGER { QuadPart: 0 },
            OtherTransferCount: LARGE_INTEGER { QuadPart: 0 },
            Threads: [SYSTEM_THREAD_INFORMATION::default(); 1],
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,
    // obsolete...delete
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformation = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    MaxSystemInfoClass = 82, // MaxSystemInfoClass should always be the last enum
}

pub type SYSTEM_INFORMATION_CLASS = _SYSTEM_INFORMATION_CLASS;
pub type ZwQuerySystemInformationFn = unsafe extern "system" fn(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: *mut SYSTEM_PROCESS_INFORMATION,
    SystemInformationLength: ULONG,
    ReturnLength: *mut ULONG,
) -> NTSTATUS;

pub const STATUS_INFO_LENGTH_MISMATCH: DWORD = 0xC0000004;

#[repr(C)]
pub struct EVENT_TRACE_PROPERTIES {
    pub Wnode: WNODE_HEADER,
    pub BufferSize: ULONG,
    pub MinimumBuffers: ULONG,
    pub MaximumBuffers: ULONG,
    pub MaximumFileSize: ULONG,
    pub LogFileMode: ULONG,
    pub FlushTimer: ULONG,
    pub EnableFlags: ULONG,
    pub DUMMYUNIONNAME: AgeLimitOrFlushThreshold,
    pub NumberOfBuffers: ULONG,
    pub FreeBuffers: ULONG,
    pub EventsLost: ULONG,
    pub BuffersWritten: ULONG,
    pub LogBuffersLost: ULONG,
    pub RealTimeBuffersLost: ULONG,
    pub LoggerThreadId: HANDLE,
    pub LogFileNameOffset: ULONG,
    pub LoggerNameOffset: ULONG,
}

#[repr(C)]
pub struct WNODE_HEADER {
    pub BufferSize: ULONG,
    pub ProviderId: ULONG,
    pub HistoricalContextOrVersionLinkage: HistoricalContextOrVersionLinkage,
    pub KernelHandleOrTimeStamp: KernelHandleOrTimeStamp,
    pub Guid: GUID,
    pub ClientContext: ULONG,
    pub Flags: ULONG,
}

#[repr(C)]
union AgeLimitOrFlushThreshold {
    AgeLimit: c_long,
    FlushThreshold: c_long,
}

#[derive(Copy, Clone)]
#[repr(C)]
struct VersionLinkage {
    Version: ULONG,
    Linkage: ULONG,
}

#[repr(C)]
union KernelHandleOrTimeStamp {
    KernelHandle: HANDLE,
    TimeStamp: LARGE_INTEGER,
}

#[repr(C)]
union HistoricalContextOrVersionLinkage {
    HistoricalContext: c_ulonglong,
    VersionLinkage: VersionLinkage,
}

bitflags! {
    pub struct EventTraceFlags: u32 {
        const EVENT_TRACE_FLAG_ALPC = 0x00100000;
        const EVENT_TRACE_FLAG_CSWITCH = 0x00000010;
        const EVENT_TRACE_FLAG_DBGPRINT = 0x00040000;
        const EVENT_TRACE_FLAG_DISK_FILE_IO = 0x00000200;
        const EVENT_TRACE_FLAG_DISK_IO = 0x00000100;
        const EVENT_TRACE_FLAG_DISK_IO_INIT = 0x00000400;
        const EVENT_TRACE_FLAG_DISPATCHER = 0x00000800;
        const EVENT_TRACE_FLAG_DPC = 0x00000020;
        const EVENT_TRACE_FLAG_DRIVER = 0x00800000;
        const EVENT_TRACE_FLAG_FILE_IO = 0x02000000;
        const EVENT_TRACE_FLAG_FILE_IO_INIT = 0x04000000;
        const EVENT_TRACE_FLAG_IMAGE_LOAD = 0x00000004;
        const EVENT_TRACE_FLAG_INTERRUPT = 0x00000040;
        const EVENT_TRACE_FLAG_JOB = 0x00080000;
        const EVENT_TRACE_FLAG_MEMORY_HARD_FAULTS = 0x00002000;
        const EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS = 0x00001000;
        const EVENT_TRACE_FLAG_NETWORK_TCPIP = 0x00010000;
        const EVENT_TRACE_FLAG_NO_SYSCONFIG = 0x10000000;
        const EVENT_TRACE_FLAG_PROCESS = 0x00000001;
        const EVENT_TRACE_FLAG_PROCESS_COUNTERS = 0x00000008;
        const EVENT_TRACE_FLAG_PROFILE = 0x01000000;
        const EVENT_TRACE_FLAG_REGISTRY = 0x00020000;
        const EVENT_TRACE_FLAG_SPLIT_IO = 0x00200000;
        const EVENT_TRACE_FLAG_SYSTEMCALL = 0x00000080;
        const EVENT_TRACE_FLAG_THREAD = 0x00000002;
        const EVENT_TRACE_FLAG_VAMAP = 0x00008000;
        const EVENT_TRACE_FLAG_VIRTUAL_ALLOC = 0x00004000;
    }
}

#[repr(u32)]
pub enum ETWTRACECONTROLCODE {
    EtwStartLoggerCode = 1,
    EtwStopLoggerCode = 2,
    EtwQueryLoggerCode = 3,
    EtwUpdateLoggerCode = 4,
    EtwFlushLoggerCode = 5,
    EtwIncrementLoggerFile = 6,
    EtwRealtimeTransition = 7,
    // reserved space is implicitly handled by not specifying those values
    EtwRealtimeConnectCode = 11,
    EtwActivityIdCreate = 12,
    EtwWdiScenarioCode = 13,
    EtwRealtimeDisconnectCode = 14,
    EtwRegisterGuidsCode = 15,
    EtwReceiveNotification = 16,
    EtwSendDataBlock = 17,
    EtwSendReplyDataBlock = 18,
    EtwReceiveReplyDataBlock = 19,
    EtwWdiSemUpdate = 20,
    EtwEnumTraceGuidList = 21,
    EtwGetTraceGuidInfo = 22,
    EtwEnumerateTraceGuids = 23,
    EtwRegisterSecurityProv = 24,
    EtwReferenceTimeCode = 25,
    EtwTrackBinaryCode = 26,
    EtwAddNotificationEvent = 27,
    EtwUpdateDisallowList = 28,
    EtwSetEnableAllKeywordsCode = 29,
    EtwSetProviderTraitsCode = 30,
    EtwUseDescriptorTypeCode = 31,
    EtwEnumTraceGroupList = 32,
    EtwGetTraceGroupInfo = 33,
    EtwGetDisallowList = 34,
    EtwSetCompressionSettings = 35,
    EtwGetCompressionSettings = 36,
    EtwUpdatePeriodicCaptureState = 37,
    EtwGetPrivateSessionTraceHandle = 38,
    EtwRegisterPrivateSession = 39,
    EtwQuerySessionDemuxObject = 40,
    EtwSetProviderBinaryTracking = 41,
    EtwMaxLoggers = 42,
    EtwMaxPmcCounter = 43,
    EtwQueryUsedProcessorCount = 44,
    EtwGetPmcOwnership = 45,
    EtwGetPmcSessions = 46,
}

#[allow(non_snake_case)]
#[repr(C)]
struct HAL_PRIVATE_DISPATCH {
    Version: ULONG,
    //0x0
    HalHandlerForBus:
        Option<unsafe extern "C" fn(arg1: _INTERFACE_TYPE, arg2: ULONG) -> *mut _BUS_HANDLER>,
    //0x8
    HalHandlerForConfigSpace:
        Option<unsafe extern "C" fn(arg1: _BUS_DATA_TYPE, arg2: ULONG) -> *mut _BUS_HANDLER>,
    //0x10
    HalLocateHiberRanges: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
    //0x18
    HalRegisterBusHandler: Option<
        unsafe extern "C" fn(
            arg1: _INTERFACE_TYPE,
            arg2: _BUS_DATA_TYPE,
            arg3: ULONG,
            arg4: _INTERFACE_TYPE,
            arg5: ULONG,
            arg6: ULONG,
            arg7: unsafe extern "C" fn(arg1: *mut _BUS_HANDLER) -> LONG,
            arg8: *mut *mut _BUS_HANDLER,
        ) -> LONG,
    >,
    //0x20
    HalSetWakeEnable: Option<unsafe extern "C" fn(arg1: UCHAR)>,
    //0x28
    HalSetWakeAlarm: Option<unsafe extern "C" fn(arg1: ULONGLONG, arg2: ULONGLONG) -> LONG>,
    //0x30
    HalPciTranslateBusAddress: Option<
        unsafe extern "C" fn(
            arg1: _INTERFACE_TYPE,
            arg2: ULONG,
            arg3: _LARGE_INTEGER,
            arg4: *mut ULONG,
            arg5: *mut _LARGE_INTEGER,
        ) -> UCHAR,
    >,
    //0x38
    HalPciAssignSlotResources: Option<
        unsafe extern "C" fn(
            arg1: *mut _UNICODE_STRING,
            arg2: *mut _UNICODE_STRING,
            arg3: *mut _DRIVER_OBJECT,
            arg4: *mut _DEVICE_OBJECT,
            arg5: _INTERFACE_TYPE,
            arg6: ULONG,
            arg7: ULONG,
            arg8: *mut *mut _CM_RESOURCE_LIST,
        ) -> LONG,
    >,
    //0x40
    HalHaltSystem: Option<unsafe extern "C" fn()>,
    //0x48
    HalFindBusAddressTranslation: Option<
        unsafe extern "C" fn(
            arg1: _LARGE_INTEGER,
            arg2: *mut ULONG,
            arg3: *mut _LARGE_INTEGER,
            arg4: *mut ULONGLONG,
            arg5: UCHAR,
        ) -> UCHAR,
    >,
    //0x50
    HalResetDisplay: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x58
    HalAllocateMapRegisters: Option<
        unsafe extern "C" fn(
            arg1: *mut _ADAPTER_OBJECT,
            arg2: ULONG,
            arg3: ULONG,
            arg4: *mut _MAP_REGISTER_ENTRY,
        ) -> LONG,
    >,
    //0x60
    KdSetupPciDeviceForDebugging: Option<
        unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut _DEBUG_DEVICE_DESCRIPTOR) -> LONG,
    >,
    //0x68
    KdReleasePciDeviceForDebugging:
        Option<unsafe extern "C" fn(arg1: *mut _DEBUG_DEVICE_DESCRIPTOR) -> LONG>,
    //0x70
    KdGetAcpiTablePhase0: Option<
        unsafe extern "C" fn(arg1: *mut _LOADER_PARAMETER_BLOCK, arg2: ULONG) -> *mut c_void,
    >,
    //0x78
    KdCheckPowerButton: Option<unsafe extern "C" fn()>,
    //0x80
    HalVectorToIDTEntry: Option<unsafe extern "C" fn(arg1: ULONG) -> UCHAR>,
    //0x88
    KdMapPhysicalMemory64:
        Option<unsafe extern "C" fn(arg1: _LARGE_INTEGER, arg2: ULONG, arg3: UCHAR) -> *mut c_void>,
    //0x90
    KdUnmapVirtualAddress:
        Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: ULONG, arg3: UCHAR)>,
    //0x98
    KdGetPciDataByOffset: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: ULONG,
            arg3: *mut c_void,
            arg4: ULONG,
            arg5: ULONG,
        ) -> ULONG,
    >,
    //0xa0
    KdSetPciDataByOffset: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: ULONG,
            arg3: *mut c_void,
            arg4: ULONG,
            arg5: ULONG,
        ) -> ULONG,
    >,
    //0xa8
    HalGetInterruptVectorOverride: Option<
        unsafe extern "C" fn(
            arg1: _INTERFACE_TYPE,
            arg2: ULONG,
            arg3: ULONG,
            arg4: ULONG,
            arg5: *mut UCHAR,
            arg6: *mut ULONGLONG,
        ) -> ULONG,
    >,
    //0xb0
    HalGetVectorInputOverride: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: *mut _GROUP_AFFINITY,
            arg3: *mut ULONG,
            arg4: *mut _KINTERRUPT_POLARITY,
            arg5: *mut _INTERRUPT_REMAPPING_INFO,
        ) -> LONG,
    >,
    //0xb8
    HalLoadMicrocode: Option<unsafe extern "C" fn(arg1: *mut c_void) -> LONG>,
    //0xc0
    HalUnloadMicrocode: Option<unsafe extern "C" fn() -> LONG>,
    //0xc8
    HalPostMicrocodeUpdate: Option<unsafe extern "C" fn() -> LONG>,
    //0xd0
    HalAllocateMessageTargetOverride: Option<
        unsafe extern "C" fn(
            arg1: *mut _DEVICE_OBJECT,
            arg2: *mut _GROUP_AFFINITY,
            arg3: ULONG,
            arg4: _KINTERRUPT_MODE,
            arg5: UCHAR,
            arg6: *mut ULONG,
            arg7: *mut UCHAR,
            arg8: *mut ULONG,
        ) -> LONG,
    >,
    //0xd8
    HalFreeMessageTargetOverride: Option<
        unsafe extern "C" fn(arg1: *mut _DEVICE_OBJECT, arg2: ULONG, arg3: *mut _GROUP_AFFINITY),
    >,
    //0xe0
    HalDpReplaceBegin: Option<
        unsafe extern "C" fn(arg1: *mut _HAL_DP_REPLACE_PARAMETERS, arg2: *mut *mut c_void) -> LONG,
    >,
    //0xe8
    HalDpReplaceTarget: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
    //0xf0
    HalDpReplaceControl: Option<unsafe extern "C" fn(arg1: ULONG, arg2: *mut c_void) -> LONG>,
    //0xf8
    HalDpReplaceEnd: Option<unsafe extern "C" fn(arg1: *mut c_void)>,
    //0x100
    HalPrepareForBugcheck: Option<unsafe extern "C" fn(arg1: ULONG)>,
    //0x108
    HalQueryWakeTime:
        Option<unsafe extern "C" fn(arg1: *mut ULONGLONG, arg2: *mut ULONGLONG) -> UCHAR>,
    //0x110
    HalReportIdleStateUsage: Option<unsafe extern "C" fn(arg1: UCHAR, arg2: *mut KAFFINITY_EX)>,
    //0x118
    HalTscSynchronization: Option<unsafe extern "C" fn(arg1: UCHAR, arg2: *mut ULONG)>,
    //0x120
    HalWheaInitProcessorGenericSection: Option<
        unsafe extern "C" fn(
            arg1: *mut _WHEA_ERROR_RECORD_SECTION_DESCRIPTOR,
            arg2: *mut _WHEA_PROCESSOR_GENERIC_ERROR_SECTION,
        ) -> LONG,
    >,
    //0x128
    HalStopLegacyUsbInterrupts: Option<unsafe extern "C" fn(arg1: SYSTEM_POWER_STATE)>,
    //0x130
    HalReadWheaPhysicalMemory:
        Option<unsafe extern "C" fn(arg1: _LARGE_INTEGER, arg2: ULONG, arg3: *mut c_void) -> LONG>,
    //0x138
    HalWriteWheaPhysicalMemory:
        Option<unsafe extern "C" fn(arg1: _LARGE_INTEGER, arg2: ULONG, arg3: *mut c_void) -> LONG>,
    //0x140
    HalDpMaskLevelTriggeredInterrupts: Option<unsafe extern "C" fn() -> LONG>,
    //0x148
    HalDpUnmaskLevelTriggeredInterrupts: Option<unsafe extern "C" fn() -> LONG>,
    //0x150
    HalDpGetInterruptReplayState:
        Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut *mut c_void) -> LONG>,
    //0x158
    HalDpReplayInterrupts: Option<unsafe extern "C" fn(arg1: *mut c_void) -> LONG>,
    //0x160
    HalQueryIoPortAccessSupported: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x168
    KdSetupIntegratedDeviceForDebugging: Option<
        unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut _DEBUG_DEVICE_DESCRIPTOR) -> LONG,
    >,
    //0x170
    KdReleaseIntegratedDeviceForDebugging:
        Option<unsafe extern "C" fn(arg1: *mut _DEBUG_DEVICE_DESCRIPTOR) -> LONG>,
    //0x178
    HalGetEnlightenmentInformation:
        Option<unsafe extern "C" fn(arg1: *mut _HAL_INTEL_ENLIGHTENMENT_INFORMATION)>,
    //0x180
    HalAllocateEarlyPages: Option<
        unsafe extern "C" fn(
            arg1: *mut _LOADER_PARAMETER_BLOCK,
            arg2: ULONG,
            arg3: *mut ULONGLONG,
            arg4: ULONG,
        ) -> *mut c_void,
    >,
    //0x188
    HalMapEarlyPages:
        Option<unsafe extern "C" fn(arg1: ULONGLONG, arg2: ULONG, arg3: ULONG) -> *mut c_void>,
    //0x190
    Dummy1: *mut c_void,
    //0x198
    Dummy2: *mut c_void,
    //0x1a0
    HalNotifyProcessorFreeze: Option<unsafe extern "C" fn(arg1: UCHAR, arg2: UCHAR)>,
    //0x1a8
    HalPrepareProcessorForIdle: Option<unsafe extern "C" fn(arg1: ULONG) -> LONG>,
    //0x1b0
    HalRegisterLogRoutine: Option<unsafe extern "C" fn(arg1: *mut _HAL_LOG_REGISTER_CONTEXT)>,
    //0x1b8
    HalResumeProcessorFromIdle: Option<unsafe extern "C" fn()>,
    //0x1c0
    Dummy: *mut c_void,
    //0x1c8
    HalVectorToIDTEntryEx: Option<unsafe extern "C" fn(arg1: ULONG) -> ULONG>,
    //0x1d0
    HalSecondaryInterruptQueryPrimaryInformation:
        Option<unsafe extern "C" fn(arg1: *mut _INTERRUPT_VECTOR_DATA, arg2: *mut ULONG) -> LONG>,
    //0x1d8
    HalMaskInterrupt: Option<unsafe extern "C" fn(arg1: ULONG, arg2: ULONG) -> LONG>,
    //0x1e0
    HalUnmaskInterrupt: Option<unsafe extern "C" fn(arg1: ULONG, arg2: ULONG) -> LONG>,
    //0x1e8
    HalIsInterruptTypeSecondary: Option<unsafe extern "C" fn(arg1: ULONG, arg2: ULONG) -> UCHAR>,
    //0x1f0
    HalAllocateGsivForSecondaryInterrupt:
        Option<unsafe extern "C" fn(arg1: *mut CHAR, arg2: USHORT, arg3: *mut ULONG) -> LONG>,
    //0x1f8
    HalAddInterruptRemapping: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: ULONG,
            arg3: *mut _PCI_BUSMASTER_DESCRIPTOR,
            arg4: UCHAR,
            arg5: *mut _INTERRUPT_VECTOR_DATA,
            arg6: ULONG,
        ) -> LONG,
    >,
    //0x200
    HalRemoveInterruptRemapping: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: ULONG,
            arg3: *mut _PCI_BUSMASTER_DESCRIPTOR,
            arg4: UCHAR,
            arg5: *mut _INTERRUPT_VECTOR_DATA,
            arg6: ULONG,
        ),
    >,
    //0x208
    HalSaveAndDisableHvEnlightenment: Option<unsafe extern "C" fn(arg1: UCHAR)>,
    //0x210
    HalRestoreHvEnlightenment: Option<unsafe extern "C" fn()>,
    //0x218
    HalFlushIoBuffersExternalCache: Option<unsafe extern "C" fn(arg1: *mut _MDL, arg2: UCHAR)>,
    //0x220
    HalFlushExternalCache: Option<unsafe extern "C" fn(arg1: UCHAR)>,
    //0x228
    HalPciEarlyRestore: Option<unsafe extern "C" fn(arg1: SYSTEM_POWER_STATE) -> LONG>,
    //0x230
    HalGetProcessorId:
        Option<unsafe extern "C" fn(arg1: ULONG, arg2: *mut ULONG, arg3: *mut ULONG) -> LONG>,
    //0x238
    HalAllocatePmcCounterSet: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: *mut _KPROFILE_SOURCE,
            arg3: ULONG,
            arg4: *mut *mut _HAL_PMC_COUNTERS,
        ) -> LONG,
    >,
    //0x240
    HalCollectPmcCounters:
        Option<unsafe extern "C" fn(arg1: *mut _HAL_PMC_COUNTERS, arg2: *mut ULONGLONG)>,
    //0x248
    HalFreePmcCounterSet: Option<unsafe extern "C" fn(arg1: *mut _HAL_PMC_COUNTERS)>,
    //0x250
    HalProcessorHalt: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: *mut c_void,
            arg3: unsafe extern "C" fn(arg1: *mut c_void) -> LONG,
        ) -> LONG,
    >,
    //0x258
    HalTimerQueryCycleCounter: Option<unsafe extern "C" fn(arg1: *mut ULONGLONG) -> ULONGLONG>,
    //0x260
    Dummy3: *mut c_void,
    //0x268
    HalPciMarkHiberPhase: Option<unsafe extern "C" fn()>,
    //0x270
    HalQueryProcessorRestartEntryPoint:
        Option<unsafe extern "C" fn(arg1: *mut _LARGE_INTEGER) -> LONG>,
    //0x278
    HalRequestInterrupt: Option<unsafe extern "C" fn(arg1: ULONG) -> LONG>,
    //0x280
    HalEnumerateUnmaskedInterrupts: Option<
        unsafe extern "C" fn(
            arg1: unsafe extern "C" fn(
                arg1: *mut c_void,
                arg2: *mut _HAL_UNMASKED_INTERRUPT_INFORMATION,
            ) -> UCHAR,
            arg2: *mut c_void,
            arg3: *mut _HAL_UNMASKED_INTERRUPT_INFORMATION,
        ) -> LONG,
    >,
    //0x288
    HalFlushAndInvalidatePageExternalCache: Option<unsafe extern "C" fn(arg1: _LARGE_INTEGER)>,
    //0x290
    KdEnumerateDebuggingDevices: Option<
        unsafe extern "C" fn(
            arg1: *mut c_void,
            arg2: *mut _DEBUG_DEVICE_DESCRIPTOR,
            arg3: unsafe extern "C" fn(arg1: *mut _DEBUG_DEVICE_DESCRIPTOR) -> KD_CALLBACK_ACTION,
        ) -> LONG,
    >,
    //0x298
    HalFlushIoRectangleExternalCache: Option<
        unsafe extern "C" fn(
            arg1: *mut _MDL,
            arg2: ULONG,
            arg3: ULONG,
            arg4: ULONG,
            arg5: ULONG,
            arg6: UCHAR,
        ),
    >,
    //0x2a0
    HalPowerEarlyRestore: Option<unsafe extern "C" fn(arg1: ULONG)>,
    //0x2a8
    HalQueryCapsuleCapabilities: Option<
        unsafe extern "C" fn(
            arg1: *mut c_void,
            arg2: ULONG,
            arg3: *mut ULONGLONG,
            arg4: *mut ULONG,
        ) -> LONG,
    >,
    //0x2b0
    HalUpdateCapsule:
        Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: ULONG, arg3: _LARGE_INTEGER) -> LONG>,
    //0x2b8
    HalPciMultiStageResumeCapable: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x2c0
    HalDmaFreeCrashDumpRegisters: Option<unsafe extern "C" fn(arg1: ULONG)>,
    //0x2c8
    HalAcpiAoacCapable: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x2d0
    HalInterruptSetDestination: Option<
        unsafe extern "C" fn(
            arg1: *mut _INTERRUPT_VECTOR_DATA,
            arg2: *mut _GROUP_AFFINITY,
            arg3: *mut ULONG,
        ) -> LONG,
    >,
    //0x2d8
    HalGetClockConfiguration:
        Option<unsafe extern "C" fn(arg1: *mut _HAL_CLOCK_TIMER_CONFIGURATION)>,
    //0x2e0
    HalClockTimerActivate: Option<unsafe extern "C" fn(arg1: UCHAR)>,
    //0x2e8
    HalClockTimerInitialize: Option<unsafe extern "C" fn()>,
    //0x2f0
    HalClockTimerStop: Option<unsafe extern "C" fn()>,
    //0x2f8
    HalClockTimerArm: Option<
        unsafe extern "C" fn(
            arg1: _HAL_CLOCK_TIMER_MODE,
            arg2: ULONGLONG,
            arg3: *mut ULONGLONG,
        ) -> LONG,
    >,
    //0x300
    HalTimerOnlyClockInterruptPending: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x308
    HalAcpiGetMultiNode: Option<unsafe extern "C" fn() -> *mut c_void>,
    //0x310
    HalPowerSetRebootHandler:
        Option<unsafe extern "C" fn(arg1: unsafe extern "C" fn(arg1: ULONG, arg2: *mut LONG))>,
    //0x318
    HalIommuRegisterDispatchTable: Option<unsafe extern "C" fn(arg1: *mut _HAL_IOMMU_DISPATCH)>,
    //0x320
    HalTimerWatchdogStart: Option<unsafe extern "C" fn()>,
    //0x328
    HalTimerWatchdogResetCountdown: Option<unsafe extern "C" fn()>,
    //0x330
    HalTimerWatchdogStop: Option<unsafe extern "C" fn()>,
    //0x338
    HalTimerWatchdogGeneratedLastReset: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x340
    HalTimerWatchdogTriggerSystemReset: Option<unsafe extern "C" fn(arg1: UCHAR) -> LONG>,
    //0x348
    HalInterruptVectorDataToGsiv:
        Option<unsafe extern "C" fn(arg1: *mut _INTERRUPT_VECTOR_DATA, arg2: *mut ULONG) -> LONG>,
    //0x350
    HalInterruptGetHighestPriorityInterrupt:
        Option<unsafe extern "C" fn(arg1: *mut ULONG, arg2: *mut UCHAR) -> LONG>,
    //0x358
    HalProcessorOn: Option<unsafe extern "C" fn(arg1: ULONG) -> LONG>,
    //0x360
    HalProcessorOff: Option<unsafe extern "C" fn() -> LONG>,
    //0x368
    HalProcessorFreeze: Option<unsafe extern "C" fn() -> LONG>,
    //0x370
    HalDmaLinkDeviceObjectByToken:
        Option<unsafe extern "C" fn(arg1: ULONGLONG, arg2: *mut _DEVICE_OBJECT) -> LONG>,
    //0x378
    HalDmaCheckAdapterToken: Option<unsafe extern "C" fn(arg1: ULONGLONG) -> LONG>,
    //0x380
    Dummy4: *mut c_void,
    //0x388
    HalTimerConvertPerformanceCounterToAuxiliaryCounter: Option<
        unsafe extern "C" fn(arg1: ULONGLONG, arg2: *mut ULONGLONG, arg3: *mut ULONGLONG) -> LONG,
    >,
    //0x390
    HalTimerConvertAuxiliaryCounterToPerformanceCounter: Option<
        unsafe extern "C" fn(arg1: ULONGLONG, arg2: *mut ULONGLONG, arg3: *mut ULONGLONG) -> LONG,
    >,
    //0x398
    HalTimerQueryAuxiliaryCounterFrequency:
        Option<unsafe extern "C" fn(arg1: *mut ULONGLONG) -> LONG>,
    //0x3a0
    HalConnectThermalInterrupt: Option<
        unsafe extern "C" fn(
            arg1: unsafe extern "C" fn(arg1: *mut _KINTERRUPT, arg2: *mut c_void) -> UCHAR,
        ) -> UCHAR,
    >,
    //0x3a8
    HalIsEFIRuntimeActive: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x3b0
    HalTimerQueryAndResetRtcErrors: Option<unsafe extern "C" fn(arg1: UCHAR) -> UCHAR>,
    //0x3b8
    HalAcpiLateRestore: Option<unsafe extern "C" fn()>,
    //0x3c0
    KdWatchdogDelayExpiration: Option<unsafe extern "C" fn(arg1: *mut ULONGLONG) -> LONG>,
    //0x3c8
    HalGetProcessorStats: Option<
        unsafe extern "C" fn(
            arg1: _HAL_PROCESSOR_STAT_TYPE,
            arg2: ULONG,
            arg3: ULONG,
            arg4: *mut ULONGLONG,
        ) -> LONG,
    >,
    //0x3d0
    HalTimerWatchdogQueryDueTime: Option<unsafe extern "C" fn(arg1: UCHAR) -> ULONGLONG>,
    //0x3d8
    HalConnectSyntheticInterrupt: Option<
        unsafe extern "C" fn(
            arg1: unsafe extern "C" fn(arg1: *mut _KINTERRUPT, arg2: *mut c_void) -> UCHAR,
        ) -> UCHAR,
    >,
    //0x3e0
    HalPreprocessNmi: Option<unsafe extern "C" fn(arg1: ULONG)>,
    //0x3e8
    HalEnumerateEnvironmentVariablesWithFilter: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: unsafe extern "C" fn(arg1: *mut _GUID, arg2: *mut WCHAR) -> UCHAR,
            arg3: *mut c_void,
            arg4: *mut ULONG,
        ) -> LONG,
    >,
    //0x3f0
    HalCaptureLastBranchRecordStack: Option<
        unsafe extern "C" fn(arg1: ULONG, arg2: *mut _HAL_LBR_ENTRY, arg3: *mut ULONG) -> LONG,
    >,
    //0x3f8
    HalClearLastBranchRecordStack: Option<unsafe extern "C" fn() -> UCHAR>,
    //0x400
    HalConfigureLastBranchRecord: Option<unsafe extern "C" fn(arg1: ULONG, arg2: ULONG) -> LONG>,
    //0x408
    HalGetLastBranchInformation:
        Option<unsafe extern "C" fn(arg1: *mut ULONG, arg2: *mut ULONG) -> UCHAR>,
    //0x410
    HalResumeLastBranchRecord: Option<unsafe extern "C" fn(arg1: UCHAR)>,
    //0x418
    HalStartLastBranchRecord: Option<unsafe extern "C" fn(arg1: ULONG, arg2: *mut ULONG) -> LONG>,
    //0x420
    HalStopLastBranchRecord: Option<unsafe extern "C" fn(arg1: ULONG) -> LONG>,
    //0x428
    HalIommuBlockDevice: Option<unsafe extern "C" fn(arg1: *mut _IOMMU_DMA_DEVICE) -> LONG>,
    //0x430
    HalIommuUnblockDevice: Option<
        unsafe extern "C" fn(
            arg1: *mut _EXT_IOMMU_DEVICE_ID,
            arg2: *mut _DEVICE_OBJECT,
            arg3: *mut *mut _IOMMU_DMA_DEVICE,
        ) -> LONG,
    >,
    //0x438
    HalGetIommuInterface:
        Option<unsafe extern "C" fn(arg1: ULONG, arg2: *mut _DMA_IOMMU_INTERFACE) -> LONG>,
    //0x440
    HalRequestGenericErrorRecovery:
        Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut ULONG) -> LONG>,
    //0x448
    HalTimerQueryHostPerformanceCounter: Option<unsafe extern "C" fn(arg1: *mut ULONGLONG) -> LONG>,
    //0x450
    HalTopologyQueryProcessorRelationships: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: ULONG,
            arg3: *mut UCHAR,
            arg4: *mut UCHAR,
            arg5: *mut UCHAR,
            arg6: *mut ULONG,
            arg7: *mut ULONG,
        ) -> LONG,
    >,
    //0x458
    HalInitPlatformDebugTriggers: Option<unsafe extern "C" fn()>,
    //0x460
    HalRunPlatformDebugTriggers: Option<unsafe extern "C" fn(arg1: UCHAR)>,
    //0x468
    HalTimerGetReferencePage: Option<unsafe extern "C" fn() -> *mut c_void>,
    //0x470
    HalGetHiddenProcessorPowerInterface:
        Option<unsafe extern "C" fn(arg1: *mut _HIDDEN_PROCESSOR_POWER_INTERFACE) -> LONG>,
    //0x478
    HalGetHiddenProcessorPackageId: Option<unsafe extern "C" fn(arg1: ULONG) -> ULONG>,
    //0x480
    HalGetHiddenPackageProcessorCount: Option<unsafe extern "C" fn(arg1: ULONG) -> ULONG>,
    //0x488
    HalGetHiddenProcessorApicIdByIndex:
        Option<unsafe extern "C" fn(arg1: ULONG, arg2: *mut ULONG) -> LONG>,
    //0x490
    HalRegisterHiddenProcessorIdleState:
        Option<unsafe extern "C" fn(arg1: ULONG, arg2: ULONGLONG) -> LONG>,
    //0x498
    HalIommuReportIommuFault:
        Option<unsafe extern "C" fn(arg1: ULONGLONG, arg2: *mut _FAULT_INFORMATION)>,
    //0x4a0
    HalIommuDmaRemappingCapable:
        Option<unsafe extern "C" fn(arg1: *mut _EXT_IOMMU_DEVICE_ID, arg2: *mut ULONG) -> UCHAR>,
    //0x4a8
    HalAllocatePmcCounterSetEx: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: *mut _KPROFILE_SOURCE,
            arg3: ULONG,
            arg4: *mut ULONG,
            arg5: *mut *mut _HAL_PMC_COUNTERS,
            arg6: *mut ULONG,
        ) -> LONG,
    >,
    //0x4b0
    HalStartProfileInterruptEx: Option<
        unsafe extern "C" fn(
            arg1: _KPROFILE_SOURCE,
            arg2: *mut ULONG,
            arg3: *mut ULONG,
            arg4: *mut *mut _HAL_PMC_COUNTERS,
        ) -> LONG,
    >,
    //0x4b8
    HalGetIommuInterfaceEx: Option<
        unsafe extern "C" fn(
            arg1: ULONG,
            arg2: ULONGLONG,
            arg3: *mut _DMA_IOMMU_INTERFACE_EX,
        ) -> LONG,
    >,
    //0x4c0
    HalNotifyIommuDomainPolicyChange: Option<unsafe extern "C" fn(arg1: *mut _DEVICE_OBJECT)>,
    //0x4c8
    HalPciGetDeviceLocationFromPhysicalAddress: Option<
        unsafe extern "C" fn(
            arg1: ULONGLONG,
            arg2: *mut USHORT,
            arg3: *mut UCHAR,
            arg4: *mut UCHAR,
            arg5: *mut UCHAR,
        ) -> UCHAR,
    >,
    //0x4d0
    HalInvokeSmc: Option<
        unsafe extern "C" fn(
            arg1: ULONGLONG,
            arg2: ULONGLONG,
            arg3: ULONGLONG,
            arg4: ULONGLONG,
            arg5: ULONGLONG,
            arg6: ULONGLONG,
            arg7: ULONGLONG,
            arg8: *mut ULONGLONG,
            arg9: *mut ULONGLONG,
            arg10: *mut ULONGLONG,
            arg11: *mut ULONGLONG,
        ),
    >,
    //0x4d8
    HalInvokeHvc: Option<
        unsafe extern "C" fn(
            arg1: ULONGLONG,
            arg2: ULONGLONG,
            arg3: ULONGLONG,
            arg4: ULONGLONG,
            arg5: ULONGLONG,
            arg6: ULONGLONG,
            arg7: ULONGLONG,
            arg8: *mut ULONGLONG,
            arg9: *mut ULONGLONG,
            arg10: *mut ULONGLONG,
            arg11: *mut ULONGLONG,
        ),
    >,
    //0x4e0
    HalGetSoftRebootDatabase: Option<unsafe extern "C" fn() -> _LARGE_INTEGER>, //0x4e8
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct _HAL_INTEL_ENLIGHTENMENT_INFORMATION {
    Enlightenments: u32,
    HypervisorConnected: u32,
    EndOfInterrupt: Option<extern "C" fn()>,
    ApicWriteIcr: Option<extern "C" fn(u32, u32)>,
    Reserved0: u32,
    SpinCountMask: u32,
    LongSpinWait: Option<extern "C" fn(u32)>,
    GetReferenceTime: Option<extern "C" fn() -> u64>,
    SetSystemSleepProperty: Option<extern "C" fn(u32, u8, u8) -> i32>,
    EnterSleepState: Option<extern "C" fn(u32) -> i32>,
    NotifyDebugDeviceAvailable: Option<extern "C" fn() -> i32>,
    MapDeviceInterrupt: Option<
        extern "C" fn(
            u64,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
        ) -> i32,
    >,
    UnmapDeviceInterrupt: Option<extern "C" fn(u64, *mut core::ffi::c_void) -> i32>,
    RetargetDeviceInterrupt: Option<
        extern "C" fn(
            u64,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
            *mut core::ffi::c_void,
        ) -> i32,
    >,
    SetHpetConfig: Option<extern "C" fn(u32, u64, u8, *mut core::ffi::c_void) -> i32>,
    NotifyHpetEnabled: Option<extern "C" fn() -> i32>,
    QueryAssociatedProcessors: Option<extern "C" fn(u32, *mut u32, *mut u32) -> i32>,
    ReadMultipleMsr: Option<extern "C" fn(u32, u32, *mut u32, *mut u64) -> i32>,
    WriteMultipleMsr: Option<extern "C" fn(u32, u32, *mut u32, *mut u64) -> i32>,
    ReadCpuid: Option<extern "C" fn(u32, u32, *mut u32, *mut u32, *mut u32, *mut u32) -> i32>,
    LpWritebackInvalidate: Option<extern "C" fn(u32) -> i32>,
    GetMachineCheckContext: Option<extern "C" fn(u32, *mut u32, *mut u64, *mut u32) -> i32>,
    SuspendPartition: Option<extern "C" fn(u64) -> i32>,
    ResumePartition: Option<extern "C" fn(u64) -> i32>,
    SetSystemMachineCheckProperty: Option<extern "C" fn(*mut core::ffi::c_void) -> i32>,
    WheaErrorNotification: Option<extern "C" fn(*mut core::ffi::c_void, u8, u8) -> i32>,
    GetProcessorIndexFromVpIndex: Option<extern "C" fn(u32) -> u32>,
    SyntheticClusterIpi: Option<extern "C" fn(*mut core::ffi::c_void, u32) -> i32>,
    VpStartEnabled: Option<extern "C" fn() -> u8>,
    StartVirtualProcessor: Option<extern "C" fn(u32, *mut core::ffi::c_void) -> i32>,
    GetVpIndexFromApicId: Option<extern "C" fn(u32, *mut u32) -> i32>,
    IumAccessPciDevice:
        Option<extern "C" fn(u8, u32, u32, u32, u32, u32, u32, *mut core::ffi::c_void) -> i32>,
    IumEfiRuntimeService: Option<extern "C" fn(u32, *mut core::ffi::c_void, u64, *mut u64) -> u64>,
    SvmGetSystemCapabilities: Option<extern "C" fn(*mut core::ffi::c_void)>,
    GetDeviceCapabilities:
        Option<extern "C" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> i32>,
    SvmCreatePasidSpace: Option<extern "C" fn(u32, u32) -> i32>,
    SvmSetPasidAddressSpace: Option<extern "C" fn(u32, u32, u64) -> i32>,
    SvmFlushPasid: Option<extern "C" fn(u32, u32, u32, *mut core::ffi::c_void)>,
    SvmAttachPasidSpace: Option<extern "C" fn(u64, u32, u32, u32) -> i32>,
    SvmDetachPasidSpace: Option<extern "C" fn(u64) -> i32>,
    SvmEnablePasid: Option<extern "C" fn(u64, u32) -> i32>,
    SvmDisablePasid: Option<extern "C" fn(u64, u32) -> i32>,
    SvmAcknowledgePageRequest: Option<extern "C" fn(u32, *mut core::ffi::c_void, *mut u32) -> i32>,
    SvmCreatePrQueue: Option<extern "C" fn(u32, u32, c_ulonglong, u32, u32) -> i32>,
    SvmDeletePrQueue: Option<extern "C" fn(u32) -> i32>,
    SvmClearPrqStalled: Option<extern "C" fn(u32) -> i32>,
    SetDeviceAtsEnabled: Option<extern "C" fn(*mut core::ffi::c_void, u8) -> i32>,
    SetDeviceCapabilities: Option<extern "C" fn(u64, u32, u32) -> i32>,
    HvDebuggerPowerHandler: Option<extern "C" fn(u8) -> i32>,
    SetQpcBias: Option<extern "C" fn(u64) -> i32>,
    GetQpcBias: Option<extern "C" fn() -> u64>,
    RegisterDeviceId: Option<extern "C" fn(*mut core::ffi::c_void, u64) -> i32>,
    UnregisterDeviceId: Option<extern "C" fn(u64) -> i32>,
    AllocateDeviceDomain: Option<extern "C" fn(*mut core::ffi::c_void) -> i32>,
    AttachDeviceDomain: Option<extern "C" fn(u64, *mut core::ffi::c_void) -> i32>,
    DetachDeviceDomain: Option<extern "C" fn(u64) -> i32>,
    DeleteDeviceDomain: Option<extern "C" fn(*mut core::ffi::c_void) -> i32>,
    MapDeviceLogicalRange: Option<
        extern "C" fn(
            *mut core::ffi::c_void,
            u32,
            c_ulonglong,
            *mut c_ulonglong,
            *mut c_ulonglong,
            u8,
        ) -> i32,
    >,
    UnmapDeviceLogicalRange:
        Option<extern "C" fn(*mut core::ffi::c_void, c_ulonglong, *mut c_ulonglong) -> i32>,
    MapDeviceSparsePages: Option<
        extern "C" fn(*mut core::ffi::c_void, u32, *mut c_ulonglong, *mut c_ulonglong) -> i32,
    >,
    UnmapDeviceSparsePages:
        Option<extern "C" fn(*mut core::ffi::c_void, *mut c_ulonglong, *mut c_ulonglong) -> i32>,
    GetDmaGuardEnabled: Option<extern "C" fn(*mut u8) -> i32>,
    UpdateMicrocode: Option<extern "C" fn(*mut core::ffi::c_void, u32, u8) -> i32>,
    GetSintMessage: Option<extern "C" fn(u8, *mut *mut core::ffi::c_void) -> i32>,
    SetRootFaultReportingReady: Option<extern "C" fn() -> i32>,
    ConfigureDeviceDomain:
        Option<extern "C" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> i32>,
    UnblockDefaultDma: Option<extern "C" fn() -> i32>,
    FlushDeviceDomain: Option<extern "C" fn(*mut core::ffi::c_void) -> i32>,
    FlushDeviceDomainVaList:
        Option<extern "C" fn(*mut core::ffi::c_void, u32, *mut core::ffi::c_void) -> i32>,
    GetHybridPassthroughReservedRegions: Option<extern "C" fn(*mut core::ffi::c_void) -> i32>,
}

#[repr(C)]
struct _HAL_LOG_REGISTER_CONTEXT {
    LogRoutine: Option<extern "C" fn(usize, PVOID, usize)>,
    Flag: u32,
}

#[repr(C)]
struct _WHEA_PROCESSOR_GENERIC_ERROR_SECTION {
    ValidBits: _WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS,
    ProcessorType: u8,
    InstructionSet: u8,
    ErrorType: u8,
    Operation: u8,
    Flags: u8,
    Level: u8,
    Reserved: u16,
    CPUVersion: u64,
    CPUBrandString: [u8; 128],
    ProcessorId: u64,
    TargetAddress: u64,
    RequesterId: u64,
    ResponderId: u64,
    InstructionPointer: u64,
}

#[repr(C)]
union _WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS {
    ValidBits: u64,
}

#[repr(C)]
struct _HAL_DP_REPLACE_PARAMETERS {
    Flags: u32,
    TargetProcessors: *mut _PNP_REPLACE_PROCESSOR_LIST,
    SpareProcessors: *mut _PNP_REPLACE_PROCESSOR_LIST,
}

struct HAL_LOG_REGISTER_CONTEXT {
    LogRoutine: Option<fn(u32, PVOID, u32)>,
    Flag: u32,
}

#[repr(C)]
struct KAFFINITY_EX {
    Count: u16,
    Size: u16,
    Reserved: u32,
    StaticBitmap: [u64; 32],
}

#[repr(u32)]
enum KD_CALLBACK_ACTION {
    KdConfigureDeviceAndContinue = 0,
    KdSkipDeviceAndContinue = 1,
    KdConfigureDeviceAndStop = 2,
    KdSkipDeviceAndStop = 3,
}

#[repr(C)]
struct _HAL_CLOCK_TIMER_CONFIGURATION {
    Flags: u8,
    KnownType: u32,
    Capabilities: u32,
    MaxIncrement: u64,
    MinIncrement: u32,
}

#[repr(C)]
struct _PCI_BUSMASTER_DESCRIPTOR {
    Type: PCI_BUSMASTER_RID_TYPE,
    // 0x0
    Segment: u32,
    // 0x4
    union: [u8; 4], // 0x8
}

#[repr(u32)]
enum PCI_BUSMASTER_RID_TYPE {
    BusmasterRidInvalid = 0,
    BusmasterRidFromDeviceRid = 1,
    BusmasterRidFromBridgeRid = 2,
    BusmasterRidFromMultipleBridges = 3,
}

#[repr(C)]
struct _HAL_UNMASKED_INTERRUPT_INFORMATION {
    Version: u16,
    // 0x0
    Size: u16,
    // 0x2
    Flags: HAL_UNMASKED_INTERRUPT_FLAGS,
    // 0x4
    Mode: KINTERRUPT_MODE,
    // 0x8
    Polarity: KINTERRUPT_POLARITY,
    // 0xc
    Gsiv: u32,
    // 0x10
    PinNumber: u16,
    // 0x14
    DeviceHandle: *mut c_void, // 0x18
}

#[repr(C)]
union HAL_UNMASKED_INTERRUPT_FLAGS {
    AsUSHORT: u16,
}

#[repr(u32)]
pub enum _HAL_PROCESSOR_STAT_TYPE {
    HalProcessorStatResidency = 0,
    HalProcessorStatCount = 1,
    HalProcessorStatMax = 2,
}

#[repr(u32)]
pub enum _HAL_CLOCK_TIMER_MODE {
    HalClockTimerModePeriodic = 0,
    HalClockTimerModeOneShot = 1,
    HalClockTimerModeMax = 2,
}

#[repr(C)]
pub struct _HAL_IOMMU_DISPATCH {
    pub hal_iommu_support_enabled: Option<extern "C" fn() -> core::ffi::c_uchar>,
    pub hal_iommu_get_configuration: Option<
        extern "C" fn(
            core::ffi::c_ulong,
            *mut core::ffi::c_ulong,
            *mut core::ffi::c_ulong,
            *mut *mut c_void,
        ) -> c_long,
    >,
    pub hal_iommu_get_library_context:
        Option<extern "C" fn(core::ffi::c_ulong, core::ffi::c_ulong, *mut *mut c_void) -> c_long>,
    pub hal_iommu_map_device: Option<
        extern "C" fn(
            *mut c_void,
            *mut _EXT_IOMMU_DEVICE_ID,
            *mut _DEVICE_OBJECT,
            *mut _IOMMU_SVM_CAPABILITIES,
            *mut *mut c_void,
        ) -> c_long,
    >,
    pub hal_iommu_enable_device_pasid: Option<extern "C" fn(*mut c_void, *mut c_void) -> c_long>,
    pub hal_iommu_set_address_space: Option<extern "C" fn(*mut c_void, u64) -> c_long>,
    pub hal_iommu_disable_device_pasid: Option<extern "C" fn(*mut c_void, *mut c_void) -> c_long>,
    pub hal_iommu_unmap_device: Option<extern "C" fn(*mut c_void, *mut c_void) -> c_long>,
    pub hal_iommu_free_library_context: Option<extern "C" fn(*mut c_void) -> c_long>,
    pub hal_iommu_flush_tb:
        Option<extern "C" fn(*mut c_void, core::ffi::c_ulong, *mut _KTB_FLUSH_VA) -> c_void>,
    pub hal_iommu_flush_all_pasid:
        Option<extern "C" fn(*mut c_void, core::ffi::c_ulong, *mut _KTB_FLUSH_VA) -> c_void>,
    pub hal_iommu_process_page_request_queue:
        Option<extern "C" fn(core::ffi::c_ulong) -> core::ffi::c_uchar>,
    pub hal_iommu_fault_routine: Option<extern "C" fn(core::ffi::c_ulong) -> c_void>,
    pub hal_iommu_reference_asid: Option<extern "C" fn(core::ffi::c_ulong) -> *mut c_void>,
    pub hal_iommu_dereference_asid: Option<extern "C" fn(core::ffi::c_ulong) -> c_void>,
    pub hal_iommu_service_page_fault:
        Option<extern "C" fn(u64, *mut c_void, core::ffi::c_ulong) -> c_long>,
    pub hal_iommu_device_power_change:
        Option<extern "C" fn(*mut c_void, *mut c_void, core::ffi::c_uchar) -> c_long>,
    pub hal_iommu_begin_device_reset:
        Option<extern "C" fn(*mut c_void, *mut core::ffi::c_ulong) -> c_long>,
    pub hal_iommu_finalize_device_reset: Option<extern "C" fn(*mut c_void) -> c_long>,
    pub hal_iommu_get_ats_settings:
        Option<extern "C" fn(*mut _EXT_IOMMU_DEVICE_ID, *mut _IOMMU_ATS_SETTINGS) -> c_long>,
    pub hal_iommu_create_ats_device: Option<
        extern "C" fn(
            *mut _EXT_IOMMU_DEVICE_ID,
            *mut _DEVICE_OBJECT,
            *mut _IOMMU_SVM_CAPABILITIES,
            *mut *mut c_void,
        ) -> c_long,
    >,
    pub hal_iommu_delete_ats_device: Option<extern "C" fn(*mut c_void) -> c_void>,
    pub hal_iommu_get_domain_transition_support:
        Option<extern "C" fn(*mut _EXT_IOMMU_DEVICE_ID, *mut core::ffi::c_uchar) -> c_long>,
}

#[repr(C)]
union _IOMMU_SVM_CAPABILITIES {
    AtsCapability: u32,
    PriCapability: u32,
    CapReg: u32,
    Rsvd: u32,
    AsULONG: u32,
}

#[repr(C)]
union _IOMMU_ATS_SETTINGS {
    AsUCHAR: u8,
}

#[repr(C)]
union _KTB_FLUSH_VA {
    Va: PVOID,
    VaLong: u64,
}

#[repr(C)]
union InterruptMessageData {
    xapic_message: XapicMessage,
    hypertransport: Hypertransport,
    generic_message: GenericMessage,
    message_request: MessageRequest,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
enum HalProcessorStatType {
    HalProcessorStatResidency = 0,
    HalProcessorStatCount = 1,
    HalProcessorStatMax = 2,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct XapicMessage {
    address: _LARGE_INTEGER,
    data_payload: core::ffi::c_ulong,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Hypertransport {
    intr_info: _INTERRUPT_HT_INTR_INFO,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct _INTERRUPT_HT_INTR_INFO {
    flags: u32,
    extended_destination: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct GenericMessage {
    address: _LARGE_INTEGER,
    data_payload: core::ffi::c_ulong,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MessageRequest {
    destination_mode: HAL_APIC_DESTINATION_MODE,
}

#[repr(u32)]
#[derive(Copy, Clone)]
enum HAL_APIC_DESTINATION_MODE {
    ApicDestinationModePhysical = 1,
    ApicDestinationModeLogicalFlat = 2,
    ApicDestinationModeLogicalClustered = 3,
    ApicDestinationModeUnknown = 4,
}

#[repr(C)]
struct _INTERRUPT_VECTOR_DATA {
    type_: INTERRUPT_CONNECTION_TYPE,
    vector: core::ffi::c_ulong,
    irql: core::ffi::c_uchar,
    polarity: _KINTERRUPT_POLARITY,
    mode: _KINTERRUPT_MODE,
    target_processors: _GROUP_AFFINITY,
    int_remap_info: _INTERRUPT_REMAPPING_INFO,
    controller_input: core::ffi::c_ulong,
    hv_device_id: c_ulonglong,
    message_data: InterruptMessageData,
}

#[repr(C)]
struct _INTERRUPT_REMAPPING_INFO {
    irt_index: core::ffi::c_ulong,
    // Using a full ulong for simplicity, use bitfields for precise control
    msi: MsiData,
}

#[repr(C)]
#[derive(Copy, Clone)]
union MsiData {
    msi_fields: MsiFields,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MsiFields {
    message_address_high: core::ffi::c_ulong,
    message_address_low: core::ffi::c_ulong,
    message_data: core::ffi::c_ushort,
    reserved: core::ffi::c_ushort,
}

#[repr(C)]
enum INTERRUPT_CONNECTION_TYPE {
    InterruptTypeControllerInput = 0,
    InterruptTypeXapicMessage = 1,
    InterruptTypeHypertransport = 2,
    InterruptTypeMessageRequest = 3,
}

#[repr(i32)]
enum _INTERFACE_TYPE {
    InterfaceTypeUndefined = -1,
    Internal = 0,
    Isa = 1,
    Eisa = 2,
    MicroChannel = 3,
    TurboChannel = 4,
    PCIBus = 5,
    VMEBus = 6,
    NuBus = 7,
    PCMCIABus = 8,
    CBus = 9,
    MPIBus = 10,
    MPSABus = 11,
    ProcessorInternal = 12,
    InternalPowerBus = 13,
    PNPISABus = 14,
    PNPBus = 15,
    Vmcs = 16,
    ACPIBus = 17,
    MaximumInterfaceType = 18,
}

#[repr(i32)]
enum _BUS_DATA_TYPE {
    ConfigurationSpaceUndefined = -1,
    Cmos = 0,
    EisaConfiguration = 1,
    Pos = 2,
    CbusConfiguration = 3,
    PCIConfiguration = 4,
    VMEConfiguration = 5,
    NuBusConfiguration = 6,
    PCMCIAConfiguration = 7,
    MPIConfiguration = 8,
    MPSAConfiguration = 9,
    PNPISAConfiguration = 10,
    SgiInternalConfiguration = 11,
    MaximumBusDataType = 12,
}

struct _ADAPTER_OBJECT {
    AdapterObject: _HALP_DMA_ADAPTER_OBJECT,
    MasterAdapter: *mut _HALP_DMA_MASTER_ADAPTER_OBJECT,
    WaitQueueEntry: _LIST_ENTRY,
    ChannelWaitQueue: _KDEVICE_QUEUE,
    ResourceWaitLock: u64,
    ResourceWaitQueue: _LIST_ENTRY,
    ChannelResourceWaitQueue: _LIST_ENTRY,
    ResourceQueueBusy: u8,
    MapRegistersPerChannel: u32,
    MapRegisterBase: *mut u8,
    NumberOfMapRegisters: u32,
    MaxTransferLength: u32,
    CrashDumpRegisterBase: [*mut u8; 2],
    NumberOfCrashDumpRegisters: [u32; 2],
    CrashDumpRegisterRefCount: [u32; 2],
    AdapterCrashDumpList: _LIST_ENTRY,
    MapRegisterMdl: *mut _MDL,
    MapRegisterMdlLock: u64,
    ExpiredLock: _EX_PUSH_LOCK,
    AllocationHandle: *mut u8,
    VirtualAddress: *mut u8,
    IsAllocationMdlBased: u8,
    NoLocalPool: u8,
    ExpiredFlag: u8,
    CurrentWcb: *mut _WAIT_CONTEXT_BLOCK,
    CurrentTransferContext: *mut _DMA_TRANSFER_CONTEXT,
    DmaController: *mut _HALP_DMA_CONTROLLER,
    Controller: u32,
    ChannelNumber: u32,
    RequestLine: u32,
    RequestedChannelCount: u32,
    AllocatedChannelCount: u32,
    AllocatedChannels: [u32; 8],
    ChannelAdapter: *mut u8,
    NeedsMapRegisters: u8,
    MasterDevice: u8,
    ScatterGather: u8,
    AutoInitialize: u8,
    IgnoreCount: u8,
    CacheCoherent: u8,
    Dma32BitAddresses: u8,
    Dma64BitAddresses: u8,
    DmaAddressWidth: u32,
    DmaPortWidth: _DMA_WIDTH,
    DeviceAddress: u64,
    AdapterList: _LIST_ENTRY,
    WorkItem: _WORK_QUEUE_ITEM,
    DomainPointer: *mut _HALP_DMA_DOMAIN_OBJECT,
    TranslationType: _HALP_DMA_TRANSLATION_TYPE,
    AdapterInUse: u8,
    DeviceObject: *mut _DEVICE_OBJECT,
    DeviceId: *mut _EXT_IOMMU_DEVICE_ID,
    IommuDevice: *mut _IOMMU_DMA_DEVICE,
    ScatterGatherMdl: *mut _MDL,
    LowMemoryLogicalAddressToken: *mut _IOMMU_DMA_LOGICAL_ADDRESS_TOKEN,
    LowMemoryLogicalAddressQueueLock: u64,
    LowMemoryLogicalAddressQueue: _LIST_ENTRY,
    LowMemoryLogicalAddressQueueInUse: u8,
    LowMemoryLogicalAddressQueueEntry: _HALP_EMERGENCY_LA_QUEUE_ENTRY,
    AllocationState: _HALP_DMA_ADAPTER_ALLOCATION_STATE,
    ScatterGatherBufferLength: u32,
    ScatterGatherBuffer: _SCATTER_GATHER_LIST,
}

#[repr(C)]
struct _HALP_DMA_ADAPTER_OBJECT {
    dma_header: _DMA_ADAPTER,
    signature: core::ffi::c_ulong,
    contiguous_map_registers: *mut _RTL_BITMAP,
    scatter_buffer_list_head: *mut _HALP_DMA_TRANSLATION_ENTRY,
    number_of_free_scatter_buffers: core::ffi::c_ulong,
    contiguous_translations: *mut _HALP_DMA_TRANSLATION_BUFFER,
    scatter_translations: *mut _HALP_DMA_TRANSLATION_BUFFER,
    contiguous_translation_end: _HALP_DMA_TRANSLATION_BUFFER_POSITION,
    scatter_translation_end: _HALP_DMA_TRANSLATION_BUFFER_POSITION,
    crash_dump: CrashDump,
    spin_lock: u64,
    grow_lock: u64,
    maximum_physical_address: _LARGE_INTEGER,
    is_master_adapter: core::ffi::c_uchar,
    dma_can_cross_64k: core::ffi::c_uchar,
    library_version: core::ffi::c_ulong,
}

#[repr(C)]
struct _HALP_DMA_TRANSLATION_ENTRY {
    physical_address: c_ulonglong,
    next: *mut _HALP_DMA_TRANSLATION_ENTRY,
    mapped_length: core::ffi::c_ulong,
    remapping_address: _IOMMU_DMA_LOGICAL_ADDRESS_TOKEN_MAPPED_SEGMENT,
    u: _HALP_DMA_TRANSLATION_ENTRY_UNION,
    next_mapping: *mut _HALP_DMA_TRANSLATION_ENTRY,
    logical_bounce_buffer_premapped: u8,
}

bitflags! {
    struct _HALP_DMA_TRANSLATION_ENTRY_UNION_Flags: u64 {
        const BOUND_TO_MASTER = 0b1;
        const BOUND_TO_SCATTER_POOL = 0b10;
        const OWNED_BY_MASTER = 0b100;
        const OWNED_BY_SCATTER_POOL = 0b1000;
        const TEMPORARY_MAPPING = 0b10000;
        const ZERO_BUFFER = 0b100000;
        // Assuming the address takes up the remaining bits,
        // you might need to adjust the mask and shift based on the actual structure.
        const ADDRESS_MASK = 0x03FFFFFFFFFFFFFF;
    }
}

#[repr(C)]
union _HALP_DMA_TRANSLATION_ENTRY_UNION {
    virtual_address: *mut c_void,
    flags: u64, // Directly use u64 here for FFI compatibility.
}

#[repr(C)]
struct _HALP_DMA_TRANSLATION_BUFFER {
    next: *mut _HALP_DMA_TRANSLATION_BUFFER,
    entry_count: core::ffi::c_ulong,
    entries: *mut _HALP_DMA_TRANSLATION_ENTRY,
}

#[repr(C)]
struct _HALP_DMA_TRANSLATION_BUFFER_POSITION {
    buffer: *mut _HALP_DMA_TRANSLATION_BUFFER,
    offset: core::ffi::c_ulong,
}

#[repr(C)]
struct CrashDump {
    contiguous_hint: _HALP_DMA_TRANSLATION_BUFFER_POSITION,
    scatter_hint: _HALP_DMA_TRANSLATION_BUFFER_POSITION,
}

#[repr(C)]
struct _HALP_DMA_MASTER_ADAPTER_OBJECT {
    AdapterObject: _HALP_DMA_ADAPTER_OBJECT,
    ContiguousAdapterQueue: _LIST_ENTRY,
    ScatterAdapterQueue: _LIST_ENTRY,
    MapBufferSize: core::ffi::c_ulong,
    MapBufferPhysicalAddress: _LARGE_INTEGER,
    ContiguousPageCount: core::ffi::c_ulong,
    ContiguousPageLimit: core::ffi::c_ulong,
    ScatterPageCount: core::ffi::c_ulong,
    ScatterPageLimit: core::ffi::c_ulong,
}

#[repr(C, align(8))]
struct _DMA_TRANSFER_CONTEXT {
    version: core::ffi::c_ulong,
    v1: _DMA_TRANSFER_CONTEXT_V1,
}

#[repr(C)]
struct _DMA_TRANSFER_CONTEXT_V1 {
    dma_state: c_long,
    transfer_state: core::ffi::c_ulong,
    wcb: _WAIT_CONTEXT_BLOCK,
    hal_wcb: *mut c_void,
}

#[repr(C)]
struct _HALP_DMA_CONTROLLER {
    controllers: _LIST_ENTRY,
    adapter_list: _LIST_ENTRY,
    controller_id: core::ffi::c_ulong,
    minimum_request_line: core::ffi::c_ulong,
    maximum_request_line: core::ffi::c_ulong,
    channel_count: core::ffi::c_ulong,
    scatter_gather_limit: core::ffi::c_ulong,
    channels: *mut _HALP_DMA_CHANNEL,
    extension_data: *mut c_void,
    cache_coherent: core::ffi::c_uchar,
    dma_address_width: core::ffi::c_ulong,
    operations: _DMA_FUNCTION_TABLE,
    supported_port_widths: core::ffi::c_ulong,
    minimum_transfer_unit: core::ffi::c_ulong,
    lock: u64,
    irql: core::ffi::c_uchar,
    generates_interrupt: core::ffi::c_uchar,
    gsi: c_long,
    interrupt_polarity: _KINTERRUPT_POLARITY,
    interrupt_mode: _KINTERRUPT_MODE,
    resource_id: _UNICODE_STRING,
    power_handle: *mut POHANDLE__,
    power_active: core::ffi::c_uchar,
}

#[repr(i32)]
enum _KINTERRUPT_MODE {
    LevelSensitive = 0,
    Latched = 1,
}

#[repr(C)]
struct _DMA_FUNCTION_TABLE {
    initialize_controller: Option<extern "C" fn(arg1: *mut c_void)>,
    validate_request_line_binding: Option<
        extern "C" fn(
            arg1: *mut c_void,
            arg2: *mut _DMA_REQUEST_LINE_BINDING_DESCRIPTION,
        ) -> core::ffi::c_uchar,
    >,
    query_max_fragments: Option<
        extern "C" fn(
            arg1: *mut c_void,
            arg2: core::ffi::c_ulong,
            arg3: core::ffi::c_ulong,
        ) -> core::ffi::c_ulong,
    >,
    program_channel: Option<
        extern "C" fn(
            arg1: *mut c_void,
            arg2: core::ffi::c_ulong,
            arg3: core::ffi::c_ulong,
            arg4: *mut _DMA_SCATTER_GATHER_LIST,
            arg5: _LARGE_INTEGER,
            arg6: core::ffi::c_uchar,
            arg7: core::ffi::c_uchar,
        ),
    >,
    configure_channel: Option<
        extern "C" fn(
            arg1: *mut c_void,
            arg2: core::ffi::c_ulong,
            arg3: core::ffi::c_ulong,
            arg4: *mut c_void,
        ) -> c_long,
    >,
    flush_channel: Option<extern "C" fn(arg1: *mut c_void, arg2: core::ffi::c_ulong)>,
    handle_interrupt: Option<
        extern "C" fn(
            arg1: *mut c_void,
            arg2: *mut core::ffi::c_ulong,
            arg3: *mut _DMA_INTERRUPT_TYPE,
        ) -> core::ffi::c_uchar,
    >,
    read_dma_counter:
        Option<extern "C" fn(arg1: *mut c_void, arg2: core::ffi::c_ulong) -> core::ffi::c_ulong>,
    report_common_buffer: Option<
        extern "C" fn(
            arg1: *mut c_void,
            arg2: core::ffi::c_ulong,
            arg3: *mut c_void,
            arg4: _LARGE_INTEGER,
        ),
    >,
    cancel_transfer:
        Option<extern "C" fn(arg1: *mut c_void, arg2: core::ffi::c_ulong) -> core::ffi::c_uchar>,
}

#[repr(C)]
struct _DMA_REQUEST_LINE_BINDING_DESCRIPTION {
    request_line: core::ffi::c_ulong,
    channel_number: core::ffi::c_ulong,
}

#[repr(C)]
struct _DMA_SCATTER_GATHER_LIST {
    number_of_elements: core::ffi::c_ulong,
    reserved: c_ulonglong,
    Elements: *mut _SCATTER_GATHER_ELEMENT,
}

#[repr(C)]
struct _SCATTER_GATHER_ELEMENT {
    address: _LARGE_INTEGER,
    length: core::ffi::c_ulong,
    reserved: c_ulonglong,
}

type CurrentCompletionRoutineType = unsafe extern "C" fn(
    *mut _DMA_ADAPTER,
    *mut _DEVICE_OBJECT,
    *mut c_void,
    DMA_COMPLETION_STATUS,
);

#[repr(i32)]
enum DMA_COMPLETION_STATUS {
    DmaComplete = 0,
    DmaAborted = 1,
    DmaError = 2,
    DmaCancelled = 3,
}

#[repr(C)]
struct _HALP_DMA_CHANNEL {
    channel_number: core::ffi::c_ulong,
    initialized: core::ffi::c_uchar,
    busy: core::ffi::c_uchar,
    complete: core::ffi::c_uchar,
    current_completion_routine: Option<CurrentCompletionRoutineType>,
    current_completion_context: *mut c_void,
    current_child_adapter: *mut _DMA_ADAPTER,
    current_interrupt_type: _DMA_INTERRUPT_TYPE,
    dpc: _KDPC,
    generates_interrupt: core::ffi::c_uchar,
    gsi: c_long,
    interrupt_polarity: _KINTERRUPT_POLARITY,
    interrupt_mode: _KINTERRUPT_MODE,
    common_buffer_length: core::ffi::c_ulong,
    common_buffer_virtual_address: *mut c_void,
    common_buffer_logical_address: _LARGE_INTEGER,
    adapter_queue: _LIST_ENTRY,
}

#[repr(i32)]
enum _DMA_INTERRUPT_TYPE {
    InterruptTypeCompletion = 0,
    InterruptTypeError = 1,
    InterruptTypeCancelled = 2,
}

#[repr(C)]
enum _DMA_WIDTH {
    Width8Bits = 0,
    Width16Bits = 1,
    Width32Bits = 2,
    Width64Bits = 3,
    WidthNoWrap = 4,
    MaximumDmaWidth = 5,
}

#[repr(C)]
struct _HALP_DMA_DOMAIN_OBJECT {
    list_entry: _LIST_ENTRY,
    maximum_physical_address: _LARGE_INTEGER,
    boundary_address_multiple: _LARGE_INTEGER,
    cache_coherent: core::ffi::c_uchar,
    firmware_reserved: core::ffi::c_uchar,
    iommu_domain_pointer: *mut _IOMMU_DMA_DOMAIN,
    translation_type: _HALP_DMA_TRANSLATION_TYPE,
    owning_adapter: *mut _ADAPTER_OBJECT,
    common_buffer_root: _RTL_RB_TREE,
    common_buffer_tree_lock: c_ulonglong,
    vector_common_buffer_list_head: _LIST_ENTRY,
    vector_common_buffer_lock: c_ulonglong,
    domain_ref_count: core::ffi::c_ulong,
}

#[repr(C)]
struct _RTL_RB_TREE {
    root: *mut _RTL_BALANCED_NODE,
    min: *mut _RTL_BALANCED_NODE, // This will also be used to store the encoded value
}

#[repr(i32)]
enum _HALP_DMA_TRANSLATION_TYPE {
    DmaTranslationTypePassthrough = 0,
    DmaTranslationTypeSafePassthrough = 1,
    DmaTranslationTypeHybridPassthrough = 2,
    DmaTranslationTypeTranslate = 3,
    DmaTranslationTypeMax = 4,
}

#[repr(C)]
struct _HALP_EMERGENCY_LA_QUEUE_ENTRY {
    ListEntry: _LIST_ENTRY,
    EntryType: _HALP_EMERGENCY_LA_QUEUE_TYPE,
}

#[repr(i32)]
enum _HALP_DMA_ADAPTER_ALLOCATION_STATE {
    HalpDmaAdapterAllocationStateNone = 0,
    HalpDmaAdapterAllocateChannel = 1,
    HalpDmaAdapterAllocateMapRegisters = 2,
    HalpDmaAdapterAllocateChannelRemapResources = 3,
    HalpDmaAdapterAllocationStateComplete = 4,
    HalpDmaAdapterAllocationStateMax = 5,
}

#[repr(i32)]
enum _HALP_EMERGENCY_LA_QUEUE_TYPE {
    HalpDmaLegacyLaQueueEntry = 0,
    HalpDmaThinLaQueueEntry = 1,
    HalpDmaLaQueueEntryMax = 2,
}

#[repr(C)]
struct _HAL_PMC_COUNTERS;

#[repr(C)]
enum _KPROFILE_SOURCE {
    ProfileTime = 0,
    ProfileAlignmentFixup = 1,
    ProfileTotalIssues = 2,
    ProfilePipelineDry = 3,
    ProfileLoadInstructions = 4,
    ProfilePipelineFrozen = 5,
    ProfileBranchInstructions = 6,
    ProfileTotalNonissues = 7,
    ProfileDcacheMisses = 8,
    ProfileIcacheMisses = 9,
    ProfileCacheMisses = 10,
    ProfileBranchMispredictions = 11,
    ProfileStoreInstructions = 12,
    ProfileFpInstructions = 13,
    ProfileIntegerInstructions = 14,
    Profile2Issue = 15,
    Profile3Issue = 16,
    Profile4Issue = 17,
    ProfileSpecialInstructions = 18,
    ProfileTotalCycles = 19,
    ProfileIcacheIssues = 20,
    ProfileDcacheAccesses = 21,
    ProfileMemoryBarrierCycles = 22,
    ProfileLoadLinkedIssues = 23,
    ProfileMaximum = 24,
}

#[repr(C)]
#[derive(Copy, Clone)]
union DeviceIdUnion {
    Pci: _EXT_IOMMU_DEVICE_ID_PCI,
    Acpi: _EXT_IOMMU_DEVICE_ID_ACPI,
    IoApicId: core::ffi::c_uchar,
    LogicalId: c_ulonglong,
    Test: _EXT_IOMMU_DEVICE_ID_TEST,
    Gic: _EXT_IOMMU_DEVICE_ID_GIC,
}

#[repr(C)]
#[derive(Copy, Clone)]
union _EXT_IOMMU_DEVICE_ID_PCI_UNION {
    as_uint64: c_ulonglong,
    parts: _EXT_IOMMU_DEVICE_ID_PCI_PARTS,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct _EXT_IOMMU_DEVICE_ID_PCI_PARTS {
    pci_segment_number: core::ffi::c_ushort,
    bdf: core::ffi::c_ushort,
    device_path_length: core::ffi::c_ushort,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct _EXT_IOMMU_DEVICE_ID_PCI {
    data: _EXT_IOMMU_DEVICE_ID_PCI_UNION,
    device_path: *const core::ffi::c_ushort,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct _EXT_IOMMU_DEVICE_ID_ACPI {
    ObjectName: *const c_char,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct _EXT_IOMMU_DEVICE_ID_TEST {
    UniqueId: c_ulonglong,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct _EXT_IOMMU_DEVICE_ID_GIC {
    LineNumber: core::ffi::c_ulong,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct _EXT_IOMMU_DEVICE_ID {
    DeviceType: _EXT_IOMMU_DEVICE_TYPE,
    Flags: _EXT_IOMMU_DEVICE_ID_FLAGS,
    DeviceId: DeviceIdUnion,
}

#[repr(i32)]
#[derive(Copy, Clone)]
enum _EXT_IOMMU_DEVICE_TYPE {
    EXT_IOMMU_DEVICE_TYPE_INVALID = 0,
    EXT_IOMMU_DEVICE_TYPE_PCI = 1,
    EXT_IOMMU_DEVICE_TYPE_ACPI = 2,
    EXT_IOMMU_DEVICE_TYPE_IOAPIC = 3,
    EXT_IOMMU_DEVICE_TYPE_LOGICAL = 4,
    EXT_IOMMU_DEVICE_TYPE_GIC = 5,
    EXT_IOMMU_DEVICE_TYPE_TEST = 6,
    EXT_IOMMU_DEVICE_TYPE_MAX = 7,
}

#[repr(C)]
#[derive(Copy, Clone)]
union _EXT_IOMMU_DEVICE_ID_FLAGS {
    as_ushort: u16,
}

impl _EXT_IOMMU_DEVICE_ID_FLAGS {
    // Getter for the `IsAliased` flag
    fn is_aliased(&self) -> u16 {
        unsafe { self.as_ushort & 0b1 }
    }

    // Setter for the `IsAliased` flag
    fn set_is_aliased(&mut self, value: u16) {
        unsafe {
            self.as_ushort = (self.as_ushort & !0b1) | (value & 0b1);
        }
    }
}

#[repr(C)]
struct _HIDDEN_PROCESSOR_POWER_INTERFACE {
    Version: core::ffi::c_ulong,
    ReadPerfMsr: Option<
        extern "C" fn(arg1: core::ffi::c_ulong, arg2: core::ffi::c_ulong, arg3: *mut u64) -> c_long,
    >,
    WritePerfMsr: Option<
        extern "C" fn(
            arg1: core::ffi::c_ulong,
            arg2: core::ffi::c_ulong,
            arg3: u64,
            arg4: u64,
        ) -> c_long,
    >,
    ReadPerfIoPort: Option<
        extern "C" fn(
            arg1: core::ffi::c_ulong,
            arg2: core::ffi::c_ushort,
            arg3: core::ffi::c_ushort,
            arg4: *mut core::ffi::c_ulong,
        ) -> c_long,
    >,
    WritePerfIoPort: Option<
        extern "C" fn(
            arg1: core::ffi::c_ulong,
            arg2: core::ffi::c_ushort,
            arg3: core::ffi::c_ushort,
            arg4: core::ffi::c_ulong,
            arg5: core::ffi::c_ulong,
        ) -> c_long,
    >,
}

#[repr(C)]
struct _HAL_LBR_ENTRY {
    FromAddress: *mut c_void,
    ToAddress: *mut c_void,
    Reserved: *mut c_void,
}

#[repr(i32)]
enum _KINTERRUPT_POLARITY {
    InterruptPolarityUnknown = 0,
    InterruptActiveHigh = 1,
    //InterruptRisingEdge = 1, // Same value as InterruptActiveHigh
    InterruptActiveLow = 2,
    //InterruptFallingEdge = 2, // Same value as InterruptActiveLow
    InterruptActiveBoth = 3,
    //InterruptActiveBothTriggerLow = 3, // Same value as InterruptActiveBoth
    InterruptActiveBothTriggerHigh = 4,
}

#[repr(C)]
pub struct KPRCB {
    pub mx_csr: u32,
    // 0x0
    pub legacy_number: u8,
    // 0x4
    pub reserved_must_be_zero: u8,
    // 0x5
    pub interrupt_request: u8,
    // 0x6
    pub idle_halt: u8,
    // 0x7
    pub current_thread: PKTHREAD,
    // 0x8
    pub next_thread: PKTHREAD,
    // 0x10
    pub idle_thread: PKTHREAD,
    // 0x18
    pub nesting_level: u8,
    // 0x20
    pub clock_owner: u8,
    // 0x21
    pub pending_tick_flags: u8,
    // 0x22
    // Anonymous union/struct in Rust
    pub idle_state: u8,
    // 0x23
    pub number: u32,
    // 0x24
    pub rsp_base: u64,
    // 0x28
    pub prcb_lock: u64,
    // 0x30
    pub priority_state: *mut u8,
    // 0x38
    pub cpu_type: i8,
    // 0x40
    pub cpu_id: i8,
    // 0x41
    pub cpu_step: u16,
    // 0x42
    // Anonymous union/struct in Rust for CpuStepping and CpuModel
    pub mhz: u32,
    // 0x44
    pub hal_reserved: [u64; 8],
    // 0x48
    pub minor_version: u16,
    // 0x88
    pub major_version: u16,
    // 0x8a
    pub build_type: u8,
    // 0x8c
    pub cpu_vendor: u8,
    // 0x8d
    pub legacy_cores_per_physical_processor: u8,
    // 0x8e
    pub legacy_logical_processors_per_core: u8,
    // 0x8f
    pub tsc_frequency: u64,
    // 0x90
    pub tracepoint_log: *mut KPRCB_TRACEPOINT_LOG,
    // 0x98
    pub cores_per_physical_processor: u32,
    // 0xa0
    pub logical_processors_per_core: u32,
    // 0xa4
    pub prcb_pad04: [u64; 3],
    // 0xa8
    pub scheduler_sub_node: *mut KSCHEDULER_SUBNODE,
    // 0xc0
    pub group_set_member: u64,
    // 0xc8
    pub group: u8,
    // 0xd0
    pub group_index: u8,
    // 0xd1
    pub prcb_pad05: [u8; 2],
    // 0xd2
    pub initial_apic_id: u32,
    // 0xd4
    pub scb_offset: u32,
    // 0xd8
    pub apic_mask: u32,
    // 0xdc
    pub acpi_reserved: *mut c_void,
    // 0xe0
    pub c_flush_size: u32,
    // 0xe8
    pub prcb_pad11: [u64; 2],
    // 0xf0
    pub processor_state: KPROCESSOR_STATE,
    // 0x100
    pub extended_supervisor_state: *mut XSAVE_AREA_HEADER,
    // 0x6c0
    pub processor_signature: u32,
    // 0x6c8
    pub processor_flags: u32,
    // 0x6cc
    pub prcb_pad12a: u64,
    // 0x6d0
    pub prcb_pad12: [u64; 3], // 0x6d8
}

#[repr(C)]
pub struct KPRCB_TRACEPOINT_LOG {
    // Assuming KPRCB_TRACEPOINT_LOG_ENTRY is previously defined
    pub entries: [KPRCB_TRACEPOINT_LOG_ENTRY; 256],
    // 0x0
    pub log_index: u32, // 0x2000
}

#[repr(C)]
pub struct KSCHEDULER_SUBNODE {
    pub sub_node_lock: u64,
    // 0x0
    pub idle_non_parked_cpu_set: u64,
    // 0x8
    pub idle_set: [u64; 3],
    // 0x10
    pub non_paired_smt_set: u64,
    // 0x28
    pub deep_idle_set: u64,
    // 0x40
    pub idle_constrained_set: u64,
    // 0x48
    pub non_parked_set: u64,
    // 0x50
    pub park_request_set: u64,
    // 0x58
    pub soft_park_request_set: u64,
    // 0x60
    pub non_isr_targeted_set: u64,
    // 0x68
    pub park_lock: i32,
    // 0x70
    pub process_seed: u8,
    // 0x74
    pub spare5: [u8; 3],
    // 0x75
    pub affinity: [u8; 0x10],
    // 0x80
    pub sibling_mask: u64,
    // 0x90
    pub shared_ready_queue_mask: u64,
    // 0x98
    pub stride_mask: u64,
    // 0xa0
    pub llc_leaders: u64,
    // 0xa8
    pub lowest: u32,
    // 0xb0
    pub highest: u32,
    // 0xb4
    pub flags: u8,
    // 0xb8
    pub workload_classes: u8,
    // 0xb9
    pub hetero_sets: *mut [u64; 3],
    // 0xc0
    pub ppm_configured_qos_sets: [u64; 7],
    // 0xc8
    pub qos_grouping_sets: u64,
    // 0x100
    pub soft_park_ranks: [u8; 64], // 0x140
}

#[repr(C)]
pub struct KDESCRIPTOR {
    pub pad: [u16; 3],
    // 0x0
    pub limit: u16,
    // 0x6
    pub base: *mut c_void, // 0x8
}

#[repr(C)]
pub struct KSPECIAL_REGISTERS {
    pub cr0: u64,
    // 0x0
    pub cr2: u64,
    // 0x8
    pub cr3: u64,
    // 0x10
    pub cr4: u64,
    // 0x18
    pub kernel_dr0: u64,
    // 0x20
    pub kernel_dr1: u64,
    // 0x28
    pub kernel_dr2: u64,
    // 0x30
    pub kernel_dr3: u64,
    // 0x38
    pub kernel_dr6: u64,
    // 0x40
    pub kernel_dr7: u64,
    // 0x48
    pub gdtr: KDESCRIPTOR,
    // 0x50
    pub idtr: KDESCRIPTOR,
    // 0x60
    pub tr: u16,
    // 0x70
    pub ldtr: u16,
    // 0x72
    pub mx_csr: u32,
    // 0x74
    pub debug_control: u64,
    // 0x78
    pub last_branch_to_rip: u64,
    // 0x80
    pub last_branch_from_rip: u64,
    // 0x88
    pub last_exception_to_rip: u64,
    // 0x90
    pub last_exception_from_rip: u64,
    // 0x98
    pub cr8: u64,
    // 0xa0
    pub msr_gs_base: u64,
    // 0xa8
    pub msr_gs_swap: u64,
    // 0xb0
    pub msr_star: u64,
    // 0xb8
    pub msr_l_star: u64,
    // 0xc0
    pub msr_c_star: u64,
    // 0xc8
    pub msr_syscall_mask: u64,
    // 0xd0
    pub xcr0: u64,
    // 0xd8
    pub msr_fs_base: u64,
    // 0xe0
    pub special_padding0: u64, // 0xe8
}

#[repr(C)]
pub struct KPROCESSOR_STATE {
    pub special_registers: KSPECIAL_REGISTERS,
    // 0x0
    pub context_frame: windows_kernel_sys::base::CONTEXT, // 0xf0
}

#[repr(C)]
pub struct KPRCB_TRACEPOINT_LOG_ENTRY {
    pub old_pc: u64,
    // 0x0
    pub old_sp: u64,
    // 0x8
    pub new_pc: u64,
    // 0x10
    pub new_sp: u64, // 0x18
}

#[repr(C)]
struct EVENT_TRACE_PERFORMANCE_INFORMATION {
    EventTraceInformationClass: EVENT_TRACE_INFORMATION_CLASS,
    // Assuming 32-bit unsigned integer for the enum
    LogfileBytesWritten: LARGE_INTEGER, // 64-bit value
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EVENT_TRACE_INFORMATION_CLASS {
    EventTraceKernelVersionInformation = 0x00,
    EventTraceGroupMaskInformation = 0x01,
    EventTracePerformanceInformation = 0x02,
    EventTraceTimeProfileInformation = 0x03,
    EventTraceSessionSecurityInformation = 0x04,
    EventTraceSpinlockInformation = 0x05,
    EventTraceStackTracingInformation = 0x06,
    EventTraceExecutiveResourceInformation = 0x07,
    EventTraceHeapTracingInformation = 0x08,
    EventTraceHeapSummaryTracingInformation = 0x09,
    EventTracePoolTagFilterInformation = 0x0A,
    EventTracePebsTracingInformation = 0x0B,
    EventTraceProfileConfigInformation = 0x0C,
    EventTraceProfileSourceListInformation = 0x0D,
    EventTraceProfileEventListInformation = 0x0E,
    EventTraceProfileCounterListInformation = 0x0F,
    EventTraceStackCachingInformation = 0x10,
    EventTraceObjectTypeFilterInformation = 0x11,
    EventTraceSoftRestartInformation = 0x12,
    EventTraceLastBranchConfigurationInformation = 0x13,
    EventTraceLastBranchEventListInformation = 0x14,
    EventTraceProfileSourceAddInformation = 0x15,
    EventTraceProfileSourceRemoveInformation = 0x16,
    EventTraceProcessorTraceConfigurationInformation = 0x17,
    EventTraceProcessorTraceEventListInformation = 0x18,
    EventTraceCoverageSamplerInformation = 0x19,
    MaxEventTraceInfoClass = 0x1A, // Used as a marker, not a real class
}

#[repr(C)]
struct EVENT_TRACE_SYSTEM_EVENT_INFORMATION {
    EventTraceInformationClass: EVENT_TRACE_INFORMATION_CLASS,
    TraceHandle: TRACEHANDLE,
    HookId: *mut ULONG,
}

#[repr(C)]
struct EVENT_TRACE_PROFILE_COUNTER_INFORMATION {
    EventTraceInformationClass: EVENT_TRACE_INFORMATION_CLASS,
    TraceHandle: TRACEHANDLE,
    ProfileSource: *mut ULONG,
}

#[repr(C)]
pub struct SYSTEM_MODULE_INFORMATION {
    pub ModulesCount: core::ffi::c_ulong,
    pub Modules: [SYSTEM_MODULE; 1],
}

#[repr(C)]
pub struct SYSTEM_MODULE {
    pub Reserved1: HANDLE,
    pub Reserved2: PVOID,
    pub ImageBaseAddress: PVOID,
    pub ImageSize: core::ffi::c_ulong,
    pub Flags: core::ffi::c_ulong,
    pub a: core::ffi::c_ushort,
    pub Id: core::ffi::c_ushort,
    pub NameLength: core::ffi::c_ushort,
    pub NameOffset: core::ffi::c_ushort,
    pub Name: [core::ffi::c_uchar; 256], // Assuming MAXIMUM_FILENAME_LENGTH is MAX_PATH
}

#[repr(C)]
pub struct CKCL_TRACE_PROPERTIES {
    pub Base: EVENT_TRACE_PROPERTIES,
    pub Unknown: [c_ulonglong; 3],
    pub ProviderName: UNICODE_STRING,
}

#[allow(non_snake_case)]
pub fn MyProbeForRead(address: *const c_void, length: usize, alignment: u64) -> bool {
    let max_address = 0x7FFF_FFFF_FFFFu64; // TODO: arch

    unsafe {
        if length != 0
            && ((address as u64) & (alignment - 1)) != 0 //alignment check
            && ((address.add(length) as u64) > max_address //user/kernel memory check
            || (address.add(length) as u64) < (address as u64))
        {
            false
        } else {
            true
        }
    }
}

#[allow(non_snake_case)]
pub unsafe fn RtlOffsetToPointer<T>(base: *const T, offset: usize) -> *const c_char {
    let base_ptr = base as *const c_void as *const c_char;
    base_ptr.add(offset)
}
