#include <Windows.h>
#include <stdio.h>


typedef struct _UNICODE_STRING {
    USHORT Length;        // Length of the string in bytes
    USHORT MaximumLength; // Maximum length of the buffer allocated for the string (in bytes)
    PWSTR  Buffer;       // Pointer to the buffer containing the Unicode characters
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void* PPS_POST_PROCESS_INIT_ROUTINE;
typedef struct {
    ULONG PriorityClass;
    ULONG PrioritySubClass;
} KPRIORITY, * PKSPRIORITY;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;



typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
    ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ProcessEffectivePagePriority, // q: ULONG
    MaxProcessInfoClass
} PROCESSINFOCLASS;
typedef NTSTATUS(NTAPI* NtQueryProcessInformationPtr)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG
    );




//Hells Gate Adds


typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... additional fields omitted for brevity
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock; // Pointer to the PEB
    // ... additional fields omitted for brevity
} TEB, * PTEB;



///////stuff that was from main.///////


// this is what SystemFunction032 function take as a parameter
typedef struct
{
    DWORD   Length;
    DWORD   MaximumLength;
    PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );


typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );
typedef NTSTATUS(NTAPI* NtWriteVirtualMemoryPtr)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
    );
typedef NTSTATUS(NTAPI* NtReadVirtualMemoryPtr)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    OUT PVOID Buffer,
    IN ULONG NumberOfBytesToRead,
    OUT PULONG NumberOfBytesRead OPTIONAL
    );

typedef NTSTATUS(NTAPI* NtVirtualProtectMemoryPtr)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PULONG NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
    );

typedef NTSTATUS(NTAPI* NtResumeThreadPtr)(
    IN HANDLE ThreadHandle,
    OUT PULONG SuspendCount OPTIONAL
    );

//Hells Gate Additions
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD dwHash;
    WORD    wSystemCall;
    WORD    wRCXVal;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
    VX_TABLE_ENTRY Allocate;
    VX_TABLE_ENTRY Protect;
    VX_TABLE_ENTRY Read;
    VX_TABLE_ENTRY Write;
    VX_TABLE_ENTRY ResumeThread;
    VX_TABLE_ENTRY QueryInfoProcess;
    VX_TABLE_ENTRY Create;
    VX_TABLE_ENTRY MapViewOfSection;
} VX_TABLE, * PVX_TABLE;
