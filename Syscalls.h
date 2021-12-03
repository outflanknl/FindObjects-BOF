#pragma once

#include <Windows.h>


__asm__("ZwQuerySystemInformation:                        \n\
    mov rax, gs:[0x60]                                    \n\
ZwQuerySystemInformation_Check_X_X_XXXX:                  \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwQuerySystemInformation_Check_6_X_XXXX           \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwQuerySystemInformation_SystemCall_10_0_XXXX     \n\
    jmp ZwQuerySystemInformation_SystemCall_Unknown       \n\
ZwQuerySystemInformation_Check_6_X_XXXX:                  \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwQuerySystemInformation_Check_6_1_XXXX           \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwQuerySystemInformation_SystemCall_6_2_XXXX      \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwQuerySystemInformation_SystemCall_6_3_XXXX      \n\
    jmp ZwQuerySystemInformation_SystemCall_Unknown       \n\
ZwQuerySystemInformation_Check_6_1_XXXX:                  \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwQuerySystemInformation_SystemCall_6_1_7601      \n\
    jmp ZwQuerySystemInformation_SystemCall_Unknown       \n\
ZwQuerySystemInformation_SystemCall_6_1_7601:             \n\
    mov eax, 0x33                                         \n\
    jmp ZwQuerySystemInformation_Epilogue                 \n\
ZwQuerySystemInformation_SystemCall_6_2_XXXX:             \n\
    mov eax, 0x34                                         \n\
    jmp ZwQuerySystemInformation_Epilogue                 \n\
ZwQuerySystemInformation_SystemCall_6_3_XXXX:             \n\
    mov eax, 0x35                                         \n\
    jmp ZwQuerySystemInformation_Epilogue                 \n\
ZwQuerySystemInformation_SystemCall_10_0_XXXX:            \n\
    mov eax, 0x36                                         \n\
    jmp ZwQuerySystemInformation_Epilogue                 \n\
ZwQuerySystemInformation_SystemCall_Unknown:              \n\
    ret                                                   \n\
ZwQuerySystemInformation_Epilogue:                        \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

__asm__("ZwQueryInformationProcess:                       \n\
    mov rax, gs:[0x60]                                    \n\
ZwQueryInformationProcess_Check_X_X_XXXX:                 \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwQueryInformationProcess_Check_6_X_XXXX          \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwQueryInformationProcess_SystemCall_10_0_XXXX    \n\
    jmp ZwQueryInformationProcess_SystemCall_Unknown      \n\
ZwQueryInformationProcess_Check_6_X_XXXX:                 \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwQueryInformationProcess_Check_6_1_XXXX          \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwQueryInformationProcess_SystemCall_6_2_XXXX     \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwQueryInformationProcess_SystemCall_6_3_XXXX     \n\
    jmp ZwQueryInformationProcess_SystemCall_Unknown      \n\
ZwQueryInformationProcess_Check_6_1_XXXX:                 \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwQueryInformationProcess_SystemCall_6_1_7601     \n\
    jmp ZwQueryInformationProcess_SystemCall_Unknown      \n\
ZwQueryInformationProcess_SystemCall_6_1_7601:            \n\
    mov eax, 0x16                                         \n\
    jmp ZwQueryInformationProcess_Epilogue                \n\
ZwQueryInformationProcess_SystemCall_6_2_XXXX:            \n\
    mov eax, 0x17                                         \n\
    jmp ZwQueryInformationProcess_Epilogue                \n\
ZwQueryInformationProcess_SystemCall_6_3_XXXX:            \n\
    mov eax, 0x18                                         \n\
    jmp ZwQueryInformationProcess_Epilogue                \n\
ZwQueryInformationProcess_SystemCall_10_0_XXXX:           \n\
    mov eax, 0x19                                         \n\
    jmp ZwQueryInformationProcess_Epilogue                \n\
ZwQueryInformationProcess_SystemCall_Unknown:             \n\
    ret                                                   \n\
ZwQueryInformationProcess_Epilogue:                       \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwQueryInformationProcess(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

__asm__("ZwOpenProcess:                                   \n\
    mov rax, gs:[0x60]                                    \n\
ZwOpenProcess_Check_X_X_XXXX:                             \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwOpenProcess_Check_6_X_XXXX                      \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwOpenProcess_SystemCall_10_0_XXXX                \n\
    jmp ZwOpenProcess_SystemCall_Unknown                  \n\
ZwOpenProcess_Check_6_X_XXXX:                             \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwOpenProcess_Check_6_1_XXXX                      \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwOpenProcess_SystemCall_6_2_XXXX                 \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwOpenProcess_SystemCall_6_3_XXXX                 \n\
    jmp ZwOpenProcess_SystemCall_Unknown                  \n\
ZwOpenProcess_Check_6_1_XXXX:                             \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwOpenProcess_SystemCall_6_1_7601                 \n\
    jmp ZwOpenProcess_SystemCall_Unknown                  \n\
ZwOpenProcess_SystemCall_6_1_7601:                        \n\
    mov eax, 0x23                                         \n\
    jmp ZwOpenProcess_Epilogue                            \n\
ZwOpenProcess_SystemCall_6_2_XXXX:                        \n\
    mov eax, 0x24                                         \n\
    jmp ZwOpenProcess_Epilogue                            \n\
ZwOpenProcess_SystemCall_6_3_XXXX:                        \n\
    mov eax, 0x25                                         \n\
    jmp ZwOpenProcess_Epilogue                            \n\
ZwOpenProcess_SystemCall_10_0_XXXX:                       \n\
    mov eax, 0x26                                         \n\
    jmp ZwOpenProcess_Epilogue                            \n\
ZwOpenProcess_SystemCall_Unknown:                         \n\
    ret                                                   \n\
ZwOpenProcess_Epilogue:                                   \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwOpenProcess(
    PHANDLE ProcessHandle, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_ATTRIBUTES ObjectAttributes, 
    PCLIENT_ID ClientId
    );

__asm__("ZwOpenProcessToken:                              \n\
    mov rax, gs:[0x60]                                    \n\
ZwOpenProcessToken_Check_X_X_XXXX:                        \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwOpenProcessToken_Check_6_X_XXXX                 \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwOpenProcessToken_Check_10_0_XXXX                \n\
    jmp ZwOpenProcessToken_SystemCall_Unknown             \n\
ZwOpenProcessToken_Check_6_X_XXXX:                        \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwOpenProcessToken_Check_6_1_XXXX                 \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwOpenProcessToken_SystemCall_6_2_XXXX            \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwOpenProcessToken_SystemCall_6_3_XXXX            \n\
    jmp ZwOpenProcessToken_SystemCall_Unknown             \n\
ZwOpenProcessToken_Check_6_1_XXXX:                        \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwOpenProcessToken_SystemCall_6_1_7601            \n\
    jmp ZwOpenProcessToken_SystemCall_Unknown             \n\
ZwOpenProcessToken_Check_10_0_XXXX:                       \n\
    cmp dword ptr [rax+0x120], 10240                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_10240          \n\
    cmp dword ptr [rax+0x120], 10586                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_10586          \n\
    cmp dword ptr [rax+0x120], 14393                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_14393          \n\
    cmp dword ptr [rax+0x120], 15063                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_15063          \n\
    cmp dword ptr [rax+0x120], 16299                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_16299          \n\
    cmp dword ptr [rax+0x120], 17134                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_17134          \n\
    cmp dword ptr [rax+0x120], 17763                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_17763          \n\
    cmp dword ptr [rax+0x120], 18362                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_18362          \n\
    cmp dword ptr [rax+0x120], 18363                      \n\
    je  ZwOpenProcessToken_SystemCall_10_0_18363          \n\
    cmp dword ptr [rax+0x120], 19041                      \n\
    je ZwOpenProcessToken_SystemCall_10_0_19041           \n\
    cmp dword ptr [rax+0x120], 19042                      \n\
    je ZwOpenProcessToken_SystemCall_10_0_19042           \n\
    cmp dword ptr [rax+0x120], 19043                      \n\
    je ZwOpenProcessToken_SystemCall_10_0_19043           \n\
    cmp dword ptr [rax+0x120], 19044                      \n\
    je ZwOpenProcessToken_SystemCall_10_0_19044           \n\
    cmp dword ptr [rax+0x120], 22000                      \n\
    je ZwOpenProcessToken_SystemCall_10_0_22000           \n\
    jmp ZwOpenProcessToken_SystemCall_Unknown             \n\
ZwOpenProcessToken_SystemCall_6_1_7601:                   \n\
    mov eax, 0xF9                                         \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_6_2_XXXX:                   \n\
    mov eax, 0x10B                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_6_3_XXXX:                   \n\
    mov eax, 0x10E                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_10240:                 \n\
    mov eax, 0x114                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_10586:                 \n\
    mov eax, 0x117                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_14393:                 \n\
    mov eax, 0x119                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_15063:                 \n\
    mov eax, 0x11d                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_16299:                 \n\
    mov eax, 0x11f                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_17134:                 \n\
    mov eax, 0x121                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_17763:                 \n\
    mov eax, 0x122                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_18362:                 \n\
    mov eax, 0x123                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_18363:                 \n\
    mov eax, 0x123                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_19041:                 \n\
    mov eax, 0x128                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_19042:                 \n\
    mov eax, 0x128                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_19043:                 \n\
    mov eax, 0x128                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_19044:                 \n\
    mov eax, 0x128                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_10_0_22000:                 \n\
    mov eax, 0x12E                                        \n\
    jmp ZwOpenProcessToken_Epilogue                       \n\
ZwOpenProcessToken_SystemCall_Unknown:                    \n\
    ret                                                   \n\
ZwOpenProcessToken_Epilogue:                              \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle
    );

__asm__("ZwAdjustPrivilegesToken:                         \n\
    mov rax, gs:[0x60]                                    \n\
ZwAdjustPrivilegesToken_Check_X_X_XXXX:                   \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwAdjustPrivilegesToken_Check_6_X_XXXX            \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwAdjustPrivilegesToken_SystemCall_10_0_XXXX      \n\
    jmp ZwAdjustPrivilegesToken_SystemCall_Unknown        \n\
ZwAdjustPrivilegesToken_Check_6_X_XXXX:                   \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwAdjustPrivilegesToken_Check_6_1_XXXX            \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwAdjustPrivilegesToken_SystemCall_6_2_XXXX       \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwAdjustPrivilegesToken_SystemCall_6_3_XXXX       \n\
    jmp ZwAdjustPrivilegesToken_SystemCall_Unknown        \n\
ZwAdjustPrivilegesToken_Check_6_1_XXXX:                   \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwAdjustPrivilegesToken_SystemCall_6_1_7601       \n\
    jmp ZwAdjustPrivilegesToken_SystemCall_Unknown        \n\
ZwAdjustPrivilegesToken_SystemCall_6_1_7601:              \n\
    mov eax, 0x3E                                         \n\
    jmp ZwAdjustPrivilegesToken_Epilogue                  \n\
ZwAdjustPrivilegesToken_SystemCall_6_2_XXXX:              \n\
    mov eax, 0x3F                                         \n\
    jmp ZwAdjustPrivilegesToken_Epilogue                  \n\
ZwAdjustPrivilegesToken_SystemCall_6_3_XXXX:              \n\
    mov eax, 0x40                                         \n\
    jmp ZwAdjustPrivilegesToken_Epilogue                  \n\
ZwAdjustPrivilegesToken_SystemCall_10_0_XXXX:             \n\
    mov eax, 0x41                                         \n\
    jmp ZwAdjustPrivilegesToken_Epilogue                  \n\
ZwAdjustPrivilegesToken_SystemCall_Unknown:               \n\
    ret                                                   \n\
ZwAdjustPrivilegesToken_Epilogue:                         \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwAdjustPrivilegesToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES TokenPrivileges,
    IN ULONG PreviousPrivilegesLength,
    OUT PTOKEN_PRIVILEGES PreviousPrivileges OPTIONAL,
    OUT PULONG RequiredLength OPTIONAL
    );

__asm__("ZwQueryInformationToken:                         \n\
    mov rax, gs:[0x60]                                    \n\
ZwQueryInformationToken_Check_X_X_XXXX:                   \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwQueryInformationToken_Check_6_X_XXXX            \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwQueryInformationToken_SystemCall_10_0_XXXX      \n\
    jmp ZwQueryInformationToken_SystemCall_Unknown        \n\
ZwQueryInformationToken_Check_6_X_XXXX:                   \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwQueryInformationToken_Check_6_1_XXXX            \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwQueryInformationToken_SystemCall_6_2_XXXX       \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwQueryInformationToken_SystemCall_6_3_XXXX       \n\
    jmp ZwQueryInformationToken_SystemCall_Unknown        \n\
ZwQueryInformationToken_Check_6_1_XXXX:                   \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwQueryInformationToken_SystemCall_6_1_7601       \n\
    jmp ZwQueryInformationToken_SystemCall_Unknown        \n\
ZwQueryInformationToken_SystemCall_6_1_7601:              \n\
    mov eax, 0x1e                                         \n\
    jmp ZwQueryInformationToken_Epilogue                  \n\
ZwQueryInformationToken_SystemCall_6_2_XXXX:              \n\
    mov eax, 0x1f                                         \n\
    jmp ZwQueryInformationToken_Epilogue                  \n\
ZwQueryInformationToken_SystemCall_6_3_XXXX:              \n\
    mov eax, 0x20                                         \n\
    jmp ZwQueryInformationToken_Epilogue                  \n\
ZwQueryInformationToken_SystemCall_10_0_XXXX:             \n\
    mov eax, 0x21                                         \n\
    jmp ZwQueryInformationToken_Epilogue                  \n\
ZwQueryInformationToken_SystemCall_Unknown:               \n\
    ret                                                   \n\
ZwQueryInformationToken_Epilogue:                         \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwQueryInformationToken(
	HANDLE TokenHandle,
	TOKEN_INFORMATION_CLASS TokenInformationClass,
	PVOID TokenInformation,
	ULONG TokenInformationLength,
	PULONG ReturnLength
	);

__asm__("ZwAllocateVirtualMemory:                         \n\
    mov rax, gs:[0x60]                                    \n\
ZwAllocateVirtualMemory_Check_X_X_XXXX:                   \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwAllocateVirtualMemory_Check_6_X_XXXX            \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwAllocateVirtualMemory_SystemCall_10_0_XXXX      \n\
    jmp ZwAllocateVirtualMemory_SystemCall_Unknown        \n\
ZwAllocateVirtualMemory_Check_6_X_XXXX:                   \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwAllocateVirtualMemory_Check_6_1_XXXX            \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwAllocateVirtualMemory_SystemCall_6_2_XXXX       \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwAllocateVirtualMemory_SystemCall_6_3_XXXX       \n\
    jmp ZwAllocateVirtualMemory_SystemCall_Unknown        \n\
ZwAllocateVirtualMemory_Check_6_1_XXXX:                   \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwAllocateVirtualMemory_SystemCall_6_1_7601       \n\
    jmp ZwAllocateVirtualMemory_SystemCall_Unknown        \n\
ZwAllocateVirtualMemory_SystemCall_6_1_7601:              \n\
    mov eax, 0x15                                         \n\
    jmp ZwAllocateVirtualMemory_Epilogue                  \n\
ZwAllocateVirtualMemory_SystemCall_6_2_XXXX:              \n\
    mov eax, 0x16                                         \n\
    jmp ZwAllocateVirtualMemory_Epilogue                  \n\
ZwAllocateVirtualMemory_SystemCall_6_3_XXXX:              \n\
    mov eax, 0x17                                         \n\
    jmp ZwAllocateVirtualMemory_Epilogue                  \n\
ZwAllocateVirtualMemory_SystemCall_10_0_XXXX:             \n\
    mov eax, 0x18                                         \n\
    jmp ZwAllocateVirtualMemory_Epilogue                  \n\
ZwAllocateVirtualMemory_SystemCall_Unknown:               \n\
    ret                                                   \n\
ZwAllocateVirtualMemory_Epilogue:                         \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID *BaseAddress, 
    ULONG_PTR ZeroBits, 
    PSIZE_T RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
    );

__asm__("ZwFreeVirtualMemory:                             \n\
    mov rax, gs:[0x60]                                    \n\
ZwFreeVirtualMemory_Check_X_X_XXXX:                       \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwFreeVirtualMemory_Check_6_X_XXXX                \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwFreeVirtualMemory_SystemCall_10_0_XXXX          \n\
    jmp ZwFreeVirtualMemory_SystemCall_Unknown            \n\
ZwFreeVirtualMemory_Check_6_X_XXXX:                       \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwFreeVirtualMemory_Check_6_1_XXXX                \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwFreeVirtualMemory_SystemCall_6_2_XXXX           \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwFreeVirtualMemory_SystemCall_6_3_XXXX           \n\
    jmp ZwFreeVirtualMemory_SystemCall_Unknown            \n\
ZwFreeVirtualMemory_Check_6_1_XXXX:                       \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwFreeVirtualMemory_SystemCall_6_1_7601           \n\
    jmp ZwFreeVirtualMemory_SystemCall_Unknown            \n\
ZwFreeVirtualMemory_SystemCall_6_1_7601:                  \n\
    mov eax, 0x1B                                         \n\
    jmp ZwFreeVirtualMemory_Epilogue                      \n\
ZwFreeVirtualMemory_SystemCall_6_2_XXXX:                  \n\
    mov eax, 0x1C                                         \n\
    jmp ZwFreeVirtualMemory_Epilogue                      \n\
ZwFreeVirtualMemory_SystemCall_6_3_XXXX:                  \n\
    mov eax, 0x1D                                         \n\
    jmp ZwFreeVirtualMemory_Epilogue                      \n\
ZwFreeVirtualMemory_SystemCall_10_0_XXXX:                 \n\
    mov eax, 0x1E                                         \n\
    jmp ZwFreeVirtualMemory_Epilogue                      \n\
ZwFreeVirtualMemory_SystemCall_Unknown:                   \n\
    ret                                                   \n\
ZwFreeVirtualMemory_Epilogue:                             \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwFreeVirtualMemory(
    HANDLE ProcessHandle, 
    PVOID *BaseAddress, 
    IN OUT PSIZE_T RegionSize, 
    ULONG FreeType
    );

__asm__("ZwReadVirtualMemory:                             \n\
    mov rax, gs:[0x60]                                    \n\
ZwReadVirtualMemory_Check_X_X_XXXX:                       \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwReadVirtualMemory_Check_6_X_XXXX                \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwReadVirtualMemory_SystemCall_10_0_XXXX          \n\
    jmp ZwReadVirtualMemory_SystemCall_Unknown            \n\
ZwReadVirtualMemory_Check_6_X_XXXX:                       \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwReadVirtualMemory_Check_6_1_XXXX                \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwReadVirtualMemory_SystemCall_6_2_XXXX           \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwReadVirtualMemory_SystemCall_6_3_XXXX           \n\
    jmp ZwReadVirtualMemory_SystemCall_Unknown            \n\
ZwReadVirtualMemory_Check_6_1_XXXX:                       \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwReadVirtualMemory_SystemCall_6_1_7601           \n\
    jmp ZwReadVirtualMemory_SystemCall_Unknown            \n\
ZwReadVirtualMemory_SystemCall_6_1_7601:                  \n\
    mov eax, 0x3C                                         \n\
    jmp ZwReadVirtualMemory_Epilogue                      \n\
ZwReadVirtualMemory_SystemCall_6_2_XXXX:                  \n\
    mov eax, 0x3D                                         \n\
    jmp ZwReadVirtualMemory_Epilogue                      \n\
ZwReadVirtualMemory_SystemCall_6_3_XXXX:                  \n\
    mov eax, 0x3E                                         \n\
    jmp ZwReadVirtualMemory_Epilogue                      \n\
ZwReadVirtualMemory_SystemCall_10_0_XXXX:                 \n\
    mov eax, 0x3F                                         \n\
    jmp ZwReadVirtualMemory_Epilogue                      \n\
ZwReadVirtualMemory_SystemCall_Unknown:                   \n\
    ret                                                   \n\
ZwReadVirtualMemory_Epilogue:                             \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwReadVirtualMemory(
    HANDLE hProcess, 
    PVOID lpBaseAddress, 
    PVOID lpBuffer, 
    SIZE_T NumberOfBytesToRead, 
    PSIZE_T NumberOfBytesRead
    );

__asm__("ZwWriteVirtualMemory:                            \n\
    mov rax, gs:[0x60]                                    \n\
ZwWriteVirtualMemory_Check_X_X_XXXX:                      \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwWriteVirtualMemory_Check_6_X_XXXX               \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwWriteVirtualMemory_SystemCall_10_0_XXXX         \n\
    jmp ZwWriteVirtualMemory_SystemCall_Unknown           \n\
ZwWriteVirtualMemory_Check_6_X_XXXX:                      \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwWriteVirtualMemory_Check_6_1_XXXX               \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwWriteVirtualMemory_SystemCall_6_2_XXXX          \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwWriteVirtualMemory_SystemCall_6_3_XXXX          \n\
    jmp ZwWriteVirtualMemory_SystemCall_Unknown           \n\
ZwWriteVirtualMemory_Check_6_1_XXXX:                      \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwWriteVirtualMemory_SystemCall_6_1_7601          \n\
    jmp ZwWriteVirtualMemory_SystemCall_Unknown           \n\
ZwWriteVirtualMemory_SystemCall_6_1_7601:                 \n\
    mov eax, 0x37                                         \n\
    jmp ZwWriteVirtualMemory_Epilogue                     \n\
ZwWriteVirtualMemory_SystemCall_6_2_XXXX:                 \n\
    mov eax, 0x38                                         \n\
    jmp ZwWriteVirtualMemory_Epilogue                     \n\
ZwWriteVirtualMemory_SystemCall_6_3_XXXX:                 \n\
    mov eax, 0x39                                         \n\
    jmp ZwWriteVirtualMemory_Epilogue                     \n\
ZwWriteVirtualMemory_SystemCall_10_0_XXXX:                \n\
    mov eax, 0x3A                                         \n\
    jmp ZwWriteVirtualMemory_Epilogue                     \n\
ZwWriteVirtualMemory_SystemCall_Unknown:                  \n\
    ret                                                   \n\
ZwWriteVirtualMemory_Epilogue:                            \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwWriteVirtualMemory(
    HANDLE hProcess, 
    PVOID lpBaseAddress, 
    PVOID lpBuffer, 
    SIZE_T NumberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWrite
    );

__asm__("ZwDuplicateObject:                               \n\
    mov rax, gs:[0x60]                                    \n\
ZwDuplicateObject_Check_X_X_XXXX:                         \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwDuplicateObject_Check_6_X_XXXX                  \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwDuplicateObject_SystemCall_10_0_XXXX            \n\
    jmp ZwDuplicateObject_SystemCall_Unknown              \n\
ZwDuplicateObject_Check_6_X_XXXX:                         \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwDuplicateObject_Check_6_1_XXXX                  \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwDuplicateObject_SystemCall_6_2_XXXX             \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwDuplicateObject_SystemCall_6_3_XXXX             \n\
    jmp ZwDuplicateObject_SystemCall_Unknown              \n\
ZwDuplicateObject_Check_6_1_XXXX:                         \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwDuplicateObject_SystemCall_6_1_7601             \n\
    jmp ZwDuplicateObject_SystemCall_Unknown              \n\
ZwDuplicateObject_SystemCall_6_1_7601:                    \n\
    mov eax, 0x39                                         \n\
    jmp ZwDuplicateObject_Epilogue                        \n\
ZwDuplicateObject_SystemCall_6_2_XXXX:                    \n\
    mov eax, 0x3a                                         \n\
    jmp ZwDuplicateObject_Epilogue                        \n\
ZwDuplicateObject_SystemCall_6_3_XXXX:                    \n\
    mov eax, 0x3b                                         \n\
    jmp ZwDuplicateObject_Epilogue                        \n\
ZwDuplicateObject_SystemCall_10_0_XXXX:                   \n\
    mov eax, 0x3c                                         \n\
    jmp ZwDuplicateObject_Epilogue                        \n\
ZwDuplicateObject_SystemCall_Unknown:                     \n\
    ret                                                   \n\
ZwDuplicateObject_Epilogue:                               \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

__asm__("ZwQueryObject:                                   \n\
    mov rax, gs:[0x60]                                    \n\
ZwQueryObject_Check_X_X_XXXX:                             \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwQueryObject_Check_6_X_XXXX                      \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwQueryObject_SystemCall_10_0_XXXX                \n\
    jmp ZwQueryObject_SystemCall_Unknown                  \n\
ZwQueryObject_Check_6_X_XXXX:                             \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwQueryObject_Check_6_1_XXXX                      \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwQueryObject_SystemCall_6_2_XXXX                 \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwQueryObject_SystemCall_6_3_XXXX                 \n\
    jmp ZwQueryObject_SystemCall_Unknown                  \n\
ZwQueryObject_Check_6_1_XXXX:                             \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwQueryObject_SystemCall_6_1_7601                 \n\
    jmp ZwQueryObject_SystemCall_Unknown                  \n\
ZwQueryObject_SystemCall_6_1_7601:                        \n\
    mov eax, 0x0d                                         \n\
    jmp ZwQueryObject_Epilogue                            \n\
ZwQueryObject_SystemCall_6_2_XXXX:                        \n\
    mov eax, 0x0e                                         \n\
    jmp ZwQueryObject_Epilogue                            \n\
ZwQueryObject_SystemCall_6_3_XXXX:                        \n\
    mov eax, 0x0f                                         \n\
    jmp ZwQueryObject_Epilogue                            \n\
ZwQueryObject_SystemCall_10_0_XXXX:                       \n\
    mov eax, 0x10                                         \n\
    jmp ZwQueryObject_Epilogue                            \n\
ZwQueryObject_SystemCall_Unknown:                         \n\
    ret                                                   \n\
ZwQueryObject_Epilogue:                                   \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwQueryObject(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

__asm__("ZwClose:                                         \n\
    mov rax, gs:[0x60]                                    \n\
ZwClose_Check_X_X_XXXX:                                   \n\
    cmp dword ptr [rax+0x118], 6                          \n\
    je  ZwClose_Check_6_X_XXXX                            \n\
    cmp dword ptr [rax+0x118], 10                         \n\
    je  ZwClose_SystemCall_10_0_XXXX                      \n\
    jmp ZwClose_SystemCall_Unknown                        \n\
ZwClose_Check_6_X_XXXX:                                   \n\
    cmp dword ptr [rax+0x11c], 1                          \n\
    je  ZwClose_Check_6_1_XXXX                            \n\
    cmp dword ptr [rax+0x11c], 2                          \n\
    je  ZwClose_SystemCall_6_2_XXXX                       \n\
    cmp dword ptr [rax+0x11c], 3                          \n\
    je  ZwClose_SystemCall_6_3_XXXX                       \n\
    jmp ZwClose_SystemCall_Unknown                        \n\
ZwClose_Check_6_1_XXXX:                                   \n\
    cmp dword ptr [rax+0x120], 7601                       \n\
    je  ZwClose_SystemCall_6_1_7601                       \n\
    jmp ZwClose_SystemCall_Unknown                        \n\
ZwClose_SystemCall_6_1_7601:                              \n\
    mov eax, 0x0C                                         \n\
    jmp ZwClose_Epilogue                                  \n\
ZwClose_SystemCall_6_2_XXXX:                              \n\
    mov eax, 0x0D                                         \n\
    jmp ZwClose_Epilogue                                  \n\
ZwClose_SystemCall_6_3_XXXX:                              \n\
    mov eax, 0x0E                                         \n\
    jmp ZwClose_Epilogue                                  \n\
ZwClose_SystemCall_10_0_XXXX:                             \n\
    mov eax, 0x0F                                         \n\
    jmp ZwClose_Epilogue                                  \n\
ZwClose_SystemCall_Unknown:                               \n\
    ret                                                   \n\
ZwClose_Epilogue:                                         \n\
    mov r10, rcx                                          \n\
    syscall                                               \n\
    ret                                                   \n\
    ");

EXTERN_C NTSTATUS ZwClose(
    IN HANDLE KeyHandle
    );
