#include <windows.h>
#include <stdio.h>

#include "NativeAPI.h"
#include "Syscalls.h"
#include "beacon.h"


BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
	if (status == STATUS_SUCCESS) {
		TOKEN_ELEVATION Elevation = { 0 };
		ULONG ReturnLength;

		status = ZwQueryInformationToken(hToken, TokenElevation, &Elevation, sizeof(Elevation), &ReturnLength);
		if (status == STATUS_SUCCESS) {
			fRet = Elevation.TokenIsElevated;
		}
	}

	if (hToken != NULL) {
		ZwClose(hToken);
	}

	return fRet;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	_NtOpenProcessToken NtOpenProcessToken = (_NtOpenProcessToken)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcessToken");
	if (NtOpenProcessToken == NULL) {
		return FALSE;
	}

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!ADVAPI32$LookupPrivilegeValueW(NULL, lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		ZwClose(hToken);
		return FALSE;
	}

	status = ZwAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS) {
		ZwClose(hToken);
		return FALSE;
	}

	ZwClose(hToken);

	return TRUE;
}

ULONG GetCurrentPid() {
	PROCESS_BASIC_INFORMATION pbi = { 0 };

	NTSTATUS status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
	if (status != STATUS_SUCCESS) {
		return 0;
	}

	return (ULONG)pbi.UniqueProcessId;
}

LPWSTR WINAPI PathFindFileNameW(LPCWSTR lpszPath) {
	LPCWSTR lastSlash = lpszPath;

	while (lpszPath && *lpszPath)
	{
		if ((*lpszPath == '\\' || *lpszPath == '/' || *lpszPath == ':') &&
			lpszPath[1] && lpszPath[1] != '\\' && lpszPath[1] != '/')
			lastSlash = lpszPath + 1;
		lpszPath++;
	}
	return (LPWSTR)lastSlash;
}

BOOL EnumerateProcessModules(HANDLE hProcess, LPCWSTR lpwModuleName, PUNICODE_STRING uProcName, ULONG ulPid) {
	PROCESS_BASIC_INFORMATION BasicInformation;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PPEB_LDR_DATA pLoaderData;
	LDR_DATA_TABLE_ENTRY LoaderModule;
	PLIST_ENTRY ListHead, Current;
	UNICODE_STRING uImagePathName;
	WCHAR wcImagePathName[MAX_PATH * 2];
	WCHAR wcFullDllName[MAX_PATH * 2];
	LPWSTR lpwDllName = NULL;

	NTSTATUS status = ZwQueryInformationProcess(hProcess, ProcessBasicInformation, &BasicInformation, sizeof(BasicInformation), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Get the address of the Process Parameters struct and read ImagePathName data.
	status = ZwReadVirtualMemory(hProcess, &(BasicInformation.PebBaseAddress->ProcessParameters), &ProcessParameters, sizeof(ProcessParameters), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	status = ZwReadVirtualMemory(hProcess, &(ProcessParameters->ImagePathName), &uImagePathName, sizeof(uImagePathName), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	MSVCRT$memset(wcImagePathName, 0, sizeof(wcImagePathName));
	status = ZwReadVirtualMemory(hProcess, uImagePathName.Buffer, &wcImagePathName, uImagePathName.MaximumLength, NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Get the address of the PE Loader data.
	status = ZwReadVirtualMemory(hProcess, &(BasicInformation.PebBaseAddress->Ldr), &pLoaderData, sizeof(pLoaderData), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	// Head of the module list: the last element in the list will point to this.
	ListHead = &pLoaderData->InLoadOrderModuleList;

	// Get the address of the first element in the list.
	status = ZwReadVirtualMemory(hProcess, &(pLoaderData->InLoadOrderModuleList.Flink), &Current, sizeof(Current), NULL);
	if (status != STATUS_SUCCESS) {
		return FALSE;
	}

	while (Current != ListHead) 
	{
		// Read the current module.
		status = ZwReadVirtualMemory(hProcess, CONTAINING_RECORD(Current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks), &LoaderModule, sizeof(LoaderModule), NULL);
		if (status != STATUS_SUCCESS) {
			return FALSE;
		}

		MSVCRT$memset(wcFullDllName, 0, sizeof(wcFullDllName));
		status = ZwReadVirtualMemory(hProcess, (LPVOID)LoaderModule.FullDllName.Buffer, &wcFullDllName, LoaderModule.FullDllName.MaximumLength, NULL);
		if (status != STATUS_SUCCESS) {
			return FALSE;
		}

		lpwDllName = PathFindFileNameW(wcFullDllName);
		if (MSVCRT$_wcsicmp(lpwDllName, lpwModuleName) == 0) {
			BeaconPrintf(CALLBACK_OUTPUT,
				"    ProcessName: %wZ\n"
				"    ProcessID:   %lu\n"
				"    ImagePath:   %ls\n"
				"    ModuleName:  %ls\n", uProcName, ulPid, wcImagePathName, wcFullDllName);
		}

		// Address of the next module in the list.
		Current = LoaderModule.InLoadOrderLinks.Flink;
	}

	return TRUE;
}


VOID go(IN PCHAR Args, IN ULONG Length) {
	NTSTATUS status;
	PSYSTEM_PROCESSES pProcInfo = NULL;
	ULONG ulCurPid = 0;
	UNICODE_STRING uLsass;
	UNICODE_STRING uWinlogon;
	LPVOID pProcInfoBuffer = NULL;
	SIZE_T procInfoSize = 0x10000;
	ULONG uReturnLength = 0;
	LPCWSTR lpwModuleName = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
	lpwModuleName = (LPWSTR)BeaconDataExtract(&parser, NULL);

	if (lpwModuleName == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Invalid argument...\n");
		return;
	}

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		return;
	}

	if (IsElevated()) {
		SetDebugPrivilege();
	}

	do {
		pProcInfoBuffer = NULL;
		status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, 0, &procInfoSize, MEM_COMMIT, PAGE_READWRITE);
		if (status != STATUS_SUCCESS) {
			return;
		}

		status = ZwQuerySystemInformation(SystemProcessInformation, pProcInfoBuffer, (ULONG)procInfoSize, &uReturnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
			procInfoSize += uReturnLength;
		}

	} while (status != STATUS_SUCCESS);

	ulCurPid = GetCurrentPid();
	RtlInitUnicodeString(&uLsass, L"lsass.exe");
	RtlInitUnicodeString(&uWinlogon, L"winlogon.exe");

	pProcInfo = (PSYSTEM_PROCESSES)pProcInfoBuffer;

	do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if ((ULONG)(ULONG_PTR)pProcInfo->ProcessId == 4) {
			continue;
		}

		if ((ULONG)(ULONG_PTR)pProcInfo->ProcessId == ulCurPid) {
			continue;
		}
		
		// Don't trigger sysmon by touching lsass or winlogon
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uLsass, TRUE)) {
			continue;
		}
		
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uWinlogon, TRUE)) {
			continue;
		}

		HANDLE hProcess = NULL;
		OBJECT_ATTRIBUTES ObjectAttributes;
		InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
		CLIENT_ID uPid = { 0 };

		uPid.UniqueProcess = pProcInfo->ProcessId;
		uPid.UniqueThread = (HANDLE)0;

		NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
		if (hProcess != NULL) {
			EnumerateProcessModules(hProcess, lpwModuleName, &pProcInfo->ProcessName, (ULONG)(ULONG_PTR)pProcInfo->ProcessId);
			ZwClose(hProcess);
		}
		
		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo && pProcInfo->NextEntryDelta);

	if (pProcInfoBuffer) {
		status = ZwFreeVirtualMemory(NtCurrentProcess(), &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
	}

	return;
}
