#include <windows.h>
#include <winevt.h>
#pragma comment(lib,"wevtapi.lib")

BOOL DeleteRecord(LPWSTR ReadPath, LPWSTR lpEventRecordId)
{
	LPWSTR lpPath = new WCHAR[MAX_PATH];
	LPWSTR lpQuery = new WCHAR[MAX_PATH];
	LPWSTR lpTargetLogFile = new WCHAR[MAX_PATH];

	ZeroMemory(lpPath, MAX_PATH);
	ZeroMemory(lpQuery, MAX_PATH);
	ZeroMemory(lpTargetLogFile, MAX_PATH);

	GetSystemDirectory(lpPath, MAX_PATH);
	lstrcat(lpPath, L"\\winevt\\logs\\");
	lstrcat(lpPath, ReadPath);
	printf("[+]ReadPath:%ws\n", lpPath);
	printf("[+]EventRecordID:%ws\n", lpEventRecordId);

	lstrcat(lpQuery, L"Event/System[EventRecordID!=");
	lstrcat(lpQuery, lpEventRecordId);
	lstrcat(lpQuery, L"]");
	lstrcat(lpTargetLogFile, L".\\temp.evtx");

	if (!EvtExportLog(NULL, lpPath, lpQuery, lpTargetLogFile, EvtExportLogFilePath)) {
		printf("[!]EvtExportLog error,%d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Use EvtExportLog to delete Eventlog Record.The new file will be saved at the same path.\n\n");
		printf("Usage:\n");
		printf("%s <eventlog file path> <EventlogRecordID>\n", argv[0]);
		printf("eg:\n");
		printf("     %s system.evtx 1910\n", argv[0]);
		return 0;
	}

	wchar_t ReadPath[100];
	swprintf(ReadPath, 100, L"%hs", argv[1]);
	_wcslwr_s(ReadPath, wcslen(ReadPath) + 1);

	wchar_t lpEventRecordId[100];
	swprintf(lpEventRecordId, 100, L"%hs", argv[2]);
	_wcslwr_s(lpEventRecordId, wcslen(lpEventRecordId) + 1);

	if (DeleteRecord(ReadPath, lpEventRecordId))
		printf("[+]Delete success\n");
	else
		printf("[!]Delete error\n");

	return 0;
}
