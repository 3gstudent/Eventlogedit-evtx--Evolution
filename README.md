# Eventlogedit-evtx--Evolution
Remove individual lines from Windows XML Event Log (EVTX) files

Support: Win7 and later

Compare with DanderSpritz,my way don't need dll injection and support more version(Server2012 and later).(It can be used to delete the setup.evtx,others may be affected by competitive conditions.)

Need more test and suggestions.

The data structure and some code details are inspired by https://bbs.pediy.com/thread-219313.htm

My posts about the details:

1. [Windows XML Event Log (EVTX)单条日志清除（一）——删除思路与实例](https://3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%80-%E5%88%A0%E9%99%A4%E6%80%9D%E8%B7%AF%E4%B8%8E%E5%AE%9E%E4%BE%8B)
2. [Windows XML Event Log (EVTX)单条日志清除（二）——程序实现删除evtx文件的单条日志记录](https://3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%8C-%E7%A8%8B%E5%BA%8F%E5%AE%9E%E7%8E%B0%E5%88%A0%E9%99%A4evtx%E6%96%87%E4%BB%B6%E7%9A%84%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95)
3. [Windows XML Event Log (EVTX)单条日志清除（三）——通过解除文件占用删除当前系统单条日志记录](https://3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%B8%89-%E9%80%9A%E8%BF%87%E8%A7%A3%E9%99%A4%E6%96%87%E4%BB%B6%E5%8D%A0%E7%94%A8%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95)
4. [Windows XML Event Log (EVTX)单条日志清除（四）——通过注入获取日志文件句柄删除当前系统单条日志记录](https://3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E5%9B%9B-%E9%80%9A%E8%BF%87%E6%B3%A8%E5%85%A5%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95)
5. [Windows XML Event Log (EVTX)单条日志清除（五）——通过DuplicateHandle获取日志文件句柄删除当前系统单条日志记录](https://3gstudent.github.io/Windows-XML-Event-Log-(EVTX)%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E6%B8%85%E9%99%A4-%E4%BA%94-%E9%80%9A%E8%BF%87DuplicateHandle%E8%8E%B7%E5%8F%96%E6%97%A5%E5%BF%97%E6%96%87%E4%BB%B6%E5%8F%A5%E6%9F%84%E5%88%A0%E9%99%A4%E5%BD%93%E5%89%8D%E7%B3%BB%E7%BB%9F%E5%8D%95%E6%9D%A1%E6%97%A5%E5%BF%97%E8%AE%B0%E5%BD%95)

Later I'll translate them into English.

Note:

- WinXP and Win7,ObjectTypeNumber = 0x1c
- Win8 and later,ObjectTypeNumber = 0x1e

---

### DeleteRecordofFile.cpp

Read an evtx file(c:\\test\\Setup.evtx),then delete an event log(EventRecordID=14).

The new evtx file is saved as `c:\test\SetupNew.evtx`.

Delete the eventlog by rewriting the evtx file.

### DeleteRecordofFileEx.cpp

Read an evtx file,then delete an event log.

The new file(temp.evtx) will be saved at the same path.

Delete the eventlog by using WinAPI EvtExportLog.

### Setup.evtx

Number of events:15

### SetupNew.evtx

Number of events:14

You can use DeleteRecordofFile.cpp to delete the second eventlog record(EventRecordID=14) of Setup.evtx.

---

### SuspendorResumeTid.cpp

Suspend or resume the Eventlog Service's thread.

Use to stop or resume the system to collect logs.

### SuspendorResumeTidEx.cpp

When the Eventlog Service is stopped(killed by me),I'll wait for it until it starts.

Use to stop the system to collect the logs when the Eventlog Service starts.

---

### DeleteRecordbyTerminateProcess.cpp

Kill the eventlog service's process and delete one eventlog record,then restart the Eventlog Service.

Delete the eventlog by rewriting the evtx file.

### DeleteRecordbyTerminateProcessEx.cpp

Kill the eventlog service's process and delete one eventlog record,then restart the Eventlog Service.

Delete the eventlog by using WinAPI EvtExportLog.

Note:

The EventRecordID of the events after the deleted one will not be changed.

---

### DeleteRecordbyGetHandle.cpp

Get specified .evtx file's handle and delete one eventlog record.

It can be used to delete the setup.evtx,others may be affected by competitive conditions.

Delete the eventlog by rewriting the evtx file.

### DeleteRecordbyGetHandleEx.cpp

Get specified .evtx file's handle and delete one eventlog record.

Read a .evtx file and replace the specified .evtx file with the data.

It can be used to delete the setup.evtx,others may be affected by competitive conditions.

Delete the eventlog by using WinAPI EvtExportLog.

---

### Loader-rewriting.cpp

Get specified .evtx file's handle and inject a dll(Dll-rewriting.dll),use the dll to delete one eventlog record.

Delete the eventlog by rewriting the evtx file.
    
### Dll-rewriting.cpp

Compile it into DLL.

Use the dll to delete one eventlog record.

Delete the eventlog by rewriting the evtx file.

---

### DeleteRecord-EvtExportLog.cpp

Use API EvtExportLog to delete Eventlog Record.

The new file will be saved as temp.evtx.

### Loader-EvtExportLog.cpp

Get specified .evtx file's handle and inject a dll(Dll-EvtExportLog.dll).

Read a .evtx file(from DeleteRecord-EvtExportLog.exe) and send the data to the dll,the dll will replace the specified .evtx file with the data.

### Dll-EvtExportLog.cpp

Compile it into DLL.

Use the dll to delete one eventlog record.

Get data from Loader-EvtExportLog.exe,then replace the specified .evtx file with the data.

---
