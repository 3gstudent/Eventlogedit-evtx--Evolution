# Eventlogedit-evtx--Evolution
Remove individual lines from Windows XML Event Log (EVTX) files

Support: Win7 and later

Compare with DanderSpritz,my way don't need dll injection and support more version(Server2012 and later).

Need more test and suggestions.

The data structure and some code details are inspired by https://bbs.pediy.com/thread-219313.htm

Later I'll write some posts to introduce the details.

Note:

- WinXP and Win7,ObjectTypeNumber = 0x1c
- Win8 and later,ObjectTypeNumber = 0x1e

---

### DeleteRecordofFile.cpp

Read an evtx file(c:\\test\\Setup.evtx),then delete an event log(EventRecordID=14).

The new evtx file is saved as `c:\test\SetupNew.evtx`.

### DeleteRecordbyTerminateProcess.cpp

Kill the eventlog service's process and delete one eventlog record,then restart the Eventlog Service.

### DeleteRecordbyGetHandle.cpp

Get specified .evtx file's handle and delete one eventlog record.

### Setup.evtx

Number of events:15

### SetupNew.evtx

Number of events:14

You can use DeleteRecordofFile.cpp to delete the second eventlog record(EventRecordID=14) of Setup.evtx.

### SuspendorResumeTid.cpp

Suspend or resume the Eventlog Service's thread.

Use to stop or resume the system to collect logs.

