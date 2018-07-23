# Eventlogedit-evtx--Evolution
Remove individual lines from Windows XML Event Log (EVTX) files

Support: Win7 and later

Need more test and suggestions.

**Update:**

1. Change the code of DeleteRecordbyGetHandle.cpp.

Note:

- WinXP and Win7,ObjectTypeNumber = 0x1c
- Win8 and later,ObjectTypeNumber = 0x1e

---

### DeleteRecordofFile.cpp

Read an evtx file(c:\\test\\System.evtx),then delete an event log(EventRecordID=1914).

The new evtx file is saved as `c:\\test\\System2.evtx`.

### DeleteRecordbyTerminateProcess.cpp

Kill the eventlog service's process and delete one eventlog record,then restart the Eventlog Service.

### DeleteRecordbyGetHandle.cpp

Get specified .evtx file's handle and delete one eventlog record.

### System.evtx

Number of events:4

### System2.evtx

Delete the last one eventlog record

Number of events:3
