# Eventlogedit-evtx--Evolution
Remove individual lines from Windows XML Event Log (EVTX) files

Support: Win7 and later

Need more test and suggestions.

### DeleteRecordofFile.cpp

Read an evtx file(c:\\test\\System.evtx),then delete an event log(EventRecordID=1914).

The new evtx file is saved as `c:\\test\\System2.evtx`.

### DeleteRecordbyTerminateProcess.cpp

Kill the eventlog service's process and delete one eventlog record,then restart the Eventlog Service.

---
The other code is coming soon.

Open at the right time
