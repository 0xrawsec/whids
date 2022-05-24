# EDR commands documentation

This page documents the EDR specific commands endpoints can run.In addition to all the commands documented\
below, **any** other binary present on the endpoint can be executed, whether by absolute path or without if\
the binary is present in the **PATH** environment variable. To understand how to send commands to endpoints and\
how to receive results, please take a look at the [**OpenAPI** documentation](https://validator.swagger.io/?url=https://raw.githubusercontent.com/0xrawsec/whids/master/doc/admin.openapi.json).

**IMPORTANT:** paths in command examples may contain escape sequences (Windows paths for instances).\
When such path is used inside JSON escape characters needs to be escaped once again (to be JSON valid).\
For instance if one wants to execute `tasklist` command from an absolute path the command would have to\
be encoded as such `C:\\\\Windows\\\\System32\\\\tasklist.exe`


## Index
* [contain](#contain)
* [uncontain](#uncontain)
* [osquery](#osquery)
* [sysmon](#sysmon)
* [terminate](#terminate)
* [hash](#hash)
* [rexhash](#rexhash)
* [stat](#stat)
* [ls](#ls)
* [walk](#walk)
* [find](#find)
* [report](#report)
* [processes](#processes)
* [modules](#modules)
* [drivers](#drivers)

## contain

**Description:** Isolate host at network level

**Help:** `contain`


## uncontain

**Description:** Uncontain host (i.e. remove network isolation)

**Help:** `uncontain`


## osquery

**Description:** Alias to `osqueryi --json -A`

**Help:** `osquery OSQUERY_TABLE`

**Example:** `osquery processes`


## sysmon

**Description:** Alias to the sysmon binary deployed by the EDR. See sysmon binary command line switches for all available options.

**Help:** `sysmon [OPTIONS]`

**Example:** `sysmon -h`


## terminate

**Description:** Terminate a process given its PID

**Help:** `terminate PID`

**Example:** `terminate 1337`


## hash

**Description:** Hash a file

**Help:** `hash FILE`

**Example:** `hash C:\\Windows\\System32\\cmd.exe`


## rexhash

**Description:** Recursively find files matching pattern and hashes them

**Help:** `rexhash DIRECTORY PATTERN`

**Example:** `rexhash C:\\Windows\\System32 cmd\\.exe`


## stat

**Description:** Stat a file or a directory

**Help:** `stat FILE|DIRECTORY`

**Example:** `stat C:\\Windows\\System32\\cmd.exe`


## ls

**Description:** List a directory

**Help:** `ls DIRECTORY`

**Example:** `ls C:\\Windows\\`


## walk

**Description:** Recursively list a directory

**Help:** `walk DIRECTORY`

**Example:** `walk C:\\Windows\\System32`


## find

**Description:** Recursively find a pattern in filename

**Help:** `find DIRECTORY REGEX_PATTERN`

**Example:** `find C:\\Windows\\System32 cmd.*\.exe`


## report

**Description:** Generate a full IR ready report

**Help:** `report`


## processes

**Description:** Retrieve the full list of processes running (monitored from Sysmon logs)

**Help:** `processes`


## modules

**Description:** Retrieve the full list of modules ever loaded since boot (monitored from Sysmon logs)

**Help:** `modules`


## drivers

**Description:** Retrieve the full list of drivers ever loaded since boot (monitored from Sysmon logs)

**Help:** `drivers`


