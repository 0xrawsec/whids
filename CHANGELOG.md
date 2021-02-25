# Archive of the old changelog

## v1.6
- **WHIDS** is installed as a true **Windows service**
- Reworked the installation script to allow several options
- Created an **optimized Sysmon configuration** to run with WHIDS
- **Process Integrity** check not done before boot is finished
- Removed DNS logging features by default (since Sysmon v10 has DNSQuery events)
- Log message if process termination is not enabled
- **Sysmon service** depends on WHIDS (solution found not to miss events at boot)
- Updated to the latest version of **Gene (v1.6)**
- New **registry** dump mode to dump suspicious registries
- Some random code refactoring
- Sysmon events enrichment:
    - *Ancestors* in **CreateProcess**
    - Name of the **windows services** is resolved and put in *Services* field for **any event**
    - *CommandLine* in **NetworkConnect**
    - *User* and *IntegrityLevel* propagated to all applicable events (all except DriverLoad)
    - **CreateRemoteThread** and **ProcessAccess** enrichment with:
        * *SourceIntegrityLevel*
        * *TargetIntegrityLevel*
        * *SourceUser*
        * *TargetUser*
        * *TargetParentProcessGuid*
        * *SourceServices*
        * *TargetServices*
    - ...

## v1.5
  * Bunch of code rewritten to make things more consistent:
    * WHIDS is no longer command line based, most of the options are configured via a configuration file
    * Some command line switches names have changed
  * WHIDS manager can now be used as a **true management server**:
    * Update clients' rules
    * Update clients' containers
    * Receive dumps (files, memory) from the clients

## v1.4
  * Dump hooks
    * dump file: dump as many relevant files as possible when an alert above threshold is raised
      * dump anything which is a file and that appears in Sysmon fields, depending on the event
      * can dump ADS
      * can dump scripts
      * can dump executables
    * dump memory: creates a **MS full minidump** of a process that triggers an alert above threshold
  * Process integrity hook
    * Two fields are added to the Sysmon **CreateProcess** events **ProcessIntegrity** and **ParentProcessIntegrity**. If value is **-1** it means process integrity could not be 
    computed. Otherwise it is a float value in **[0;100]** measuring the degree of similarity between the image loaded in memory and the image on the disk. The **higher** the value is, the more likely the process image **has been modified**.
  * Builtin alert forwarder
    * New command line utility **whids-man** aiming at collecting the logs and being deployed on a remote machine (**windows, linux, macos ...**)
      * HTTP / HTTPS are supported (HTTPS is preferred)
      * Builtin cert and key generation (convenient for testing but better with OpenSSL for prod)
      * Client authentication via API key to forward the logs
      * Server authentication can be enforced on client side via authentication key
      * Alerts are dumped in a GZIP file automatically rotated when **100MB** size is reached
    * New command line switch **-forward** to configure forwarding on Host side
      * if manager is offline, we store the alerts in a local queue and upload them when the manager comes up again
      * builtin queue file rotation
      * builtin queued files cleaning if disk space is too high
  * Install script has been updated
    * Protects the installation directory to be accessible / modifiable only by users member of Administrators group or SYSTEM user
    * The scheduled tasks now starts **whids-launcher.bat** located in installation directory, instead of starting WHIDS directly. This way it is easier to modify the command line arguments.
  * Project tree has a bit changed, **main** code has been moved to **tools** directory
      
## v1.3
  * **Event Hook** introduction
    * Can modify the events before going through detection engine
    * Created hooks to overcome domain name resolution issue
    * Implemented hooks to enrich Sysmon events 1, 6 and 7 with the size of the PE image
    * Implemented several other hooks
  * Can run in **service mode**:
    * restart in case of failure
    * log alerts to compressed file and rotate file automatically
    * log messages to a file
  * Installation script
    * creates a scheduled start running at boot to start Whids
    * agenerate an uninstall script dropped in the install folder
  * Number of new command lines arguments
    * **-hooks**: control event hook activation
    * **-protect**: dummy protection against crypto-locker (can be seen as a nice POC of event hooks)
    * **-all**: option to enable logging of **all** the events coming from the monitored channels
    should not be used in production, it is more for debugging purposes
    * ...
  * Some minor code refactoring

## v1.2
  * Log to Windows Application channel
  * Updated with latest version of gene so it benefits of its new features
    * "Match extracts" feature to match parts of event fields against containers (blacklist/whitelist)
  * New channel Alias to Microsoft-Windows-DNS-Client/Operational
  * Command line switch to enable DNS client logs (Microsoft-Windows-DNS-Client/Operational log channel)