<p align="center">
  <img src="https://github.com/0xrawsec/whids/blob/master/doc/img/logo.png?s=200" alt="logo">
</p>

## What

This is an hybrid solution combining a flexible **Host IDS** with detection based **Incident Response 
capabilities**. The detection engine is built on top of a previously developped rule engine 
[Gene](https://github.com/0xrawsec/gene) specially designed to match Windows events against 
user defined rules.

## Why
* Provide an **Open Source EDR** like tool
* Flexible detection
* Easy integration with other open-source tools (MISP, The Hive ...)

## How
### Detection
* On host real time detection
* Listens to Windows event log channels and apply detection rules
* User defined rules (we know why we detect something)
* Designed to be used with MS [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* Enriches Windows events in order to build powerfull detection primitives
* Central agent to distributes rules and collect alerts

### Incident Response
* Reacts on detection (when an event above a given criticality is detected, artifacts are collected)
* Real time evidence collection (files, process memory and registries)
* Central agent to collect evidences

<p align="center">
  <img src="https://github.com/0xrawsec/whids/blob/master/doc/img/workflow.png" alt="workflow">
</p>

# Demo

## Rule Example

Here is an example of a rule designed to catch suspicious access to *lsass.exe*
as it is done by the well known Mimikatz credential dump tool.

```json
{
  "Name": "MaliciousLsassAccess",
  "Tags": ["Mimikatz", "Credentials", "Lsass"],
  "Meta": {
    "EventIDs": [10],
    "Channels": ["Microsoft-Windows-Sysmon/Operational"],
    "Computers": [],
    "Traces": [],
    "Criticality": 10,
    "Author": "0xrawsec"
  },
  "Matches": [
    "$ct: CallTrace ~= 'UNKNOWN'",
    "$lsass: TargetImage ~= '(?i:\\\\lsass\\.exe$)'"
  ],
  "Condition": "$lsass and $ct"
}
```

You can find a bunch of other rules as well as a quick introduction to the
syntax of the rules on the [Gene repository](https://github.com/0xrawsec/gene-rules).

## In Action
Running WHIDS with an already running Powershell Empire agent which invokes
Mimikatz module.

![WHIDS Mimikatz Demo](https://github.com/0xrawsec/whids/blob/master/demo/whids.gif)

Herafter is the kind of output returned by WHIDS. An additional section is added to the
JSON event where the criticality of the alert is reported along with the different signatures
which matched the event.

```json
{
  "Event": {
    "EventData": {
      "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+4bf9a|C:\\Windows\\system32\\KERNELBASE.dll+189b7|UNKNOWN(00000000259123BC)",
      "GrantedAccess": "0x1410",
      "SourceImage": "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "SourceProcessGUID": "{49F1AF32-DD18-5A72-0000-0010042C0A00}",
      "SourceProcessId": "2248",
      "SourceThreadId": "3308",
      "TargetImage": "C:\\Windows\\system32\\lsass.exe",
      "TargetProcessGUID": "{49F1AF32-DB3B-5A72-0000-001013690000}",
      "TargetProcessId": "492",
      "UtcTime": "2018-02-01 11:24:53.331"
    },
    "GeneInfo": {
      "Criticality": 10,
      "Signature": [
        "MaliciousLsassAccess"
      ]
    },
    "System": {
        "Classical Windows Event System Section": "..."
    }
  }
}
```

# Installation

## WHIDS
1. Download and extract the latest WHIDS release https://github.com/0xrawsec/whids/releases
2. If you want WHIDS to run along with Sysmon (**strongly recommended**), install it first. An optimal **configuration file** is shipped with the release so that you can take the most out of WHIDS. At installation the **Sysmon service** will be made *dependant* of **WHIDS service** so that we are sure the IDS runs before **Sysmon** starts generating some events.
3. Run `manage.bat` as **administrator**
4. Launch installation by selecting the appropriate option
5. Verify that files have been created at the **installation directory**
6. With a text editor **opened as administrator** (to prevent changing the rights of the WHIDS installation directory) open `config.json` and modify it as you wish. This can also be done from `manage.bat`
7. Skip this if running with a connection to a manager, because rules will be updated automatically. If there is nothing in the **rules directory** the tool will be useless, so make sure there are some **gene** rules in there. Some rules are packaged with WHIDS and you will be prompted if you want to install those or not. If you want the last up to date rules, you can get those [here](https://raw.githubusercontent.com/0xrawsec/gene-rules/master/compiled.gen) (take the **compiled** ones)
8. Start the **services** from appropriate option in `manage.bat` or just reboot (**preferred option** otherwise some enrichment fields will be incomplete leading to false alerts)
9. If you configured a **manager** do not forget to run it in order to receive alerts and dumps

**NB:** whenever you go to the installation directory with **Explorer.exe** and if you are **Administrator** the explorer will ask you if you want to change the permission of the directory. **DO NOT CLICK YES**, otherwise it will break the folder permissions put in place at installation time. Always access installation directory from **applications started as Administrator** (i.e. text editor).

# Configuration

## WHIDS

WHIDS configuration file example

```
{
    // Path to the rules directory used for detection
    "rules-db": "C:\\Program Files\\Whids\\Database\\Rules",
    // Path to the containers used in some of the rules
    // containers must be GZIP compressed and have .cont.gz extension
    // basename without extension is taken as container name
    // Example: blacklist.cont.gz will create blacklist container
    "containers-db": "C:\\Program Files\\Whids\\Database\\Containers",
    // Forwarder related configuration
    "forwarder": {
        "manager-client": {
            // Hostname or IP address of remote manager
            "host": "",
            // Port used by remote manager
            "port": 0,
            // Protocol used http or https
            "proto": "",
            // Key used to authenticate the client
            "key": "",
            // Server key used to authenticate remote server
            "server-key": "",
            // Whether or not the TLS certificate should be verified
            "unsafe": false,
            // Maximum upload side for dump forwarding
            "max-upload-size": 104857600
        },
        // Alert logging settings
        "logging": {
            // Path where to store the alerts
            "dir": "C:\\Program Files\\Whids\\Logs\\Alerts",
            // Rotation interval
            "rotation-interval": "24h"
        },
        // If local=true the forwarder won't communicate with manager
        "local": true
    },
    // Windows event log channels to monitor
    // run "whids -h" to get the list of aliases
    // otherwise any Windows channel can be used here 
    "channels": [
        "all"
    ],
    // Dump related settings
    "dump": {
        // Dump mode: file, memory or all (can be empty)
        // file: dumps anything identified as a file in the event
        // memory: dumps (guilty) process memory in Windows minidump format
        // registry: dumps registry in case alert concerns a registry
        "mode": "file|registry",
        // Dumps when criticality of the events is above or equal to treshold
        "treshold": 8,
        // Where to store dumps
        "dir": "C:\\Program Files\\Whids\\Dumps",
        // Whether or not to enable dump compression
        "compression": true
    },
    // Log events with criticality above or equal to treshold
    "criticality-treshold": 5,
    // Sleep time in seconds between two rules updates (negative number means no update)
    "update-interval": 60,
    // Whether on not hooks should be enabled
    "en-hooks": true,
    // Logfile used to store WHIDS stderr
    "logfile": "C:\\Program Files\\Whids\\Logs\\whids.log",
    // Log all the events passing through the engine (usefull for event dumping or debugging)
    "log-all": false,
    // Tells WHIDS that it is running on an endpoint. If false any kind 
    // of dump is disabled to avoid dump things if installed on a WEC
    "endpoint": true
}
```

## Manager

Manager configuration example

```
{
    // Hostname / IP on which to run the manager
    "host": "192.168.56.1",
    // Port used by the manager
    "port": 1519,
    // Logfile (automatically rotated) where to store alerts received
    "logfile": "alerts.log",
    // Server authentication key (see server-key in WHIDS config)
    "key": "someserverkey",
    // List of authorized client keys (see key in WHIDS config)
    // If the client is not authorized in this list, all the connections 
    // to the manager will abort
    "authorized": [
      "clientapikey"
    ],
    // TLS settings
    "tls": {
        // Server certificate to use
        "cert": "cert.pem",
        // Server key to use
        "key": "key.pem"
    },
    "misp": {
        // Protocol to use for MISP connection
        "protocol" :"https",
        // MISP host
        "host" : "misp.host",
        // API key to use
        "api-key" :"your misp api key"
    },
    // Rules directory used to serve rules to the clients
    "rules-dir": "",
    // Rules of containers used in rules (served to the clients)
    // a container name is the basename of the file without extension
    // Example: /some/container/dir/blacklist.txt will take the content
    // of the file and use it as being a Gene container named blacklist
    "containers-dir": ""
    // Directory used to store dumps sent by the client
    "dump-dir": "",
}
```

# Documentation

To know how to write rules for the engine please visit: https://rawsec.lu/doc/gene/1.6/

# Known Issues

* Does not work properly when ran from a network share **mapped as a network drive** (this case prevent whids to identify itself and thus generate some noise). Example: if `\\vbox\test` is mounted as `Z:` drive, running `Z:\whids.exe` **won't work** while running `\\vbox\test\whids.exe` actually would.

# Recommendations

In order to get the most of WHIDS you need to activate specific features

* [Install Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [Enable Powershell Module Logging](https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html)

# Changelog

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
