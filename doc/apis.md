

# Table of Contents
* [EDR statistics](#EDR statistics)
* [Rule Management Endpoints](#Rule-Management-Endpoints)
	* [List rules loaded in the EDR](#List-rules-loaded-in-the-EDR)
	* [Deleting rule](#Deleting-rule)
	* [Adding a new rule](#Adding-a-new-rule)
	* [Save Rules](#Save-Rules)
	* [Reloading rules](#Reloading-rules)
* [Endpoint Management](#Endpoint-Management)
	* [List all endpoints](#List-all-endpoints)
	* [Get a single endpoint](#Get-a-single-endpoint)
	* [Adding a new endpoint](#Adding-a-new-endpoint)
	* [Deleting an endpoint](#Deleting-an-endpoint)
* [Executing command on endpoint](#Executing-command-on-endpoint)
	* [Getting command information](#Getting-command-information)
	* [Getting a specific command field information](#Getting-a-specific-command-field-information)
	* [Executing a command on endpoint](#Executing-a-command-on-endpoint)
		* [The command we want to execute](#The-command-we-want-to-execute)
		* [Pushing the command on the endpoint](#Pushing-the-command-on-the-endpoint)
		* [Getting the result](#Getting-the-result)
* [Endpoint logs and alerts](#Endpoint-logs-and-alerts)
	* [Getting endpoint alerts](#Getting-endpoint-alerts)
	* [Getting endpoint logs](#Getting-endpoint-logs)
* [Endpoint artifacts](#Endpoint-artifacts)
	* [Listing available endpoint artifacts](#Listing-available-endpoint-artifacts)
	* [Downloading a given artifact](#Downloading-a-given-artifact)
* [Endpoint reports](#Endpoint-reports)
	* [All endpoint reports](#All-endpoint-reports)
	* [Getting a single endpoint report](#Getting-a-single-endpoint-report)
	* [Deleting an endpoint report](#Deleting-an-endpoint-report)

# EDR statistics

🟢 **GET** `/stats`

**Description:** Used to retrieve basic statistics about the EDR manager

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/stats"
```

**Response:**
```json
{
  "data": {
    "endpoint-count": 1,
    "rule-count": 133
  },
  "message": "OK",
  "error": ""
}
```

# Rule Management Endpoints

## List rules loaded in the EDR

🟢 **GET** `/rules?name=REGEXP`
2021-07-06T17:18:42.835802162Z
**Description:** This endpoint is usde to retrive rules loaded in the EDR manager (also deployed on all the endpoints connected).

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/rules?name=HighlyPol.*"
```

**Response:**
```json
{
  "data": [
    {
      "Name": "HighlyPolymorphicCode",
      "Tags": [
        "WHIDS"
      ],
      "Meta": {
        "EventIDs": [
          1
        ],
        "Channels": [
          "Microsoft-Windows-Sysmon/Operational"
        ],
        "Computers": [],
        "ATTACK": [
          {
            "ID": "T1093",
            "Tactic": "defense-evasion",
            "Reference": "https://attack.mitre.org/techniques/T1093"
          }
        ],
        "Criticality": 10,
        "Disable": false,
        "Filter": false
      },
      "Matches": [
        "$lowboundproc: ProcessIntegrity >= '50'",
        "$lowboundpproc: ParentProcessIntegrity >= '50'"
      ],
      "Condition": "$lowboundproc or $lowboundpproc"
    }
  ],
  "message": "OK",
  "error": ""
}
```

## Deleting rule

🟢 **DELETE** `/rules?name=RULE_NAME`

**Description:** Used to delete a rule from the EDR manager. The engine needs to be reloaded after deletion (c.f. [reloading rules](reloading-rules))

**Request:**
```bash
curl -skH "Api-key: admin" -X DELETE "https://localhost:8001/rules?name=HighlyPolymorphicCode"
```

**Response:**
```json
{
  "data": null,
  "message": "Rules updated succesfully, engine needs to be reloaded",
  "error": ""
}
```


## Adding a new rule

🟢 **POST** `/rules?update=[1|0|t|f|true|false]`

**Description:** Used to add a new rule to the manager or update an existing rule. In case of update the rule engine needs to be reloaded (c.f. [reloading rules](reloading-rules)).

Params:
* **update:** boolean value to force update if rule already exists

**Request:**
```bash
# Let's look at the rule definition
jq . /tmp/rule.gen
```

**Response:**
```json
{
  "Name": "HighlyPolymorphicCode",
  "Tags": [
    "WHIDS"
  ],
  "Meta": {
    "EventIDs": [
      1
    ],
    "Channels": [
      "Microsoft-Windows-Sysmon/Operational"
    ],
    "Computers": [],
    "ATTACK": [
      {
        "ID": "T1093",
        "Tactic": "defense-evasion",
        "Reference": "https://attack.mitre.org/techniques/T1093"
      }
    ],
    "Criticality": 10,
    "Disable": false,
    "Filter": false
  },
  "Matches": [
    "$lowboundproc: ProcessIntegrity >= '50'",
    "$lowboundpproc: ParentProcessIntegrity >= '50'"
  ],
  "Condition": "$lowboundproc or $lowboundpproc"
}
```

We try to create a new rule from the file shown above

**Request:**
```bash
curl -d @/tmp/rule.gen -skH "Api-key: admin" "https://localhost:8001/rules"
```

**Response:**
```json
{
  "data": null,
  "message": "NOK",
  "error": "Error loading rule: Rule \"HighlyPolymorphicCode\" already exists"
}
```

If we want the rule to be overwritten, we need to force update

**Request:**
```bash
curl -d @/tmp/rule.gen -skH "Api-key: admin" "https://localhost:8001/rules?update=true"
```

**Response:**
```json
{
  "data": null,
  "message": "Rules updated succesfully, engine needs to be reloaded",
  "error": ""
}
```

## Save Rules

🟢 **GET** `/rules/save`

**Description:** endpoint to use to save rules.

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/rules/save"
```

**Response:**
```json
{
  "data": null,
  "message": "Rules saved succesfully on disk",
  "error": ""
}
```

## Reloading rules

🟢 **GET** `/rules/reload`

**Description:** API endpoint used to reload the rule engine.

```bash
curl -skH "Api-key: admin" "https://localhost:8001/rules/reload"
```
```json
{
  "data": {
    "endpoint-count": 1,
    "rule-count": 132
  },
  "message": "OK",
  "error": ""
}
```

# Endpoint Management

## List all endpoints

🟢 **GET** `/endpoints`

**Description:** API endpoint to use to list all the available endpoints configured to communicate with the manager.

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/endpoints"
```

**Response:**
```json
{
  "data": [
    {
      "uuid": "03e31275-2277-d8e0-bb5f-480fac7ee4ef",
      "hostname": "DESKTOP-LLOYD",
      "ip": "192.168.42.42",
      "key": "ztBdB6XGl81Vx957YmVXjmh1SfnqliRMeoa7zYewtimXCGCNoR6O2Nfw9YjVD8KX",
      "last-connection": "2021-03-02T22:42:35.664304855+01:00"
    }
  ],
  "message": "OK",
  "error": ""
}
```

## Get a single endpoint

🟢 **GET** `/endpoints/{ENDPOINT_UUID}`

**Description:** endpoint used to list information about a single endpoint.

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef"
```

**Response:**
```json
{
  "data": {
    "uuid": "03e31275-2277-d8e0-bb5f-480fac7ee4ef",
    "hostname": "DESKTOP-LLOYD",
    "ip": "192.168.0.93",
    "key": "ztBdB6XGl81Vx957YmVXjmh1SfnqliRMeoa7zYewtimXCGCNoR6O2Nfw9YjVD8KX",
    "last-connection": "2021-03-02T16:39:13.64023147+01:00"
  },
  "message": "OK",
  "error": ""
}
```

## Adding a new endpoint

🟢 **PUT** `/endpoints`

**Description:** adds a **new endpoint** to the EDR. The endpoint will also be added to
the configuration of the manager and committed to disk. You can now configure a new
EDR agent on any endpoint.

**Request:**
```bash
curl -skH "Api-key: admin" -X PUT "https://localhost:8001/endpoints"
```

**Response:**
```json
{
  "data": {
    "uuid": "4a796766-bb17-2e35-64fb-2fb836bf04d0",
    "hostname": "",
    "ip": "",
    "key": "x5l68KpJwk6v5pc1wyJkgBWjTCDRzIGCn9aXapcOjVoWCgKFEh3KEffJRDdkIgNi",
    "last-connection": "0001-01-01T00:00:00Z"
  },
  "message": "OK",
  "error": ""
}
```

## Deleting an endpoint

🟢 **DELETE** `/endpoints/{ENDPOINT_UUID}`

**Description:** deletes an endpoint from the EDR. This change is immediate
and persistent. Thus if an EDR agent is still configured using these
credentials it will not be able to communicate with the manager any longer.

**Request:**
```bash
curl -skH "Api-key: admin" -X DELETE "https://localhost:8001/endpoints/49e63832-cb8e-e2ee-04d5-115e7a85b62f"
```
**Response:** information of the **deleted** endpoint
```json
{ 
  "data": {
    "uuid": "49e63832-cb8e-e2ee-04d5-115e7a85b62f",
    "hostname": "",
    "ip": "",
    "key": "FysqI9gCMT9C9eQgslsOfuW567Ba7X4xWfOe21Dbu7WBKxs1F5sbfXeSH033sj9v",
    "last-connection": "0001-01-01T00:00:00Z"
  },
  "message": "OK",
  "error": ""
}
```

# Executing command on endpoint

## Getting command information

🟢 **GET** `/endpoints/{ENDPOINT_UUID}/command`

**Description:** this API endpoint is used to get information about a pending or executed 
command. In order to make sure the command has been ran, a specific flag in the response
can be checked.

**Request:**
```bash
# HTTP GET
curl -skH "Api-key: admin" "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/command"
```

**Response:**
```json
{
  "data": {
    "uuid": "f3e15c2e-c46e-082d-53a3-fd7621453505",
    "name": "cmd.exe",
    "args": [
      "cmd.exe",
      "/c",
      "dir",
      "C:\\"
    ],
    "drop": [],
    "fetch": {},
    # stdout, base64 encoded
    "stdout": "IFZvbHVtZSBpbiBkcml2ZSBDIGhhcyBubyBsYWJlbC4NCiBWb2x1bWUgU2VyaWFsIE51bWJlciBpcyA5Mjc0LTcxQzENCg0KIERpcmVjdG9yeSBvZiBDOlwNCg0KMDMvMDIvMjAyMSAgMDg6MjggQU0gICAgPERJUj4gICAgICAgICAgUHJvZ3JhbSBGaWxlcw0KMDEvMTEvMjAyMSAgMDU6MDYgUE0gICAgPERJUj4gICAgICAgICAgUHJvZ3JhbSBGaWxlcyAoeDg2KQ0KMDYvMTIvMjAxOSAgMTA6NTEgQU0gICAgPERJUj4gICAgICAgICAgVXNlcnMNCjAzLzAzLzIwMjEgIDAyOjA1IFBNICAgIDxESVI+ICAgICAgICAgIFdpbmRvd3MNCiAgICAgICAgICAgICAgIDAgRmlsZShzKSAgICAgICAgICAgICAgMCBieXRlcw0KICAgICAgICAgICAgICAgNCBEaXIocykgIDE0LDY1Niw5MzcsOTg0IGJ5dGVzIGZyZWUNCg==",
    "stderr": null,
    "error": "",
    # true if the endpoint received the command
    "sent": true,
    "background": false,
    # flag to check to make sure command completed
    "completed": true,
    "timeout": 0,
    # time at which the command has been received by the endpoint
    "sent-time": "2021-03-03T14:32:40.939939135+01:00"
  },
  "message": "OK",
  "error": ""
}
```

## Getting a specific command field information

🟢 **GET** `/endpoints/{ENDPOINT_UUID}/command/{FIELD}`

**Description:** this endpoint is used to retrieve only one field of the command. This way it
allows saving bandwith for polling patterns. Not all fields are accessible through that endpoint.

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/command/completed"
```

**Response:** the data field of the response contains only the value of the queried field
```json
{
  "data": true,
  "message": "OK",
  "error": ""
}
```

## Executing a command on endpoint

🟢 **POST** `/endpoints/{ENDPOINT_UUID}/command`

**Description:** this endpoint can be used to ask the endpoint to **execute a command** or
**fetch files from the endpoint**. Files can also be dropped prior to command execution, this
way it is possible to execute binaries or scripts not initially present on the endpoint. Such
dropped files are removed post command execution.

It is worth mentionning that it is the EDR agent installed on the endpoint which is 
responsible for checking commands to execute. So no connection from the EDR manager 
to the agent is made. 

**Post Data:**

  ```json
  {
    # command line to execute
    "command-line": "cmd /c dir C:\\\\Windows\\\\System32",
    # files to collect (post command execution) from the endpoint
    # it can be used to retrieve command's output file or collect
    # artifacts
    "fetch-files": [
      "C:\\\\Windows\\\\System32\\\\malware.exe"
    ],
    # files to drop on the endpoint (prior to execution)
    # it can be used to execute script, exe not initially
    # present on the endpoint.
    # the paths specified here must be local to the manager
    "drop-files": [
      ""
    ],
    # timeout for the command, if 0 or empty no timeout is applied
    "timeout": 10 ,
  }
  ```

### The command we want to execute

```bash
jq . /tmp/command.json
```
```json
{
  "command-line": "cmd.exe /c dir C:\\\\"
}
```

### Pushing the command on the endpoint

**Request:**
```bash
# POST command
curl -skH "Api-key: admin" -d @/tmp/command.json "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/command"
```
**Response:**
```json
{
  "data": {
    "uuid": "03e31275-2277-d8e0-bb5f-480fac7ee4ef",
    "hostname": "DESKTOP-LLOYD",
    "ip": "192.168.0.93",
    "key": "ztBdB6XGl81Vx957YmVXjmh1SfnqliRMeoa7zYewtimXCGCNoR6O2Nfw9YjVD8KX",
    "command": {
      "uuid": "f3e15c2e-c46e-082d-53a3-fd7621453505",
      "name": "cmd.exe",
      "args": [
        "/c",
        "dir",
        "C:\\"
      ],
      "drop": [],
      "fetch": {},
      "stdout": null,
      "stderr": null,
      "error": "",
      "sent": false,
      "background": false,
      "completed": false,
      "timeout": 0,
      "sent-time": "0001-01-01T00:00:00Z"
    },
    "last-connection": "2021-03-03T14:32:36.460166243+01:00"
  },
  "message": "OK",
  "error": ""
}
```

### Getting the result

**Request:**
```bash
# GET
curl -skH "Api-key: admin" "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/command"
```

**Response:**
```json
{
  "data": {
    "uuid": "f3e15c2e-c46e-082d-53a3-fd7621453505",
    "name": "cmd.exe",
    "args": [
      "cmd.exe",
      "/c",
      "dir",
      "C:\\"
    ],
    "drop": [],
    "fetch": {},
    # stdout, base64 encoded
    "stdout": "IFZvbHVtZSBpbiBkcml2ZSBDIGhhcyBubyBsYWJlbC4NCiBWb2x1bWUgU2VyaWFsIE51bWJlciBpcyA5Mjc0LTcxQzENCg0KIERpcmVjdG9yeSBvZiBDOlwNCg0KMDMvMDIvMjAyMSAgMDg6MjggQU0gICAgPERJUj4gICAgICAgICAgUHJvZ3JhbSBGaWxlcw0KMDEvMTEvMjAyMSAgMDU6MDYgUE0gICAgPERJUj4gICAgICAgICAgUHJvZ3JhbSBGaWxlcyAoeDg2KQ0KMDYvMTIvMjAxOSAgMTA6NTEgQU0gICAgPERJUj4gICAgICAgICAgVXNlcnMNCjAzLzAzLzIwMjEgIDAyOjA1IFBNICAgIDxESVI+ICAgICAgICAgIFdpbmRvd3MNCiAgICAgICAgICAgICAgIDAgRmlsZShzKSAgICAgICAgICAgICAgMCBieXRlcw0KICAgICAgICAgICAgICAgNCBEaXIocykgIDE0LDY1Niw5MzcsOTg0IGJ5dGVzIGZyZWUNCg==",
    "stderr": null,
    "error": "",
    # true if the endpoint received the command
    "sent": true,
    "background": false,
    # flag to check to make sure command completed
    "completed": true,
    "timeout": 0,
    # time at which the command has been received by the endpoint
    "sent-time": "2021-03-03T14:32:40.939939135+01:00"
  },
  "message": "OK",
  "error": ""
}
```
As stdout may contain binary data it is **base64 encoded**, after decoding we get
```txt
 Volume in drive C has no label.
 Volume Serial Number is 9274-71C1

 Directory of C:\

03/02/2021  08:28 AM    <DIR>          Program Files
01/11/2021  05:06 PM    <DIR>          Program Files (x86)
06/12/2019  10:51 AM    <DIR>          Users
03/03/2021  02:05 PM    <DIR>          Windows
               0 File(s)              0 bytes
               4 Dir(s)  14,656,937,984 bytes free
```

# Endpoint logs and alerts

## Getting endpoint alerts

🟢 **GET** `/endpoints/{ENDPOINT_UUID}/alerts`

**Description:** API endpoint to use in order to retrieve alerts collected from a given endpoint.

**Requirement:** endpoint logging must be configured on the manager (cf. [manager config](configuration.md#manager))

**Params:**
  * **start:** RFC 3339 formatted timestamp used as **starting point** for getting alerts
  * **stop:** RFC 3339 formatted timestamp used as **stopping point** for getting alerts
  * **pivot:** RFC 3339 formatted timestamp used as pivot point for retrieving logs
  * **delta:** duration string used for getting alerts around pivot point. Specifying
  a pivot and a delta will search alerts from `pivot-delta` to `pivot+delta`

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/alerts"
```

**Response:**
```json
{
  "data": [
    {
      "Event": {
        "EventData": {
          "Ancestors": "System|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\wininit.exe|C:\\Windows\\System32\\services.exe",
          "CommandLine": "\"C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe\" /service",
          "Company": "Microsoft Corporation",
          "CurrentDirectory": "C:\\Windows\\system32\\",
          "Description": "Microsoft Office Click-to-Run (SxS)",
          "FileVersion": "16.0.13628.20346",
          "Hashes": "SHA1=6A32BCEA6106E9151A5BDB4B7A8AA31C78C8C5C7,MD5=2B2DC8D683ACDC977F9E4109F0BBE0D9,SHA256=C779EA16CE7AD786AA83455F2A5A46A964ADE47FB8CDA5537CFE116B14ECACD3,IMPHASH=4606D7A079BA8D6E7F9540975D7E79FF",
          "Image": "C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe",
          "ImageSize": "8905608",
          "IntegrityLevel": "System",
          "LogonGuid": "{515cd0d1-00f4-6040-e703-000000000000}",
          "LogonId": "0x3e7",
          "OriginalFileName": "OfficeClickToRun.exe",
          "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
          "ParentImage": "C:\\Windows\\System32\\services.exe",
          "ParentIntegrityLevel": "System",
          "ParentProcessGuid": "{515cd0d1-00f4-6040-0b00-000000005a00}",
          "ParentProcessId": "640",
          "ParentServices": "N/A",
          "ParentUser": "NT AUTHORITY\\SYSTEM",
          "ProcessGuid": "{515cd0d1-00f6-6040-4400-000000005a00}",
          "ProcessId": "2796",
          "Product": "Microsoft Office",
          "RuleName": "-",
          "Services": "ClickToRunSvc",
          "TerminalSessionId": "0",
          "User": "NT AUTHORITY\\SYSTEM",
          "UtcTime": "2021-03-03 21:34:46.769"
        },
        "GeneInfo": {
          "Criticality": 10,
          "Signature": [
            "UnknownServices"
          ]
        },
        "System": {
          "Channel": "Microsoft-Windows-Sysmon/Operational",
          "Computer": "DESKTOP-LLOYD",
          "Correlation": {},
          "EventID": "1",
          "EventRecordID": "53336456",
          "Execution": {
            "ProcessID": "3288",
            "ThreadID": "724"
          },
          "Keywords": "0x8000000000000000",
          "Level": "4",
          "Opcode": "0",
          "Provider": {
            "Guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
            "Name": "Microsoft-Windows-Sysmon"
          },
          "Security": {
            "UserID": "S-1-5-18"
          },
          "Task": "1",
          "TimeCreated": {
            "SystemTime": "2021-03-03T21:34:51.790661600Z"
          },
          "Version": "5"
        }
      }
    },
    # [...]
  ],
  "message": "OK",
  "error": ""
}
```

## Getting endpoint logs

🟢 **GET** `/endpoints/{ENDPOINT_UUID}/logs`

**Description:** used to retrieve logs of an endpoint. Those logs includes filtered in events as well as alerts.

**Requirement:** endpoint logging must be configured on the manager (cf. [manager config](configuration.md#manager))

Exact same behaviour as [endpoint alerts endpoint](#Getting-endpoint-alerts)

# Endpoint artifacts

## Listing available endpoint artifacts

🟢 **GET** `/endpoints/{ENDPOINT_UUID}/artifacts`

**Description:** list the artifacts collected (following an alert) on a given endpoint.

**Params:**
  * **since:** RFC 3339 formatted timestamp used to retrieve artifact collected last updated after this date

**Request:**
```bash
curl -skH Api-key: admin https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/artifacts?since=2021-07-06T17:19:42.835802162Z
```

**Response:**
```json
{
  "data": [
    {
      "update": "2021-07-06T19:21:50.655802826Z",
      "process-guid": "515cd0d1-ab35-60e4-827c-000000004e00",
      "event-hash": "2252cc3dee2623a44f5d1644338129b9",
      "base-url": "/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/artifacts/515cd0d1-ab35-60e4-827c-000000004e00/2252cc3dee2623a44f5d1644338129b9/",
      "files": [
        "event.json.gz",
        "powershell.exe_12644_1625598794801114200.dmp.gz",
        "report.json.gz"
      ]
    }
  ],
  "message": "OK",
  "error": ""
}
```

## Downloading a given artifact

🟢 **GET** `/endpoints/{ENDPOINT_UUID}/artifacts/{PROCESS_GUID}/{EVENT_HASH}/{FILENAME}`

**Description:** download a given artifact

**Params:**
  * **raw:** boolean telling that we want to receive the raw file 
  * **gunzip:** boolean instructing that artifact content must be gunzipped before being sent

**NB:** boolean must be in one of the following values (true, false, t, f, 0, 1)

**Request:**
```bash
curl -skH Api-key: admin https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/artifacts/515cd0d1-9064-60e4-577c-000000004e00/443884f68ad4203613ff54a80d4fba15/event.json.gz
```

**Response:**
```json
{
  "data": "H4sIAAAAAAAE/5xUW2/iRhT+K+g8tZKdnfFcfJGiyvgS6JINislW27oPXvvAWgseNDZJKOK/V2MDSbZNH5q84Jn5zu37vnOA5BGbDoLTj7joCvMRNiW2ndItBBAFef5b3VTqqc3zbN92uGFOnreoH+sS2yt8RrAgUptN0VSzukEIIO9Rc61WutiM0nqN7einZ0/+nOc3Sq3WmOcP26ro8Pw9fJlYOYw+tI/lEHJbNHsIYMCMZrPIHO+0xqaLa41lp7S5f1NieykRLIixLXW97WrVvMSZNm1XrNeowQJT22fU7fCAXrErJq88ChZMivYbmgFkk5BeU8cXJPaJTFOXsJSFNCHj2HdZGoXOmDOWiHDsENe6jcW1H0oZsjhxhOenLiUed2SYMjccu6kcc2plk9AR8jr0KeNUSEdyxmIRk5S4MUsiTjweSjdNZSoo8yIWsVTyhMk4JhENEx5xh0VSWNPb+STMJtdunFKPSof5kRhHnhCSkJhThxJOZCTGYMF0U6wQAoiC/P8Rc46R1X+ZOFRwLqQ5bDpc6brbz/AR1xDAoBGwYKZWqrnZ1RUEcBBUlBWpqF15FG1JqtJGlzCbEHL5P55BUwMhzwxdsOBO16u6KdaGqk/FxiQfBPEiGrBgXhhVRG9k+I4ufpDugJxuipUJ/QYztPIvcj9hfmz9l0shc61KbNv/6J58JeTSPUfSdz/EPYH7KUiPX4JmOHgOgleZHlrU54N3kvpEclsS5LZw3fKfSQdYn853eZ9Pq2pXdi+eGWYNFtzv1mcWbLDgVUmrXW9psGCBemMYy7A1xuoDE7DgVOqnxSh8WEzu7qeLL3mefckWya257cpF3dPrEIfaxLWJHFE3oF7geFe+T+BowQ02OG2WymypSNddXRbruttDQIkFWb1qim6nEYI/4KH53qin5lLgn0frLM3gANG3oml6ud7WpVatWnb2acvZ2b7dqObD3RZ1YTZHsTZrR222u64fdZxkHxd3c3v26/3nhBgPREprXPePITgcrWGtTmMIwKySfsneY6l01Z85gvie4xtk8ozlziQxRZ2JMDiHMseM8pvG4oTinJgRfMT9k9KVUQF59i7mGf6Mg04+NDzebUtVGVmbi7lWj3VlWjjAzdmWrkuYJ5Z26TiFzRkS++uSlzaRSyF9b7n8WvnGlifjvTcsU1eG5U73XBx6pvs2MpvawqaeebAo2u+niRiiI41Fh5VpfPCZOYTgFfuLV+wzJgUl5HcT6DPqtlYNBCDgeDz+DQAA//8BAAD//1JaS5vGBgAA",
  "message": "OK",
  "error": ""
}
```

# Endpoint reports

## All endpoint reports

🟢 **GET** `/endpoints/reports`

**Description:** API endpoint to get EDR reports about all the endpoints connected. Reports are not persistent accross restart of the manager.

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/endpoints/reports"
```

**Response:**
```json
{
  "data": {
    "03e31275-2277-d8e0-bb5f-480fac7ee4ef": {
      "identifier": "03e31275-2277-d8e0-bb5f-480fac7ee4ef",
      "alert-count": 99,
      "count-by-signature": {
        "DefenderConfigChanged": 2,
        "ExecTimestomping": 1,
        "ExecutableFileCreated": 3,
        "HeurPersistentRAT": 1,
        "HeurSpawnShell": 1,
        "NewAutorun": 8,
        "StopSvchostAccess": 71,
        "UnknownServices": 6,
        "UntrustedDriverLoaded": 4,
        "UntrustedService": 3
      },
      "signatures": [
        "DefenderConfigChanged",
        "UntrustedDriverLoaded",
        "HeurPersistentRAT",
        "NewAutorun",
        "UnknownServices",
        "HeurSpawnShell",
        "UntrustedService",
        "ExecTimestomping",
        "ExecutableFileCreated",
        "StopSvchostAccess"
      ],
      "techniques": [
        "T1014",
        "T1060",
        "T1035"
      ],
      "tactics": [
        "Defense Evasion",
        "persistence",
        "Execution"
      ],
      "signature-count": 100,
      "sum-alert-criticality": 744,
      "avg-alert-criticality": 7.51,
      "std-dev-alert-criticality": 1.05,
      "sum-rule-criticality": 747,
      "avg-signature-criticality": 7.47,
      "std-dev-signature-criticality": 1.05,
      "signature-diversity": 100,
      "count-uniq-signatures": 10,
      "signature-criticality-metric": 70,
      "alert-criticality-metric": 751,
      # aggregated metric which can be used to rank endpoints
      # between them and prioritize investigation. It is made
      # in such a way that it is relative to every environment.
      # So a given noisy machine would not have the same score
      # in a noisy and quiet environment.
      "score": 821,
      "start-time": "2021-03-03T21:34:51.3769993Z",
      "median-time": "2021-03-03T21:43:01.53481525Z",
      "stop-time": "2021-03-03T21:51:11.6926312Z"
    },
    "1829e1ac-acf6-953f-c3a8-27818820bb9f": null,
    "5949e4a8-82c3-2284-58d1-0a93a3f8ed04": null,
    "7fa7a8ab-4725-bf63-f8b3-9c72ed07f45a": null
  },
  "message": "OK",
  "error": ""
}
```

## Getting a single endpoint report

🟢 **GET** `/endpoints/{ENDPOINT_UUID}/reports`

**Description:** API endpoint to get an EDR report about a given endpoint.

**Request:**
```bash
curl -skH "Api-key: admin" "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/report"
```

**Response:**
```json
{
  "data": {
    "identifier": "03e31275-2277-d8e0-bb5f-480fac7ee4ef",
    "alert-count": 99,
    "count-by-signature": {
      "DefenderConfigChanged": 2,
      "ExecTimestomping": 1,
      "ExecutableFileCreated": 3,
      "HeurPersistentRAT": 1,
      "HeurSpawnShell": 1,
      "NewAutorun": 8,
      "StopSvchostAccess": 71,
      "UnknownServices": 6,
      "UntrustedDriverLoaded": 4,
      "UntrustedService": 3
    },
    "signatures": [
      "DefenderConfigChanged",
      "UntrustedDriverLoaded",
      "HeurPersistentRAT",
      "NewAutorun",
      "ExecutableFileCreated",
      "StopSvchostAccess",
      "UnknownServices",
      "HeurSpawnShell",
      "UntrustedService",
      "ExecTimestomping"
    ],
    "techniques": [
      "T1014",
      "T1060",
      "T1035"
    ],
    "tactics": [
      "persistence",
      "Execution",
      "Defense Evasion"
    ],
    "signature-count": 100,
    "sum-alert-criticality": 744,
    "avg-alert-criticality": 7.51,
    "std-dev-alert-criticality": 1.05,
    "sum-rule-criticality": 747,
    "avg-signature-criticality": 7.47,
    "std-dev-signature-criticality": 1.05,
    "signature-diversity": 100,
    "count-uniq-signatures": 10,
    "signature-criticality-metric": 70,
    "alert-criticality-metric": 751,
    "score": 821,
    "start-time": "2021-03-03T21:34:51.3769993Z",
    "median-time": "2021-03-03T21:43:01.53481525Z",
    "stop-time": "2021-03-03T21:51:11.6926312Z"
  },
  "message": "OK",
  "error": ""
}
```

## Deleting an endpoint report

🟢 **DELETE** `/endpoints/{ENDPOINT_UUID}/reports`

**Description:** API to delete a report for a given endpoint. A report can be deleted after an enpoint has been investigated.

**Request:**
```bash
curl -skH "Api-key: admin" -X DELETE "https://localhost:8001/endpoints/03e31275-2277-d8e0-bb5f-480fac7ee4ef/report"
```

**Response:**
```json
{
  "data": {
    "identifier": "03e31275-2277-d8e0-bb5f-480fac7ee4ef",
    "alert-count": 99,
    "count-by-signature": {
      "DefenderConfigChanged": 2,
      "ExecTimestomping": 1,
      "ExecutableFileCreated": 3,
      "HeurPersistentRAT": 1,
      "HeurSpawnShell": 1,
      "NewAutorun": 8,
      "StopSvchostAccess": 71,
      "UnknownServices": 6,
      "UntrustedDriverLoaded": 4,
      "UntrustedService": 3
    },
    "signatures": [
      "NewAutorun",
      "DefenderConfigChanged",
      "UntrustedDriverLoaded",
      "HeurPersistentRAT",
      "ExecTimestomping",
      "ExecutableFileCreated",
      "StopSvchostAccess",
      "UnknownServices",
      "HeurSpawnShell",
      "UntrustedService"
    ],
    "techniques": [
      "T1060",
      "T1035",
      "T1014"
    ],
    "tactics": [
      "Defense Evasion",
      "persistence",
      "Execution"
    ],
    "signature-count": 100,
    "sum-alert-criticality": 744,
    "avg-alert-criticality": 7.51,
    "std-dev-alert-criticality": 1.05,
    "sum-rule-criticality": 747,
    "avg-signature-criticality": 7.47,
    "std-dev-signature-criticality": 1.05,
    "signature-diversity": 100,
    "count-uniq-signatures": 10,
    "signature-criticality-metric": 70,
    "alert-criticality-metric": 751,
    "score": 821,
    "start-time": "2021-03-03T21:34:51.3769993Z",
    "median-time": "2021-03-03T21:43:01.53481525Z",
    "stop-time": "2021-03-03T21:51:11.6926312Z"
  },
  "message": "OK",
  "error": ""
}
```
