package server

var OpenAPIDefinition = `
{
  "openapi": "3.0.2",
  "info": {
    "title": "WHIDS API documentation",
    "version": "1.0"
  },
  "servers": [
    {
      "url": "https://localhost:1520"
    }
  ],
  "paths": {
    "/endpoints": {
      "get": {
        "tags": [
          "Endpoint Management"
        ],
        "summary": "Get endpoints",
        "parameters": [
          {
            "name": "showkey",
            "in": "query",
            "description": "Show or not key",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          },
          {
            "name": "group",
            "in": "query",
            "description": "Filter by group",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "status",
            "in": "query",
            "description": "Filter by status",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "criticality",
            "in": "query",
            "description": "Filter by criticality",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "Config": {
                        "Actions": {
                          "AvailableActions": [],
                          "Critical": [],
                          "High": [],
                          "Low": [],
                          "Medium": []
                        },
                        "AuditConfig": {
                          "AuditDirs": [],
                          "AuditPolicies": [],
                          "Enable": false
                        },
                        "CanariesConfig": {
                          "Actions": [],
                          "Canaries": [],
                          "Enable": false,
                          "Whitelist": []
                        },
                        "CritTresh": 0,
                        "DatabasePath": "",
                        "Dump": {
                          "Compression": false,
                          "Dir": "",
                          "DumpUntracked": false,
                          "MaxDumps": 0
                        },
                        "EnableFiltering": false,
                        "EnableHooks": false,
                        "Endpoint": false,
                        "EtwConfig": {
                          "Providers": [],
                          "Traces": []
                        },
                        "FwdConfig": {
                          "Client": {
                            "Host": "",
                            "Key": "",
                            "MaxUploadSize": 0,
                            "Port": 0,
                            "Proto": "",
                            "ServerFingerprint": "",
                            "ServerKey": "",
                            "UUID": "",
                            "Unsafe": false
                          },
                          "Local": false,
                          "Logging": {
                            "Dir": "",
                            "RotationInterval": 0
                          }
                        },
                        "LogAll": false,
                        "Logfile": "",
                        "Report": {
                          "CommandTimeout": 0,
                          "Commands": [],
                          "EnableReporting": false,
                          "OSQuery": {
                            "Tables": []
                          }
                        },
                        "RulesConfig": {
                          "ContainersDB": "",
                          "RulesDB": "",
                          "UpdateInterval": 0
                        },
                        "Sysmon": {
                          "ArchiveDirectory": "",
                          "Bin": "",
                          "CleanArchived": false
                        }
                      },
                      "criticality": 0,
                      "group": "",
                      "hostname": "OpenHappy",
                      "ip": "127.0.0.1",
                      "key": "1dBTeTTbXc5OE3qU8XW8WwkHfpGxHPn7eRyVoXmgQLQ7T7vqapOEVCPd3Cqx6MEE",
                      "last-connection": "2022-07-26T10:16:09.409830822Z",
                      "last-detection": "2022-07-26T12:16:08.351197299+02:00",
                      "last-event": "2022-07-26T12:16:08.351197299+02:00",
                      "score": 0,
                      "status": "",
                      "system-info": {
                        "bios": {
                          "date": "12/01/2006",
                          "version": "VirtualBox"
                        },
                        "cpu": {
                          "count": 4,
                          "name": "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
                        },
                        "edr": {
                          "commit": "deadbeeeeeeeeeeeeeeeeef",
                          "version": "major.minor.patch"
                        },
                        "error": null,
                        "os": {
                          "build": "18362",
                          "edition": "Enterprise",
                          "name": "windows",
                          "product": "Windows 10 Pro",
                          "version": "10.0.18362"
                        },
                        "sysmon": {
                          "config": {
                            "hash": "2d1652d67b565cabf2e774668f2598188373e957ef06aa5653bf9bf6fe7fe837",
                            "version": {
                              "binary": "15.0",
                              "schema": "4.70"
                            }
                          },
                          "driver": {
                            "image": "C:\\Windows\\SysmonDrv.sys",
                            "name": "SysmonDrv",
                            "sha256": "e9ea8c0390c65c055d795b301ee50de8f8884313530023918c2eea56de37a525"
                          },
                          "service": {
                            "image": "C:\\Program Files\\Whids\\Sysmon64.exe",
                            "name": "Sysmon64",
                            "sha256": "b448cd80b09fa43a3848f5181362ac52ffcb283f88693b68f1a0e4e6ae932863"
                          },
                          "version": "v13.23"
                        },
                        "system": {
                          "manufacturer": "innotek GmbH",
                          "name": "VirtualBox",
                          "virtual": true
                        }
                      },
                      "uuid": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "put": {
        "tags": [
          "Endpoint Management"
        ],
        "summary": "Create a new endpoint",
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "Config": null,
                    "criticality": 0,
                    "group": "",
                    "hostname": "",
                    "ip": "",
                    "key": "NknjFBuHmm83cfLMIyYBOGTaH6zYovgBxkaD5NNbgaBUKrlvIJYBHgTvm4N0sSxn",
                    "last-connection": "0001-01-01T00:00:00Z",
                    "last-detection": "0001-01-01T00:00:00Z",
                    "last-event": "0001-01-01T00:00:00Z",
                    "score": 0,
                    "status": "",
                    "uuid": "9bad456e-ab68-06ee-3242-6f0425951686"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/artifacts": {
      "get": {
        "tags": [
          "Artifact Search and Retrieval"
        ],
        "summary": "Artifacts on all endpoints",
        "parameters": [
          {
            "name": "since",
            "in": "query",
            "description": "Retrieve artifacts received since date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d": [
                      {
                        "base-url": "/endpoints/5a92baeb-9384-47d3-92b4-a0db6f9b8c6d/artifacts/5a92baeb-9384-47d3-92b4-a0db6f9b8c6d/3d8441643c204ba9b9dcb5c414b25a3129f66f6c/",
                        "creation": "2022-07-26T10:16:13.747105168Z",
                        "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                        "files": [
                          {
                            "name": "bar.txt",
                            "size": 4,
                            "timestamp": "2022-07-26T10:16:13.747105168Z"
                          },
                          {
                            "name": "foo.txt",
                            "size": 4,
                            "timestamp": "2022-07-26T10:16:13.747105168Z"
                          }
                        ],
                        "modification": "2022-07-26T10:16:13.747105168Z",
                        "process-guid": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                      }
                    ]
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/reports": {
      "get": {
        "tags": [
          "Detection Reports"
        ],
        "summary": "Get all detection reports",
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d": {
                      "alert-count": 50,
                      "alert-criticality-metric": 0,
                      "avg-alert-criticality": 0,
                      "avg-signature-criticality": 0,
                      "bounded-score": 0,
                      "count-by-signature": {
                        "DefenderConfigChanged": 6,
                        "NewAutorun": 27,
                        "SuspiciousService": 4,
                        "UnknownServices": 7,
                        "UntrustedDriverLoaded": 6
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-07-26T12:16:11.570582416+02:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "NewAutorun",
                        "UnknownServices",
                        "SuspiciousService",
                        "DefenderConfigChanged",
                        "UntrustedDriverLoaded"
                      ],
                      "start-time": "2022-07-26T12:16:11.5690665+02:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-07-26T12:16:11.572098332+02:00",
                      "sum-alert-criticality": 0,
                      "sum-rule-criticality": 0,
                      "tactics": null,
                      "techniques": null
                    }
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{os}/osqueryi/binary": {
      "get": {
        "tags": [
          "Manage OSQueryi installation"
        ],
        "summary": "Get information about OSQueryi binary",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "binary",
            "in": "query",
            "description": "Show binary in response",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alias": "osqueryi",
                    "binary": "TVpmb29iYXI=",
                    "metadata": {
                      "md5": "6d6b9b955abe00ae042be6c0090e3c47",
                      "sha1": "9cc75cdbefa6d4490db401c9b0dc6398c7fb2a39",
                      "sha256": "31b7bcfda3653f68213fd59b33fdcda5bf9513c31f0adde1c75beaaa31e0f44b",
                      "sha512": "1d23010c1687f3d96a3762767f17b7e14a4b1da7aaa56c4fb0a046d59738fc27417f7ddd9409279f9e8765ed9d7229e19f1ec628a8ccfcafe586dcd161585438"
                    },
                    "name": "osqueryi",
                    "os": "windows",
                    "uuid": "661564ba-e14c-639e-437b-537abb656bc6"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Manage OSQueryi installation"
        ],
        "summary": "Add or update OSQueryi binary to deploy on endpoints",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "binary",
            "in": "query",
            "description": "Show binary in response",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "requestBody": {
          "description": "OSQueryi binary to deploy",
          "content": {
            "application/octet-stream": {
              "schema": {
                "type": "string",
                "format": "binary"
              },
              "example": "TVpmb29iYXI="
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alias": "osqueryi",
                    "binary": "TVpmb29iYXI=",
                    "metadata": {
                      "md5": "6d6b9b955abe00ae042be6c0090e3c47",
                      "sha1": "9cc75cdbefa6d4490db401c9b0dc6398c7fb2a39",
                      "sha256": "31b7bcfda3653f68213fd59b33fdcda5bf9513c31f0adde1c75beaaa31e0f44b",
                      "sha512": "1d23010c1687f3d96a3762767f17b7e14a4b1da7aaa56c4fb0a046d59738fc27417f7ddd9409279f9e8765ed9d7229e19f1ec628a8ccfcafe586dcd161585438"
                    },
                    "name": "osqueryi",
                    "os": "windows",
                    "uuid": "661564ba-e14c-639e-437b-537abb656bc6"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Manage OSQueryi installation"
        ],
        "summary": "Delete OSQueryi binary from manager and connected endpoints",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "binary",
            "in": "query",
            "description": "Show binary in response",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alias": "osqueryi",
                    "binary": "TVpmb29iYXI=",
                    "metadata": {
                      "md5": "6d6b9b955abe00ae042be6c0090e3c47",
                      "sha1": "9cc75cdbefa6d4490db401c9b0dc6398c7fb2a39",
                      "sha256": "31b7bcfda3653f68213fd59b33fdcda5bf9513c31f0adde1c75beaaa31e0f44b",
                      "sha512": "1d23010c1687f3d96a3762767f17b7e14a4b1da7aaa56c4fb0a046d59738fc27417f7ddd9409279f9e8765ed9d7229e19f1ec628a8ccfcafe586dcd161585438"
                    },
                    "name": "osqueryi",
                    "os": "windows",
                    "uuid": "661564ba-e14c-639e-437b-537abb656bc6"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{os}/sysmon/binary": {
      "get": {
        "tags": [
          "Manage Sysmon"
        ],
        "summary": "Get information about Sysmon binary",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "binary",
            "in": "query",
            "description": "Show binary in response",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alias": "sysmon",
                    "binary": "TVpmb29iYXI=",
                    "metadata": {
                      "md5": "6d6b9b955abe00ae042be6c0090e3c47",
                      "sha1": "9cc75cdbefa6d4490db401c9b0dc6398c7fb2a39",
                      "sha256": "31b7bcfda3653f68213fd59b33fdcda5bf9513c31f0adde1c75beaaa31e0f44b",
                      "sha512": "1d23010c1687f3d96a3762767f17b7e14a4b1da7aaa56c4fb0a046d59738fc27417f7ddd9409279f9e8765ed9d7229e19f1ec628a8ccfcafe586dcd161585438"
                    },
                    "name": "sysmon",
                    "os": "windows",
                    "uuid": "1e4dff28-8d71-34cf-22ef-5ed6d057aef7"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Manage Sysmon"
        ],
        "summary": "Add or update Sysmon binary to deploy on connected endpoints",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "binary",
            "in": "query",
            "description": "Show binary in response",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "requestBody": {
          "description": "Sysmon binary to deploy",
          "content": {
            "application/octet-stream": {
              "schema": {
                "type": "string",
                "format": "binary"
              },
              "example": "TVpmb29iYXI="
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alias": "sysmon",
                    "binary": "TVpmb29iYXI=",
                    "metadata": {
                      "md5": "6d6b9b955abe00ae042be6c0090e3c47",
                      "sha1": "9cc75cdbefa6d4490db401c9b0dc6398c7fb2a39",
                      "sha256": "31b7bcfda3653f68213fd59b33fdcda5bf9513c31f0adde1c75beaaa31e0f44b",
                      "sha512": "1d23010c1687f3d96a3762767f17b7e14a4b1da7aaa56c4fb0a046d59738fc27417f7ddd9409279f9e8765ed9d7229e19f1ec628a8ccfcafe586dcd161585438"
                    },
                    "name": "sysmon",
                    "os": "windows",
                    "uuid": "1e4dff28-8d71-34cf-22ef-5ed6d057aef7"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Manage Sysmon"
        ],
        "summary": "Delete Sysmon binary from manager and connected endpoints",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "binary",
            "in": "query",
            "description": "Show binary in response",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alias": "sysmon",
                    "binary": "TVpmb29iYXI=",
                    "metadata": {
                      "md5": "6d6b9b955abe00ae042be6c0090e3c47",
                      "sha1": "9cc75cdbefa6d4490db401c9b0dc6398c7fb2a39",
                      "sha256": "31b7bcfda3653f68213fd59b33fdcda5bf9513c31f0adde1c75beaaa31e0f44b",
                      "sha512": "1d23010c1687f3d96a3762767f17b7e14a4b1da7aaa56c4fb0a046d59738fc27417f7ddd9409279f9e8765ed9d7229e19f1ec628a8ccfcafe586dcd161585438"
                    },
                    "name": "sysmon",
                    "os": "windows",
                    "uuid": "1e4dff28-8d71-34cf-22ef-5ed6d057aef7"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{os}/sysmon/config": {
      "get": {
        "tags": [
          "Manage Sysmon"
        ],
        "summary": "Get a Sysmon configuration",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "version",
            "in": "query",
            "description": "version query parameter",
            "required": true,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "format",
            "in": "query",
            "description": "format query parameter",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "raw",
            "in": "query",
            "description": "raw query parameter",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "CheckRevocation": false,
                    "CopyOnDeletePE": false,
                    "DnsLookup": false,
                    "EventFiltering": {
                      "ClipboardChange": {
                        "onmatch": "exclude"
                      },
                      "CreateRemoteThread": {
                        "onmatch": "exclude"
                      },
                      "DriverLoad": {
                        "onmatch": "exclude"
                      },
                      "FileCreate": {
                        "onmatch": "exclude"
                      },
                      "FileCreateStreamHash": {
                        "onmatch": "exclude"
                      },
                      "FileCreateTime": {
                        "onmatch": "exclude"
                      },
                      "FileDelete": {
                        "onmatch": "exclude"
                      },
                      "FileDeleteDetected": {
                        "onmatch": "exclude"
                      },
                      "NetworkConnect": {
                        "onmatch": "exclude"
                      },
                      "PipeEvent": {
                        "onmatch": "exclude"
                      },
                      "ProcessCreate": {
                        "onmatch": "exclude"
                      },
                      "ProcessTampering": {
                        "onmatch": "exclude"
                      },
                      "ProcessTerminate": {
                        "onmatch": "exclude"
                      },
                      "RawAccessRead": {
                        "onmatch": "exclude"
                      },
                      "RuleGroup": [
                        {
                          "ImageLoad": {
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "Signature": [
                              {
                                "condition": "is",
                                "value": "Microsoft Windows Publisher"
                              },
                              {
                                "condition": "is",
                                "value": "Microsoft Corporation"
                              },
                              {
                                "condition": "is",
                                "value": "Microsoft Windows"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "ProcessAccess": {
                            "GrantedAccess": [
                              {
                                "condition": "is",
                                "value": "0x1000"
                              },
                              {
                                "condition": "is",
                                "value": "0x2000"
                              },
                              {
                                "condition": "is",
                                "value": "0x3000"
                              },
                              {
                                "condition": "is",
                                "value": "0x100000"
                              },
                              {
                                "condition": "is",
                                "value": "0x101000"
                              }
                            ],
                            "SourceImage": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\system32\\wbem\\wmiprvse.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\System32\\VBoxService.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\system32\\taskmgr.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "RegistryEvent": {
                            "EventType": [
                              {
                                "condition": "is not",
                                "value": "SetValue"
                              }
                            ],
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "DnsQuery": {
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        }
                      ],
                      "WmiEvent": {
                        "onmatch": "exclude"
                      }
                    },
                    "HashAlgorithms": [
                      "*"
                    ],
                    "OS": "windows",
                    "XmlSha256": "a939006f3ccb8862411bb67a73976e35a61149d4c65952c7d3b588e7015dd7f4",
                    "schemaversion": "4.70"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Manage Sysmon"
        ],
        "summary": "Add or update a Sysmon configuration",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "format",
            "in": "query",
            "description": "format query parameter",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "description": "Sysmon configuration file. Raw XML file that you would use to configure Sysmon can be posted here.",
          "content": {
            "application/xml": {
              "schema": {
                "type": "object",
                "properties": {
                  "InnerConfig": {
                    "type": "object",
                    "properties": {
                      "": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "EventFiltering": {
                        "type": "object",
                        "properties": {
                          "Filters": {
                            "type": "object",
                            "properties": {
                              "": {
                                "type": "object",
                                "properties": {
                                  "EventFilter": {
                                    "type": "object",
                                    "properties": {
                                      "onmatch": {
                                        "type": "string"
                                      }
                                    }
                                  },
                                  "Hashes": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "Image": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "IsExecutable": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "ProcessGuid": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "ProcessId": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "RuleName": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "TargetFilename": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "User": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  },
                                  "UtcTime": {
                                    "type": "array",
                                    "items": {
                                      "type": "object",
                                      "properties": {
                                        "": {
                                          "type": "string"
                                        },
                                        "condition": {
                                          "type": "string"
                                        },
                                        "name": {
                                          "type": "string"
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          },
                          "RuleGroup": {
                            "type": "array",
                            "items": {
                              "type": "object",
                              "properties": {
                                "Filters": {
                                  "type": "object",
                                  "properties": {
                                    "": {
                                      "type": "object",
                                      "properties": {
                                        "EventFilter": {
                                          "type": "object",
                                          "properties": {
                                            "onmatch": {
                                              "type": "string"
                                            }
                                          }
                                        },
                                        "Hashes": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "Image": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "IsExecutable": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "ProcessGuid": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "ProcessId": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "RuleName": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "TargetFilename": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "User": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        },
                                        "UtcTime": {
                                          "type": "array",
                                          "items": {
                                            "type": "object",
                                            "properties": {
                                              "": {
                                                "type": "string"
                                              },
                                              "condition": {
                                                "type": "string"
                                              },
                                              "name": {
                                                "type": "string"
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                },
                                "groupRelation": {
                                  "type": "string"
                                },
                                "name": {
                                  "type": "string"
                                }
                              }
                            }
                          }
                        }
                      },
                      "Sysmon": {
                        "type": "object",
                        "properties": {
                          "Local": {
                            "type": "string"
                          },
                          "Space": {
                            "type": "string"
                          }
                        }
                      },
                      "schemaversion": {
                        "type": "string"
                      }
                    }
                  },
                  "Item": {
                    "type": "object"
                  }
                }
              },
              "example": {
                "schemaversion": "4.70",
                "CheckRevocation": false,
                "CopyOnDeletePE": false,
                "DnsLookup": false,
                "HashAlgorithms": [
                  "*"
                ],
                "EventFiltering": {
                  "ProcessCreate": {
                    "onmatch": "exclude"
                  },
                  "FileCreateTime": {
                    "onmatch": "exclude"
                  },
                  "NetworkConnect": {
                    "onmatch": "exclude"
                  },
                  "ProcessTerminate": {
                    "onmatch": "exclude"
                  },
                  "DriverLoad": {
                    "onmatch": "exclude"
                  },
                  "CreateRemoteThread": {
                    "onmatch": "exclude"
                  },
                  "RawAccessRead": {
                    "onmatch": "exclude"
                  },
                  "FileCreate": {
                    "onmatch": "exclude"
                  },
                  "FileCreateStreamHash": {
                    "onmatch": "exclude"
                  },
                  "PipeEvent": {
                    "onmatch": "exclude"
                  },
                  "WmiEvent": {
                    "onmatch": "exclude"
                  },
                  "FileDelete": {
                    "onmatch": "exclude"
                  },
                  "ClipboardChange": {
                    "onmatch": "exclude"
                  },
                  "ProcessTampering": {
                    "onmatch": "exclude"
                  },
                  "FileDeleteDetected": {
                    "onmatch": "exclude"
                  },
                  "RuleGroup": [
                    {
                      "ImageLoad": {
                        "onmatch": "exclude",
                        "Image": [
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\Sysmon.exe"
                          },
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\Sysmon64.exe"
                          }
                        ],
                        "Signature": [
                          {
                            "condition": "is",
                            "value": "Microsoft Windows Publisher"
                          },
                          {
                            "condition": "is",
                            "value": "Microsoft Corporation"
                          },
                          {
                            "condition": "is",
                            "value": "Microsoft Windows"
                          }
                        ]
                      },
                      "groupRelation": "or"
                    },
                    {
                      "ProcessAccess": {
                        "onmatch": "exclude",
                        "SourceImage": [
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\system32\\wbem\\wmiprvse.exe"
                          },
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\System32\\VBoxService.exe"
                          },
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\system32\\taskmgr.exe"
                          }
                        ],
                        "GrantedAccess": [
                          {
                            "condition": "is",
                            "value": "0x1000"
                          },
                          {
                            "condition": "is",
                            "value": "0x2000"
                          },
                          {
                            "condition": "is",
                            "value": "0x3000"
                          },
                          {
                            "condition": "is",
                            "value": "0x100000"
                          },
                          {
                            "condition": "is",
                            "value": "0x101000"
                          }
                        ]
                      },
                      "groupRelation": "or"
                    },
                    {
                      "RegistryEvent": {
                        "onmatch": "exclude",
                        "EventType": [
                          {
                            "condition": "is not",
                            "value": "SetValue"
                          }
                        ],
                        "Image": [
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\Sysmon.exe"
                          },
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\Sysmon64.exe"
                          }
                        ]
                      },
                      "groupRelation": "or"
                    },
                    {
                      "DnsQuery": {
                        "onmatch": "exclude",
                        "Image": [
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\Sysmon.exe"
                          },
                          {
                            "condition": "is",
                            "value": "C:\\Windows\\Sysmon64.exe"
                          }
                        ]
                      },
                      "groupRelation": "or"
                    }
                  ]
                },
                "XmlSha256": "a939006f3ccb8862411bb67a73976e35a61149d4c65952c7d3b588e7015dd7f4",
                "OS": "windows"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "CheckRevocation": false,
                    "CopyOnDeletePE": false,
                    "DnsLookup": false,
                    "EventFiltering": {
                      "ClipboardChange": {
                        "onmatch": "exclude"
                      },
                      "CreateRemoteThread": {
                        "onmatch": "exclude"
                      },
                      "DriverLoad": {
                        "onmatch": "exclude"
                      },
                      "FileCreate": {
                        "onmatch": "exclude"
                      },
                      "FileCreateStreamHash": {
                        "onmatch": "exclude"
                      },
                      "FileCreateTime": {
                        "onmatch": "exclude"
                      },
                      "FileDelete": {
                        "onmatch": "exclude"
                      },
                      "FileDeleteDetected": {
                        "onmatch": "exclude"
                      },
                      "NetworkConnect": {
                        "onmatch": "exclude"
                      },
                      "PipeEvent": {
                        "onmatch": "exclude"
                      },
                      "ProcessCreate": {
                        "onmatch": "exclude"
                      },
                      "ProcessTampering": {
                        "onmatch": "exclude"
                      },
                      "ProcessTerminate": {
                        "onmatch": "exclude"
                      },
                      "RawAccessRead": {
                        "onmatch": "exclude"
                      },
                      "RuleGroup": [
                        {
                          "ImageLoad": {
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "Signature": [
                              {
                                "condition": "is",
                                "value": "Microsoft Windows Publisher"
                              },
                              {
                                "condition": "is",
                                "value": "Microsoft Corporation"
                              },
                              {
                                "condition": "is",
                                "value": "Microsoft Windows"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "ProcessAccess": {
                            "GrantedAccess": [
                              {
                                "condition": "is",
                                "value": "0x1000"
                              },
                              {
                                "condition": "is",
                                "value": "0x2000"
                              },
                              {
                                "condition": "is",
                                "value": "0x3000"
                              },
                              {
                                "condition": "is",
                                "value": "0x100000"
                              },
                              {
                                "condition": "is",
                                "value": "0x101000"
                              }
                            ],
                            "SourceImage": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\system32\\wbem\\wmiprvse.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\System32\\VBoxService.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\system32\\taskmgr.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "RegistryEvent": {
                            "EventType": [
                              {
                                "condition": "is not",
                                "value": "SetValue"
                              }
                            ],
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "DnsQuery": {
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        }
                      ],
                      "WmiEvent": {
                        "onmatch": "exclude"
                      }
                    },
                    "HashAlgorithms": [
                      "*"
                    ],
                    "OS": "windows",
                    "XmlSha256": "a939006f3ccb8862411bb67a73976e35a61149d4c65952c7d3b588e7015dd7f4",
                    "schemaversion": "4.70"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Manage Sysmon"
        ],
        "summary": "Delete a Sysmon configuration",
        "parameters": [
          {
            "name": "os",
            "in": "path",
            "description": "os path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "version",
            "in": "query",
            "description": "version query parameter",
            "required": true,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "CheckRevocation": false,
                    "CopyOnDeletePE": false,
                    "DnsLookup": false,
                    "EventFiltering": {
                      "ClipboardChange": {
                        "onmatch": "exclude"
                      },
                      "CreateRemoteThread": {
                        "onmatch": "exclude"
                      },
                      "DriverLoad": {
                        "onmatch": "exclude"
                      },
                      "FileCreate": {
                        "onmatch": "exclude"
                      },
                      "FileCreateStreamHash": {
                        "onmatch": "exclude"
                      },
                      "FileCreateTime": {
                        "onmatch": "exclude"
                      },
                      "FileDelete": {
                        "onmatch": "exclude"
                      },
                      "FileDeleteDetected": {
                        "onmatch": "exclude"
                      },
                      "NetworkConnect": {
                        "onmatch": "exclude"
                      },
                      "PipeEvent": {
                        "onmatch": "exclude"
                      },
                      "ProcessCreate": {
                        "onmatch": "exclude"
                      },
                      "ProcessTampering": {
                        "onmatch": "exclude"
                      },
                      "ProcessTerminate": {
                        "onmatch": "exclude"
                      },
                      "RawAccessRead": {
                        "onmatch": "exclude"
                      },
                      "RuleGroup": [
                        {
                          "ImageLoad": {
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "Signature": [
                              {
                                "condition": "is",
                                "value": "Microsoft Windows Publisher"
                              },
                              {
                                "condition": "is",
                                "value": "Microsoft Corporation"
                              },
                              {
                                "condition": "is",
                                "value": "Microsoft Windows"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "ProcessAccess": {
                            "GrantedAccess": [
                              {
                                "condition": "is",
                                "value": "0x1000"
                              },
                              {
                                "condition": "is",
                                "value": "0x2000"
                              },
                              {
                                "condition": "is",
                                "value": "0x3000"
                              },
                              {
                                "condition": "is",
                                "value": "0x100000"
                              },
                              {
                                "condition": "is",
                                "value": "0x101000"
                              }
                            ],
                            "SourceImage": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\system32\\wbem\\wmiprvse.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\System32\\VBoxService.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\system32\\taskmgr.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "RegistryEvent": {
                            "EventType": [
                              {
                                "condition": "is not",
                                "value": "SetValue"
                              }
                            ],
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        },
                        {
                          "DnsQuery": {
                            "Image": [
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon.exe"
                              },
                              {
                                "condition": "is",
                                "value": "C:\\Windows\\Sysmon64.exe"
                              }
                            ],
                            "onmatch": "exclude"
                          },
                          "groupRelation": "or"
                        }
                      ],
                      "WmiEvent": {
                        "onmatch": "exclude"
                      }
                    },
                    "HashAlgorithms": [
                      "*"
                    ],
                    "OS": "windows",
                    "XmlSha256": "a939006f3ccb8862411bb67a73976e35a61149d4c65952c7d3b588e7015dd7f4",
                    "schemaversion": "4.70"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}": {
      "get": {
        "tags": [
          "Endpoint Management"
        ],
        "summary": "Get information about a single endpoint",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "Config": {
                      "Actions": {
                        "AvailableActions": [],
                        "Critical": [],
                        "High": [],
                        "Low": [],
                        "Medium": []
                      },
                      "AuditConfig": {
                        "AuditDirs": [],
                        "AuditPolicies": [],
                        "Enable": false
                      },
                      "CanariesConfig": {
                        "Actions": [],
                        "Canaries": [],
                        "Enable": false,
                        "Whitelist": []
                      },
                      "CritTresh": 0,
                      "DatabasePath": "",
                      "Dump": {
                        "Compression": false,
                        "Dir": "",
                        "DumpUntracked": false,
                        "MaxDumps": 0
                      },
                      "EnableFiltering": false,
                      "EnableHooks": false,
                      "Endpoint": false,
                      "EtwConfig": {
                        "Providers": [],
                        "Traces": []
                      },
                      "FwdConfig": {
                        "Client": {
                          "Host": "",
                          "Key": "",
                          "MaxUploadSize": 0,
                          "Port": 0,
                          "Proto": "",
                          "ServerFingerprint": "",
                          "ServerKey": "",
                          "UUID": "",
                          "Unsafe": false
                        },
                        "Local": false,
                        "Logging": {
                          "Dir": "",
                          "RotationInterval": 0
                        }
                      },
                      "LogAll": false,
                      "Logfile": "",
                      "Report": {
                        "CommandTimeout": 0,
                        "Commands": [],
                        "EnableReporting": false,
                        "OSQuery": {
                          "Tables": []
                        }
                      },
                      "RulesConfig": {
                        "ContainersDB": "",
                        "RulesDB": "",
                        "UpdateInterval": 0
                      },
                      "Sysmon": {
                        "ArchiveDirectory": "",
                        "Bin": "",
                        "CleanArchived": false
                      }
                    },
                    "command": {
                      "args": [],
                      "background": false,
                      "completed": true,
                      "drop": [],
                      "error": "",
                      "expect-json": false,
                      "fetch": {},
                      "json": null,
                      "name": "",
                      "sent": true,
                      "sent-time": "2022-07-26T12:16:09.408987389+02:00",
                      "stderr": "",
                      "stdout": "",
                      "timeout": 0,
                      "uuid": ""
                    },
                    "criticality": 0,
                    "group": "",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-07-26T10:16:09.409830822Z",
                    "last-detection": "2022-07-26T12:16:08.351197299+02:00",
                    "last-event": "2022-07-26T12:16:08.351197299+02:00",
                    "score": 0,
                    "status": "",
                    "system-info": {
                      "bios": {
                        "date": "12/01/2006",
                        "version": "VirtualBox"
                      },
                      "cpu": {
                        "count": 4,
                        "name": "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
                      },
                      "edr": {
                        "commit": "deadbeeeeeeeeeeeeeeeeef",
                        "version": "major.minor.patch"
                      },
                      "error": null,
                      "os": {
                        "build": "18362",
                        "edition": "Enterprise",
                        "name": "windows",
                        "product": "Windows 10 Pro",
                        "version": "10.0.18362"
                      },
                      "sysmon": {
                        "config": {
                          "hash": "2d1652d67b565cabf2e774668f2598188373e957ef06aa5653bf9bf6fe7fe837",
                          "version": {
                            "binary": "15.0",
                            "schema": "4.70"
                          }
                        },
                        "driver": {
                          "image": "C:\\Windows\\SysmonDrv.sys",
                          "name": "SysmonDrv",
                          "sha256": "e9ea8c0390c65c055d795b301ee50de8f8884313530023918c2eea56de37a525"
                        },
                        "service": {
                          "image": "C:\\Program Files\\Whids\\Sysmon64.exe",
                          "name": "Sysmon64",
                          "sha256": "b448cd80b09fa43a3848f5181362ac52ffcb283f88693b68f1a0e4e6ae932863"
                        },
                        "version": "v13.23"
                      },
                      "system": {
                        "manufacturer": "innotek GmbH",
                        "name": "VirtualBox",
                        "virtual": true
                      }
                    },
                    "uuid": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Endpoint Management"
        ],
        "summary": "Modify an existing endpoint",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "showkey",
            "in": "query",
            "description": "Show endpoint key in response",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          },
          {
            "name": "newkey",
            "in": "query",
            "description": "Generate a new key for endpoint",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "requestBody": {
          "description": "Fields to modify. NB: Not all the fields can be modified",
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "Config": {
                    "type": "object",
                    "properties": {
                      "Actions": {
                        "type": "object",
                        "properties": {
                          "AvailableActions": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "Critical": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "High": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "Low": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "Medium": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "AuditConfig": {
                        "type": "object",
                        "properties": {
                          "AuditDirs": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "AuditPolicies": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "Enable": {
                            "type": "boolean"
                          }
                        }
                      },
                      "CanariesConfig": {
                        "type": "object",
                        "properties": {
                          "Actions": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "Canaries": {
                            "type": "array",
                            "items": {
                              "type": "object",
                              "properties": {
                                "Delete": {
                                  "type": "boolean"
                                },
                                "Directories": {
                                  "type": "array",
                                  "items": {
                                    "type": "string"
                                  }
                                },
                                "Files": {
                                  "type": "array",
                                  "items": {
                                    "type": "string"
                                  }
                                },
                                "HideDirectories": {
                                  "type": "boolean"
                                },
                                "HideFiles": {
                                  "type": "boolean"
                                },
                                "SetAuditACL": {
                                  "type": "boolean"
                                }
                              }
                            }
                          },
                          "Enable": {
                            "type": "boolean"
                          },
                          "Whitelist": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "CritTresh": {
                        "type": "integer",
                        "format": "int64"
                      },
                      "DatabasePath": {
                        "type": "string"
                      },
                      "Dump": {
                        "type": "object",
                        "properties": {
                          "Compression": {
                            "type": "boolean"
                          },
                          "Dir": {
                            "type": "string"
                          },
                          "DumpUntracked": {
                            "type": "boolean"
                          },
                          "MaxDumps": {
                            "type": "integer",
                            "format": "int64"
                          }
                        }
                      },
                      "EnableFiltering": {
                        "type": "boolean"
                      },
                      "EnableHooks": {
                        "type": "boolean"
                      },
                      "Endpoint": {
                        "type": "boolean"
                      },
                      "EtwConfig": {
                        "type": "object",
                        "properties": {
                          "Providers": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "Traces": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "FwdConfig": {
                        "type": "object",
                        "properties": {
                          "Client": {
                            "type": "object",
                            "properties": {
                              "Host": {
                                "type": "string"
                              },
                              "Key": {
                                "type": "string"
                              },
                              "MaxUploadSize": {
                                "type": "integer",
                                "format": "int64"
                              },
                              "Port": {
                                "type": "integer",
                                "format": "int64"
                              },
                              "Proto": {
                                "type": "string"
                              },
                              "ServerFingerprint": {
                                "type": "string"
                              },
                              "ServerKey": {
                                "type": "string"
                              },
                              "UUID": {
                                "type": "string"
                              },
                              "Unsafe": {
                                "type": "boolean"
                              }
                            }
                          },
                          "Local": {
                            "type": "boolean"
                          },
                          "Logging": {
                            "type": "object",
                            "properties": {
                              "Dir": {
                                "type": "string"
                              },
                              "RotationInterval": {
                                "type": "object"
                              }
                            }
                          }
                        }
                      },
                      "LogAll": {
                        "type": "boolean"
                      },
                      "Logfile": {
                        "type": "string"
                      },
                      "Report": {
                        "type": "object",
                        "properties": {
                          "CommandTimeout": {
                            "type": "object"
                          },
                          "Commands": {
                            "type": "array",
                            "items": {
                              "type": "object",
                              "properties": {
                                "args": {
                                  "type": "array",
                                  "items": {
                                    "type": "string"
                                  }
                                },
                                "description": {
                                  "type": "string"
                                },
                                "error": {
                                  "type": "string"
                                },
                                "expect-json": {
                                  "type": "boolean"
                                },
                                "name": {
                                  "type": "string"
                                },
                                "stderr": {
                                  "type": "string",
                                  "format": "binary"
                                },
                                "stdout": {
                                  "type": "object"
                                },
                                "timeout": {
                                  "type": "object"
                                },
                                "timestamp": {
                                  "type": "string",
                                  "format": "date"
                                }
                              }
                            }
                          },
                          "EnableReporting": {
                            "type": "boolean"
                          },
                          "OSQuery": {
                            "type": "object",
                            "properties": {
                              "Tables": {
                                "type": "array",
                                "items": {
                                  "type": "string"
                                }
                              }
                            }
                          }
                        }
                      },
                      "RulesConfig": {
                        "type": "object",
                        "properties": {
                          "ContainersDB": {
                            "type": "string"
                          },
                          "RulesDB": {
                            "type": "string"
                          },
                          "UpdateInterval": {
                            "type": "object"
                          }
                        }
                      },
                      "Sysmon": {
                        "type": "object",
                        "properties": {
                          "ArchiveDirectory": {
                            "type": "string"
                          },
                          "Bin": {
                            "type": "string"
                          },
                          "CleanArchived": {
                            "type": "boolean"
                          }
                        }
                      }
                    }
                  },
                  "Item": {
                    "type": "object"
                  },
                  "command": {
                    "type": "object",
                    "properties": {
                      "args": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "background": {
                        "type": "boolean"
                      },
                      "completed": {
                        "type": "boolean"
                      },
                      "drop": {
                        "type": "array",
                        "items": {
                          "type": "object",
                          "properties": {
                            "data": {
                              "type": "string",
                              "format": "binary"
                            },
                            "error": {
                              "type": "string"
                            },
                            "name": {
                              "type": "string"
                            },
                            "uuid": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "error": {
                        "type": "string"
                      },
                      "expect-json": {
                        "type": "boolean"
                      },
                      "fetch": {
                        "type": "object",
                        "properties": {
                          "key(string)": {
                            "type": "object",
                            "properties": {
                              "data": {
                                "type": "string",
                                "format": "binary"
                              },
                              "error": {
                                "type": "string"
                              },
                              "name": {
                                "type": "string"
                              },
                              "uuid": {
                                "type": "string"
                              }
                            }
                          }
                        }
                      },
                      "json": {
                        "type": "object"
                      },
                      "name": {
                        "type": "string"
                      },
                      "sent": {
                        "type": "boolean"
                      },
                      "sent-time": {
                        "type": "string",
                        "format": "date"
                      },
                      "stderr": {
                        "type": "string",
                        "format": "binary"
                      },
                      "stdout": {
                        "type": "string",
                        "format": "binary"
                      },
                      "timeout": {
                        "type": "object"
                      },
                      "uuid": {
                        "type": "string"
                      }
                    }
                  },
                  "criticality": {
                    "type": "integer",
                    "format": "int64"
                  },
                  "group": {
                    "type": "string"
                  },
                  "hostname": {
                    "type": "string"
                  },
                  "ip": {
                    "type": "string"
                  },
                  "key": {
                    "type": "string"
                  },
                  "last-connection": {
                    "type": "string",
                    "format": "date"
                  },
                  "last-detection": {
                    "type": "string",
                    "format": "date"
                  },
                  "last-event": {
                    "type": "string",
                    "format": "date"
                  },
                  "score": {
                    "type": "number",
                    "format": "double"
                  },
                  "status": {
                    "type": "string"
                  },
                  "system-info": {
                    "type": "object",
                    "properties": {
                      "bios": {
                        "type": "object",
                        "properties": {
                          "date": {
                            "type": "string"
                          },
                          "version": {
                            "type": "string"
                          }
                        }
                      },
                      "cpu": {
                        "type": "object",
                        "properties": {
                          "count": {
                            "type": "integer",
                            "format": "int64"
                          },
                          "name": {
                            "type": "string"
                          }
                        }
                      },
                      "edr": {
                        "type": "object",
                        "properties": {
                          "commit": {
                            "type": "string"
                          },
                          "version": {
                            "type": "string"
                          }
                        }
                      },
                      "error": {
                        "type": "object"
                      },
                      "os": {
                        "type": "object",
                        "properties": {
                          "build": {
                            "type": "string"
                          },
                          "edition": {
                            "type": "string"
                          },
                          "name": {
                            "type": "string"
                          },
                          "product": {
                            "type": "string"
                          },
                          "version": {
                            "type": "string"
                          }
                        }
                      },
                      "sysmon": {
                        "type": "object",
                        "properties": {
                          "config": {
                            "type": "object",
                            "properties": {
                              "hash": {
                                "type": "string"
                              },
                              "version": {
                                "type": "object",
                                "properties": {
                                  "binary": {
                                    "type": "string"
                                  },
                                  "schema": {
                                    "type": "string"
                                  }
                                }
                              }
                            }
                          },
                          "driver": {
                            "type": "object",
                            "properties": {
                              "image": {
                                "type": "string"
                              },
                              "name": {
                                "type": "string"
                              },
                              "sha256": {
                                "type": "string"
                              }
                            }
                          },
                          "service": {
                            "type": "object",
                            "properties": {
                              "image": {
                                "type": "string"
                              },
                              "name": {
                                "type": "string"
                              },
                              "sha256": {
                                "type": "string"
                              }
                            }
                          },
                          "version": {
                            "type": "string"
                          }
                        }
                      },
                      "system": {
                        "type": "object",
                        "properties": {
                          "manufacturer": {
                            "type": "string"
                          },
                          "name": {
                            "type": "string"
                          },
                          "virtual": {
                            "type": "boolean"
                          }
                        }
                      }
                    }
                  },
                  "uuid": {
                    "type": "string"
                  }
                }
              },
              "example": {
                "uuid": "",
                "hostname": "",
                "ip": "",
                "group": "New Group",
                "criticality": 0,
                "key": "New Key",
                "score": 0,
                "status": "New Status",
                "Config": null,
                "last-event": "0001-01-01T00:00:00Z",
                "last-detection": "0001-01-01T00:00:00Z",
                "last-connection": "0001-01-01T00:00:00Z"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "Config": {
                      "Actions": {
                        "AvailableActions": [],
                        "Critical": [],
                        "High": [],
                        "Low": [],
                        "Medium": []
                      },
                      "AuditConfig": {
                        "AuditDirs": [],
                        "AuditPolicies": [],
                        "Enable": false
                      },
                      "CanariesConfig": {
                        "Actions": [],
                        "Canaries": [],
                        "Enable": false,
                        "Whitelist": []
                      },
                      "CritTresh": 0,
                      "DatabasePath": "",
                      "Dump": {
                        "Compression": false,
                        "Dir": "",
                        "DumpUntracked": false,
                        "MaxDumps": 0
                      },
                      "EnableFiltering": false,
                      "EnableHooks": false,
                      "Endpoint": false,
                      "EtwConfig": {
                        "Providers": [],
                        "Traces": []
                      },
                      "FwdConfig": {
                        "Client": {
                          "Host": "",
                          "Key": "",
                          "MaxUploadSize": 0,
                          "Port": 0,
                          "Proto": "",
                          "ServerFingerprint": "",
                          "ServerKey": "",
                          "UUID": "",
                          "Unsafe": false
                        },
                        "Local": false,
                        "Logging": {
                          "Dir": "",
                          "RotationInterval": 0
                        }
                      },
                      "LogAll": false,
                      "Logfile": "",
                      "Report": {
                        "CommandTimeout": 0,
                        "Commands": [],
                        "EnableReporting": false,
                        "OSQuery": {
                          "Tables": []
                        }
                      },
                      "RulesConfig": {
                        "ContainersDB": "",
                        "RulesDB": "",
                        "UpdateInterval": 0
                      },
                      "Sysmon": {
                        "ArchiveDirectory": "",
                        "Bin": "",
                        "CleanArchived": false
                      }
                    },
                    "command": {
                      "args": [],
                      "background": false,
                      "completed": true,
                      "drop": [],
                      "error": "",
                      "expect-json": false,
                      "fetch": {},
                      "json": null,
                      "name": "",
                      "sent": true,
                      "sent-time": "2022-07-26T12:16:09.408987389+02:00",
                      "stderr": "",
                      "stdout": "",
                      "timeout": 0,
                      "uuid": ""
                    },
                    "criticality": 0,
                    "group": "New Group",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-07-26T10:16:09.409830822Z",
                    "last-detection": "2022-07-26T12:16:08.351197299+02:00",
                    "last-event": "2022-07-26T12:16:08.351197299+02:00",
                    "score": 0,
                    "status": "New Status",
                    "system-info": {
                      "bios": {
                        "date": "12/01/2006",
                        "version": "VirtualBox"
                      },
                      "cpu": {
                        "count": 4,
                        "name": "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
                      },
                      "edr": {
                        "commit": "deadbeeeeeeeeeeeeeeeeef",
                        "version": "major.minor.patch"
                      },
                      "error": null,
                      "os": {
                        "build": "18362",
                        "edition": "Enterprise",
                        "name": "windows",
                        "product": "Windows 10 Pro",
                        "version": "10.0.18362"
                      },
                      "sysmon": {
                        "config": {
                          "hash": "2d1652d67b565cabf2e774668f2598188373e957ef06aa5653bf9bf6fe7fe837",
                          "version": {
                            "binary": "15.0",
                            "schema": "4.70"
                          }
                        },
                        "driver": {
                          "image": "C:\\Windows\\SysmonDrv.sys",
                          "name": "SysmonDrv",
                          "sha256": "e9ea8c0390c65c055d795b301ee50de8f8884313530023918c2eea56de37a525"
                        },
                        "service": {
                          "image": "C:\\Program Files\\Whids\\Sysmon64.exe",
                          "name": "Sysmon64",
                          "sha256": "b448cd80b09fa43a3848f5181362ac52ffcb283f88693b68f1a0e4e6ae932863"
                        },
                        "version": "v13.23"
                      },
                      "system": {
                        "manufacturer": "innotek GmbH",
                        "name": "VirtualBox",
                        "virtual": true
                      }
                    },
                    "uuid": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Endpoint Management"
        ],
        "summary": "Delete an existing endpoint",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "Config": {
                      "Actions": {
                        "AvailableActions": [],
                        "Critical": [],
                        "High": [],
                        "Low": [],
                        "Medium": []
                      },
                      "AuditConfig": {
                        "AuditDirs": [],
                        "AuditPolicies": [],
                        "Enable": false
                      },
                      "CanariesConfig": {
                        "Actions": [],
                        "Canaries": [],
                        "Enable": false,
                        "Whitelist": []
                      },
                      "CritTresh": 0,
                      "DatabasePath": "",
                      "Dump": {
                        "Compression": false,
                        "Dir": "",
                        "DumpUntracked": false,
                        "MaxDumps": 0
                      },
                      "EnableFiltering": false,
                      "EnableHooks": false,
                      "Endpoint": false,
                      "EtwConfig": {
                        "Providers": [],
                        "Traces": []
                      },
                      "FwdConfig": {
                        "Client": {
                          "Host": "",
                          "Key": "",
                          "MaxUploadSize": 0,
                          "Port": 0,
                          "Proto": "",
                          "ServerFingerprint": "",
                          "ServerKey": "",
                          "UUID": "",
                          "Unsafe": false
                        },
                        "Local": false,
                        "Logging": {
                          "Dir": "",
                          "RotationInterval": 0
                        }
                      },
                      "LogAll": false,
                      "Logfile": "",
                      "Report": {
                        "CommandTimeout": 0,
                        "Commands": [],
                        "EnableReporting": false,
                        "OSQuery": {
                          "Tables": []
                        }
                      },
                      "RulesConfig": {
                        "ContainersDB": "",
                        "RulesDB": "",
                        "UpdateInterval": 0
                      },
                      "Sysmon": {
                        "ArchiveDirectory": "",
                        "Bin": "",
                        "CleanArchived": false
                      }
                    },
                    "command": {
                      "args": [],
                      "background": false,
                      "completed": true,
                      "drop": [],
                      "error": "",
                      "expect-json": false,
                      "fetch": {},
                      "json": null,
                      "name": "",
                      "sent": true,
                      "sent-time": "2022-07-26T12:16:09.408987389+02:00",
                      "stderr": "",
                      "stdout": "",
                      "timeout": 0,
                      "uuid": ""
                    },
                    "criticality": 0,
                    "group": "New Group",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-07-26T10:16:09.409830822Z",
                    "last-detection": "2022-07-26T12:16:08.351197299+02:00",
                    "last-event": "2022-07-26T12:16:08.351197299+02:00",
                    "score": 0,
                    "status": "New Status",
                    "system-info": {
                      "bios": {
                        "date": "12/01/2006",
                        "version": "VirtualBox"
                      },
                      "cpu": {
                        "count": 4,
                        "name": "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
                      },
                      "edr": {
                        "commit": "deadbeeeeeeeeeeeeeeeeef",
                        "version": "major.minor.patch"
                      },
                      "error": null,
                      "os": {
                        "build": "18362",
                        "edition": "Enterprise",
                        "name": "windows",
                        "product": "Windows 10 Pro",
                        "version": "10.0.18362"
                      },
                      "sysmon": {
                        "config": {
                          "hash": "2d1652d67b565cabf2e774668f2598188373e957ef06aa5653bf9bf6fe7fe837",
                          "version": {
                            "binary": "15.0",
                            "schema": "4.70"
                          }
                        },
                        "driver": {
                          "image": "C:\\Windows\\SysmonDrv.sys",
                          "name": "SysmonDrv",
                          "sha256": "e9ea8c0390c65c055d795b301ee50de8f8884313530023918c2eea56de37a525"
                        },
                        "service": {
                          "image": "C:\\Program Files\\Whids\\Sysmon64.exe",
                          "name": "Sysmon64",
                          "sha256": "b448cd80b09fa43a3848f5181362ac52ffcb283f88693b68f1a0e4e6ae932863"
                        },
                        "version": "v13.23"
                      },
                      "system": {
                        "manufacturer": "innotek GmbH",
                        "name": "VirtualBox",
                        "virtual": true
                      }
                    },
                    "uuid": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/artifacts": {
      "get": {
        "tags": [
          "Artifact Search and Retrieval"
        ],
        "summary": "Artifacts for a single endpoint",
        "parameters": [
          {
            "name": "since",
            "in": "query",
            "description": "Retrieve artifacts received since date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "base-url": "/endpoints/5a92baeb-9384-47d3-92b4-a0db6f9b8c6d/artifacts/5a92baeb-9384-47d3-92b4-a0db6f9b8c6d/3d8441643c204ba9b9dcb5c414b25a3129f66f6c/",
                      "creation": "2022-07-26T10:16:13.747105168Z",
                      "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                      "files": [
                        {
                          "name": "bar.txt",
                          "size": 4,
                          "timestamp": "2022-07-26T10:16:13.747105168Z"
                        },
                        {
                          "name": "foo.txt",
                          "size": 4,
                          "timestamp": "2022-07-26T10:16:13.747105168Z"
                        }
                      ],
                      "modification": "2022-07-26T10:16:13.747105168Z",
                      "process-guid": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/artifacts/{pguid}/{ehash}/{filename}": {
      "get": {
        "tags": [
          "Artifact Search and Retrieval"
        ],
        "summary": "Retrieve the content of an artifact",
        "parameters": [
          {
            "name": "raw",
            "in": "query",
            "description": "Retrieve raw file content",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          },
          {
            "name": "gunzip",
            "in": "query",
            "description": "Serve gunziped file content",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          },
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "pguid",
            "in": "path",
            "description": "pguid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "ehash",
            "in": "path",
            "description": "ehash path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "filename",
            "in": "path",
            "description": "filename path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": "QmxhaA==",
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/command": {
      "get": {
        "tags": [
          "Endpoint Command Execution"
        ],
        "summary": "Get the result of a command executed on endpoint",
        "parameters": [
          {
            "name": "wait",
            "in": "query",
            "description": "Wait command to end before responding, making the call blocking",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          },
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "args": [
                      "printf",
                      "Hello World"
                    ],
                    "background": false,
                    "completed": true,
                    "drop": [],
                    "error": "",
                    "expect-json": false,
                    "fetch": {},
                    "json": null,
                    "name": "/usr/bin/printf",
                    "sent": true,
                    "sent-time": "2022-07-26T12:16:11.484199786+02:00",
                    "stderr": "",
                    "stdout": "SGVsbG8gV29ybGQ=",
                    "timeout": 0,
                    "uuid": "a11af54b-60cb-ce0d-c869-daa4c97d1521"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Endpoint Command Execution"
        ],
        "summary": "Send a command to be executed by the endpoint",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "description": "Command to be executed. One can also specify files \n\t\t\t\tto drop from the manager to the endpoint prior to command execution \n\t\t\t\tand files to fetch after execution. A timeout for the can also \n\t\t\t\tbe specified, if zero there will be no timeout. For a full list of \n\t\t\t\tavailable EDR specific commands check [documentation](https://github.com/0xrawsec/whids/blob/master/doc/edr-commands.md).",
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "command-line": {
                    "type": "string"
                  },
                  "drop-files": {
                    "type": "array",
                    "items": {
                      "type": "string"
                    }
                  },
                  "fetch-files": {
                    "type": "array",
                    "items": {
                      "type": "string"
                    }
                  },
                  "timeout": {
                    "type": "object"
                  }
                }
              },
              "example": {
                "command-line": "printf \"Hello World\"",
                "fetch-files": null,
                "drop-files": null,
                "timeout": 0
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "Config": {
                      "Actions": {
                        "AvailableActions": [],
                        "Critical": [],
                        "High": [],
                        "Low": [],
                        "Medium": []
                      },
                      "AuditConfig": {
                        "AuditDirs": [],
                        "AuditPolicies": [],
                        "Enable": false
                      },
                      "CanariesConfig": {
                        "Actions": [],
                        "Canaries": [],
                        "Enable": false,
                        "Whitelist": []
                      },
                      "CritTresh": 0,
                      "DatabasePath": "",
                      "Dump": {
                        "Compression": false,
                        "Dir": "",
                        "DumpUntracked": false,
                        "MaxDumps": 0
                      },
                      "EnableFiltering": false,
                      "EnableHooks": false,
                      "Endpoint": false,
                      "EtwConfig": {
                        "Providers": [],
                        "Traces": []
                      },
                      "FwdConfig": {
                        "Client": {
                          "Host": "",
                          "Key": "",
                          "MaxUploadSize": 0,
                          "Port": 0,
                          "Proto": "",
                          "ServerFingerprint": "",
                          "ServerKey": "",
                          "UUID": "",
                          "Unsafe": false
                        },
                        "Local": false,
                        "Logging": {
                          "Dir": "",
                          "RotationInterval": 0
                        }
                      },
                      "LogAll": false,
                      "Logfile": "",
                      "Report": {
                        "CommandTimeout": 0,
                        "Commands": [],
                        "EnableReporting": false,
                        "OSQuery": {
                          "Tables": []
                        }
                      },
                      "RulesConfig": {
                        "ContainersDB": "",
                        "RulesDB": "",
                        "UpdateInterval": 0
                      },
                      "Sysmon": {
                        "ArchiveDirectory": "",
                        "Bin": "",
                        "CleanArchived": false
                      }
                    },
                    "command": {
                      "args": [
                        "Hello World"
                      ],
                      "background": false,
                      "completed": false,
                      "drop": [],
                      "error": "",
                      "expect-json": false,
                      "fetch": {},
                      "json": null,
                      "name": "printf",
                      "sent": false,
                      "sent-time": "0001-01-01T00:00:00Z",
                      "stderr": null,
                      "stdout": null,
                      "timeout": 0,
                      "uuid": "a11af54b-60cb-ce0d-c869-daa4c97d1521"
                    },
                    "criticality": 0,
                    "group": "",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "key": "rG1txTFPuFk22sMEHMelMgNtOqszf7BRw8fIN0BvQpn5VCo8ahXs2dyk7zQNgpRb",
                    "last-connection": "2022-07-26T10:16:10.480698644Z",
                    "last-detection": "2022-07-26T12:16:09.452094893+02:00",
                    "last-event": "2022-07-26T12:16:09.452094893+02:00",
                    "score": 0,
                    "status": "",
                    "system-info": {
                      "bios": {
                        "date": "12/01/2006",
                        "version": "VirtualBox"
                      },
                      "cpu": {
                        "count": 4,
                        "name": "Intel(R) Core(TM) i7-8565U CPU @ 1.80GHz"
                      },
                      "edr": {
                        "commit": "deadbeeeeeeeeeeeeeeeeef",
                        "version": "major.minor.patch"
                      },
                      "error": null,
                      "os": {
                        "build": "18362",
                        "edition": "Enterprise",
                        "name": "windows",
                        "product": "Windows 10 Pro",
                        "version": "10.0.18362"
                      },
                      "sysmon": {
                        "config": {
                          "hash": "2d1652d67b565cabf2e774668f2598188373e957ef06aa5653bf9bf6fe7fe837",
                          "version": {
                            "binary": "15.0",
                            "schema": "4.70"
                          }
                        },
                        "driver": {
                          "image": "C:\\Windows\\SysmonDrv.sys",
                          "name": "SysmonDrv",
                          "sha256": "e9ea8c0390c65c055d795b301ee50de8f8884313530023918c2eea56de37a525"
                        },
                        "service": {
                          "image": "C:\\Program Files\\Whids\\Sysmon64.exe",
                          "name": "Sysmon64",
                          "sha256": "b448cd80b09fa43a3848f5181362ac52ffcb283f88693b68f1a0e4e6ae932863"
                        },
                        "version": "v13.23"
                      },
                      "system": {
                        "manufacturer": "innotek GmbH",
                        "name": "VirtualBox",
                        "virtual": true
                      }
                    },
                    "uuid": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/command/{field}": {
      "get": {
        "tags": [
          "Endpoint Command Execution"
        ],
        "summary": "Retrieve only a field of the command structure",
        "parameters": [
          {
            "name": "wait",
            "in": "query",
            "description": "Wait command to end before responding, making the call blocking",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          },
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "field",
            "in": "path",
            "description": "Field of the Command structure to return",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": "SGVsbG8gV29ybGQ=",
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/detections": {
      "get": {
        "tags": [
          "Endpoint Log Retrieval"
        ],
        "summary": "Retrieve detections logs",
        "parameters": [
          {
            "name": "since",
            "in": "query",
            "description": "Retrieve logs since date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "until",
            "in": "query",
            "description": "Retrieve logs until date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "last",
            "in": "query",
            "description": "Return last logs from duration (ex: '1d' for last day)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "pivot",
            "in": "query",
            "description": "Timestamp to pivot around (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "delta",
            "in": "query",
            "description": "Delta duration used to pivot (ex: '5m' to get logs 5min around pivot) ",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of reports to return",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          },
          {
            "name": "skip",
            "in": "query",
            "description": "Skip number of events",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          },
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "Event": {
                        "Detection": {
                          "Actions": [],
                          "Criticality": 10,
                          "Signature": [
                            "UnknownServices"
                          ]
                        },
                        "EdrData": {
                          "Endpoint": {
                            "Group": "",
                            "Hostname": "OpenHappy",
                            "IP": "127.0.0.1",
                            "UUID": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                          },
                          "Event": {
                            "Detection": true,
                            "Hash": "0f0d61843edd1cdeddb710ecd38c4813d406e8bc",
                            "ReceiptTime": "2022-07-25T13:42:46.388637264Z"
                          }
                        },
                        "EventData": {
                          "Ancestors": "System|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\wininit.exe|C:\\Windows\\System32\\services.exe",
                          "CommandLine": "C:\\Windows\\System32\\VBoxService.exe",
                          "Company": "Oracle Corporation",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Description": "VirtualBox Guest Additions Service",
                          "FileVersion": "6.0.8.130520",
                          "Hashes": "SHA1=AE49D900887E95D7B3040BFD2C888D3439F94035,MD5=3001126B78719A1189A0A5270DA316A0,SHA256=9A66844E7ADA8E2D1D454136D68413CE74D90004BAD754D79DAA1A020A27E86C,IMPHASH=6A98677D1BE25D4274AAA7C9C37E832F",
                          "Image": "C:\\Windows\\System32\\VBoxService.exe",
                          "ImageSize": "2732048",
                          "IntegrityLevel": "System",
                          "LogonGuid": "{515cd0d1-7667-6123-e703-000000000000}",
                          "LogonId": "0x3E7",
                          "OriginalFileName": "VBoxService.exe",
                          "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
                          "ParentImage": "C:\\Windows\\System32\\services.exe",
                          "ParentIntegrityLevel": "System",
                          "ParentProcessGuid": "{515cd0d1-7666-6123-0b00-000000007300}",
                          "ParentProcessId": "692",
                          "ParentServices": "N/A",
                          "ParentUser": "NT AUTHORITY\\SYSTEM",
                          "ProcessGuid": "{515cd0d1-7668-6123-2300-000000007300}",
                          "ProcessId": "1592",
                          "Product": "Oracle VM VirtualBox Guest Additions",
                          "RuleName": "-",
                          "Services": "VBoxService",
                          "TerminalSessionId": "0",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:24.054"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
                          "Correlation": {
                            "ActivityID": "",
                            "RelatedActivityID": ""
                          },
                          "EventID": 1,
                          "Execution": {
                            "ProcessID": 3220,
                            "ThreadID": 3848
                          },
                          "Keywords": {
                            "Name": "",
                            "Value": 9223372036854776000
                          },
                          "Level": {
                            "Name": "Information",
                            "Value": 4
                          },
                          "Opcode": {
                            "Name": "Info",
                            "Value": 0
                          },
                          "Provider": {
                            "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                            "Name": "Microsoft-Windows-Sysmon"
                          },
                          "Task": {
                            "Name": "",
                            "Value": 0
                          },
                          "TimeCreated": {
                            "SystemTime": "2022-07-25T15:42:45.373142764+02:00"
                          }
                        }
                      }
                    },
                    {
                      "Event": {
                        "Detection": {
                          "Actions": [],
                          "Criticality": 4,
                          "Signature": [
                            "SuspiciousService"
                          ]
                        },
                        "EdrData": {
                          "Endpoint": {
                            "Group": "",
                            "Hostname": "OpenHappy",
                            "IP": "127.0.0.1",
                            "UUID": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                          },
                          "Event": {
                            "Detection": true,
                            "Hash": "f4d21ac421927aacd195af9018463ac6e8affeb0",
                            "ReceiptTime": "2022-07-25T13:42:46.389008991Z"
                          }
                        },
                        "EventData": {
                          "Ancestors": "System|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\wininit.exe|C:\\Windows\\System32\\services.exe",
                          "CommandLine": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\NisSrv.exe\"",
                          "Company": "Microsoft Corporation",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Description": "Microsoft Network Realtime Inspection Service",
                          "FileVersion": "4.18.2106.6 (WinBuild.160101.0800)",
                          "Hashes": "SHA1=924E8FFFA0578AD8C9C902148F93AA08088B1870,MD5=3E373AF37BB6A15EBC5C42EB741B1965,SHA256=3E60923E4690397EF38D5C97CF578E6E3D136D7977B8C58C26C2DE0A8552F30F,IMPHASH=22CB254211A4B914EE99372F003D561A",
                          "Image": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\NisSrv.exe",
                          "ImageSize": "2665432",
                          "IntegrityLevel": "System",
                          "LogonGuid": "{515cd0d1-7667-6123-e503-000000000000}",
                          "LogonId": "0x3E5",
                          "OriginalFileName": "NisSrv.exe",
                          "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
                          "ParentImage": "C:\\Windows\\System32\\services.exe",
                          "ParentIntegrityLevel": "System",
                          "ParentProcessGuid": "{515cd0d1-7666-6123-0b00-000000007300}",
                          "ParentProcessId": "692",
                          "ParentServices": "N/A",
                          "ParentUser": "NT AUTHORITY\\SYSTEM",
                          "ProcessGuid": "{515cd0d1-7670-6123-7100-000000007300}",
                          "ProcessId": "5628",
                          "Product": "Microsoft® Windows® Operating System",
                          "RuleName": "-",
                          "Services": "WdNisSvc",
                          "TerminalSessionId": "0",
                          "User": "NT AUTHORITY\\LOCAL SERVICE",
                          "UtcTime": "2021-08-23 10:20:32.460"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
                          "Correlation": {
                            "ActivityID": "",
                            "RelatedActivityID": ""
                          },
                          "EventID": 1,
                          "Execution": {
                            "ProcessID": 3220,
                            "ThreadID": 3848
                          },
                          "Keywords": {
                            "Name": "",
                            "Value": 9223372036854776000
                          },
                          "Level": {
                            "Name": "Information",
                            "Value": 4
                          },
                          "Opcode": {
                            "Name": "Info",
                            "Value": 0
                          },
                          "Provider": {
                            "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                            "Name": "Microsoft-Windows-Sysmon"
                          },
                          "Task": {
                            "Name": "",
                            "Value": 0
                          },
                          "TimeCreated": {
                            "SystemTime": "2022-07-25T15:42:45.373158064+02:00"
                          }
                        }
                      }
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/logs": {
      "get": {
        "tags": [
          "Endpoint Log Retrieval"
        ],
        "summary": "Retrieve any kind of logs (detections + filtered)",
        "parameters": [
          {
            "name": "since",
            "in": "query",
            "description": "Retrieve logs since date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "until",
            "in": "query",
            "description": "Retrieve logs until date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "last",
            "in": "query",
            "description": "Return last logs from duration (ex: '1d' for last day)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "pivot",
            "in": "query",
            "description": "Timestamp to pivot around (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "delta",
            "in": "query",
            "description": "Delta duration used to pivot (ex: '5m' to get logs 5min around pivot) ",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of reports to return",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          },
          {
            "name": "skip",
            "in": "query",
            "description": "Skip number of events",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          },
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "Event": {
                        "EdrData": {
                          "Endpoint": {
                            "Group": "",
                            "Hostname": "OpenHappy",
                            "IP": "127.0.0.1",
                            "UUID": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                          },
                          "Event": {
                            "Detection": false,
                            "Hash": "5f8b190da254450eb36d535c8ebfa519284df7c8",
                            "ReceiptTime": "2022-07-25T13:42:46.385362731Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\system32\\svchost.exe -k appmodel -p -s StateRepository",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "AppResolverUX.App",
                          "EventType": "SetValue",
                          "Image": "C:\\Windows\\system32\\svchost.exe",
                          "ImageHashes": "SHA1=75C5A97F521F760E32A4A9639A653EED862E9C61,MD5=9520A99E77D6196D0D09833146424113,SHA256=DD191A5B23DF92E12A8852291F9FB5ED594B76A28A5A464418442584AFD1E048,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69",
                          "ImageSignature": "?",
                          "ImageSignatureStatus": "?",
                          "ImageSigned": "false",
                          "IntegrityLevel": "System",
                          "ProcessGuid": "{515cd0d1-7668-6123-3c00-000000007300}",
                          "ProcessId": "2556",
                          "ProcessThreatScore": "0",
                          "RuleName": "-",
                          "Services": "StateRepository",
                          "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\Application\\Data\\3\\Entrypoint",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:30.123"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
                          "Correlation": {
                            "ActivityID": "",
                            "RelatedActivityID": ""
                          },
                          "EventID": 13,
                          "Execution": {
                            "ProcessID": 3220,
                            "ThreadID": 3848
                          },
                          "Keywords": {
                            "Name": "",
                            "Value": 9223372036854776000
                          },
                          "Level": {
                            "Name": "Information",
                            "Value": 4
                          },
                          "Opcode": {
                            "Name": "Info",
                            "Value": 0
                          },
                          "Provider": {
                            "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                            "Name": "Microsoft-Windows-Sysmon"
                          },
                          "Task": {
                            "Name": "",
                            "Value": 0
                          },
                          "TimeCreated": {
                            "SystemTime": "2022-07-25T15:42:45.372403048+02:00"
                          }
                        }
                      }
                    },
                    {
                      "Event": {
                        "EdrData": {
                          "Endpoint": {
                            "Group": "",
                            "Hostname": "OpenHappy",
                            "IP": "127.0.0.1",
                            "UUID": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d"
                          },
                          "Event": {
                            "Detection": false,
                            "Hash": "15c800b58e6f2460cb82e157ce5e30465cba2e3c",
                            "ReceiptTime": "2022-07-25T13:42:46.385713163Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\system32\\svchost.exe -k appmodel -p -s StateRepository",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "DWORD (0x00000001)",
                          "EventType": "SetValue",
                          "Image": "C:\\Windows\\system32\\svchost.exe",
                          "ImageHashes": "SHA1=75C5A97F521F760E32A4A9639A653EED862E9C61,MD5=9520A99E77D6196D0D09833146424113,SHA256=DD191A5B23DF92E12A8852291F9FB5ED594B76A28A5A464418442584AFD1E048,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69",
                          "ImageSignature": "?",
                          "ImageSignatureStatus": "?",
                          "ImageSigned": "false",
                          "IntegrityLevel": "System",
                          "ProcessGuid": "{515cd0d1-7668-6123-3c00-000000007300}",
                          "ProcessId": "2556",
                          "ProcessThreatScore": "0",
                          "RuleName": "-",
                          "Services": "StateRepository",
                          "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\Package\\Data\\1d2\\Volume",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:29.865"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
                          "Correlation": {
                            "ActivityID": "",
                            "RelatedActivityID": ""
                          },
                          "EventID": 13,
                          "Execution": {
                            "ProcessID": 3220,
                            "ThreadID": 3848
                          },
                          "Keywords": {
                            "Name": "",
                            "Value": 9223372036854776000
                          },
                          "Level": {
                            "Name": "Information",
                            "Value": 4
                          },
                          "Opcode": {
                            "Name": "Info",
                            "Value": 0
                          },
                          "Provider": {
                            "Guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
                            "Name": "Microsoft-Windows-Sysmon"
                          },
                          "Task": {
                            "Name": "",
                            "Value": 0
                          },
                          "TimeCreated": {
                            "SystemTime": "2022-07-25T15:42:45.372403541+02:00"
                          }
                        }
                      }
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/report": {
      "get": {
        "tags": [
          "Detection Reports"
        ],
        "summary": "Retrieve report for a single endpoint",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alert-count": 50,
                    "alert-criticality-metric": 0,
                    "avg-alert-criticality": 0,
                    "avg-signature-criticality": 0,
                    "bounded-score": 0,
                    "count-by-signature": {
                      "DefenderConfigChanged": 6,
                      "NewAutorun": 27,
                      "SuspiciousService": 4,
                      "UnknownServices": 7,
                      "UntrustedDriverLoaded": 6
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-07-26T12:16:11.570582416+02:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "NewAutorun",
                      "UnknownServices",
                      "SuspiciousService",
                      "DefenderConfigChanged",
                      "UntrustedDriverLoaded"
                    ],
                    "start-time": "2022-07-26T12:16:11.5690665+02:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-07-26T12:16:11.572098332+02:00",
                    "sum-alert-criticality": 0,
                    "sum-rule-criticality": 0,
                    "tactics": null,
                    "techniques": null
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Detection Reports"
        ],
        "summary": "Delete and archive a report for a single endpoint",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "alert-count": 50,
                    "alert-criticality-metric": 0,
                    "avg-alert-criticality": 0,
                    "avg-signature-criticality": 0,
                    "bounded-score": 0,
                    "count-by-signature": {
                      "DefenderConfigChanged": 6,
                      "NewAutorun": 27,
                      "SuspiciousService": 4,
                      "UnknownServices": 7,
                      "UntrustedDriverLoaded": 6
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-07-26T12:16:11.570582416+02:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "NewAutorun",
                      "UnknownServices",
                      "SuspiciousService",
                      "DefenderConfigChanged",
                      "UntrustedDriverLoaded"
                    ],
                    "start-time": "2022-07-26T12:16:11.5690665+02:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-07-26T12:16:11.572098332+02:00",
                    "sum-alert-criticality": 0,
                    "sum-rule-criticality": 0,
                    "tactics": null,
                    "techniques": null
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/endpoints/{uuid}/report/archive": {
      "get": {
        "tags": [
          "Detection Reports"
        ],
        "summary": "Get archived reports",
        "parameters": [
          {
            "name": "since",
            "in": "query",
            "description": "Retrieve report since date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "until",
            "in": "query",
            "description": "Retrieve report until date (RFC3339)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string",
              "format": "date"
            }
          },
          {
            "name": "last",
            "in": "query",
            "description": "Return last reports from duration (ex: '1d' for last day)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "limit",
            "in": "query",
            "description": "Maximum number of reports to return",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "integer",
              "format": "int64"
            }
          },
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "alert-count": 50,
                      "alert-criticality-metric": 0,
                      "archived-time": "2022-07-26T12:16:12.611066041+02:00",
                      "avg-alert-criticality": 0,
                      "avg-signature-criticality": 0,
                      "bounded-score": 0,
                      "count-by-signature": {
                        "DefenderConfigChanged": 6,
                        "NewAutorun": 27,
                        "SuspiciousService": 4,
                        "UnknownServices": 7,
                        "UntrustedDriverLoaded": 6
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-07-26T12:16:11.570582416+02:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "NewAutorun",
                        "UnknownServices",
                        "SuspiciousService",
                        "DefenderConfigChanged",
                        "UntrustedDriverLoaded"
                      ],
                      "start-time": "2022-07-26T12:16:11.5690665+02:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-07-26T12:16:11.572098332+02:00",
                      "sum-alert-criticality": 0,
                      "sum-rule-criticality": 0,
                      "tactics": null,
                      "techniques": null
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/iocs": {
      "get": {
        "tags": [
          "IoC Management (control IoCs pushed on Endpoints)"
        ],
        "summary": "Query IoCs loaded on manager and currently pushed to endpoints.\n\t\t\t\tQuery parameters can be used to restrict the search. Search criteria are\n\t\t\t\tORed together.",
        "parameters": [
          {
            "name": "uuid",
            "in": "query",
            "description": "Filter by uuid",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "guuid",
            "in": "query",
            "description": "Filter by group uuid\n\t\t\t\t\t(used to group IoCs, from the same event for example)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "source",
            "in": "query",
            "description": "Filter by source",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "value",
            "in": "query",
            "description": "Filter by value",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "type",
            "in": "query",
            "description": "Filter by type",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "guuid": "d89f8c3e-731a-3da1-13bf-be45605f8ae3",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "df040f2a-6720-c709-7230-3ee5da9f05ce",
                      "value": "some.random.domain"
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "IoC Management (control IoCs pushed on Endpoints)"
        ],
        "summary": "Add IoCs to be pushed on endpoints for detection",
        "requestBody": {
          "content": {
            "application/json": {
              "schema": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "Item": {
                      "type": "object"
                    },
                    "guuid": {
                      "type": "string"
                    },
                    "source": {
                      "type": "string"
                    },
                    "type": {
                      "type": "string"
                    },
                    "uuid": {
                      "type": "string"
                    },
                    "value": {
                      "type": "string"
                    }
                  }
                }
              },
              "example": [
                {
                  "uuid": "df040f2a-6720-c709-7230-3ee5da9f05ce",
                  "guuid": "d89f8c3e-731a-3da1-13bf-be45605f8ae3",
                  "source": "XyzTIProvider",
                  "value": "some.random.domain",
                  "type": "domain"
                }
              ]
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "guuid": "d89f8c3e-731a-3da1-13bf-be45605f8ae3",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "df040f2a-6720-c709-7230-3ee5da9f05ce",
                      "value": "some.random.domain"
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "IoC Management (control IoCs pushed on Endpoints)"
        ],
        "summary": "Delete IoCs from manager, modulo a synchronization delay, endpoints should \n\t\t\tstop using those for detection. Query parameters can be used to select IoCs to delete.\n\t\t\tDeletion criteria are ANDed together.",
        "parameters": [
          {
            "name": "uuid",
            "in": "query",
            "description": "Filter by uuid",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "guuid",
            "in": "query",
            "description": "Filter by group uuid\n\t\t\t\t\t(used to group IoCs, from the same event for example)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "source",
            "in": "query",
            "description": "Filter by source",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "value",
            "in": "query",
            "description": "Filter by value",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "type",
            "in": "query",
            "description": "Filter by type",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": null,
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/rules": {
      "get": {
        "tags": [
          "Rules Management"
        ],
        "summary": "Get rules loaded on endpoints",
        "parameters": [
          {
            "name": "name",
            "in": "query",
            "description": "Regex matching the names of the rules to retrieve",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "filters",
            "in": "query",
            "description": "Show only filters (rules used to filter-in logs)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "Actions": [
                        "memdump",
                        "kill"
                      ],
                      "Condition": "$foo or $bar",
                      "Matches": [
                        "$foo: Image ~= 'C:\\\\Malware.exe'",
                        "$bar: TargetFilename ~= 'C:\\\\config.txt'"
                      ],
                      "Meta": {
                        "Computers": null,
                        "Criticality": 10,
                        "Disable": false,
                        "Events": {
                          "Microsoft-Windows-Sysmon/Operational": [
                            11,
                            23,
                            26
                          ]
                        },
                        "Filter": false,
                        "Schema": "2.0.0"
                      },
                      "Name": "TestRule",
                      "Tags": null
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Rules Management"
        ],
        "summary": "Add or modify a rule",
        "parameters": [
          {
            "name": "update",
            "in": "query",
            "description": "Update rule if already existing",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "requestBody": {
          "description": "Rule to add to the manager",
          "content": {
            "application/json": {
              "schema": {
                "type": "array",
                "items": {
                  "type": "object",
                  "properties": {
                    "Actions": {
                      "type": "array",
                      "items": {
                        "type": "string"
                      }
                    },
                    "Condition": {
                      "type": "string"
                    },
                    "Matches": {
                      "type": "array",
                      "items": {
                        "type": "string"
                      }
                    },
                    "Meta": {
                      "type": "object",
                      "properties": {
                        "ATTACK": {
                          "type": "array",
                          "items": {
                            "type": "object",
                            "properties": {
                              "": {
                                "type": "string"
                              },
                              "ID": {
                                "type": "string"
                              },
                              "Reference": {
                                "type": "string"
                              },
                              "Tactic": {
                                "type": "string"
                              }
                            }
                          }
                        },
                        "Computers": {
                          "type": "array",
                          "items": {
                            "type": "string"
                          }
                        },
                        "Criticality": {
                          "type": "integer",
                          "format": "int64"
                        },
                        "Disable": {
                          "type": "boolean"
                        },
                        "Events": {
                          "type": "object",
                          "properties": {
                            "key(string)": {
                              "type": "array",
                              "items": {
                                "type": "integer",
                                "format": "int64"
                              }
                            }
                          }
                        },
                        "Filter": {
                          "type": "boolean"
                        },
                        "Schema": {
                          "type": "object",
                          "properties": {
                            "Major": {
                              "type": "integer",
                              "format": "int64"
                            },
                            "Minor": {
                              "type": "integer",
                              "format": "int64"
                            },
                            "Patch": {
                              "type": "integer",
                              "format": "int64"
                            }
                          }
                        }
                      }
                    },
                    "Name": {
                      "type": "string"
                    },
                    "Tags": {
                      "type": "array",
                      "items": {
                        "type": "string"
                      }
                    }
                  }
                }
              },
              "example": [
                {
                  "Name": "TestRule",
                  "Tags": null,
                  "Meta": {
                    "Events": {
                      "Microsoft-Windows-Sysmon/Operational": [
                        11,
                        23,
                        26
                      ]
                    },
                    "Computers": null,
                    "Criticality": 10,
                    "Disable": false,
                    "Filter": false,
                    "Schema": "2.0.0"
                  },
                  "Matches": [
                    "$foo: Image ~= 'C:\\\\Malware.exe'",
                    "$bar: TargetFilename ~= 'C:\\\\config.txt'"
                  ],
                  "Condition": "$foo or $bar",
                  "Actions": [
                    "memdump",
                    "kill"
                  ]
                }
              ]
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "Actions": [
                        "memdump",
                        "kill"
                      ],
                      "Condition": "$foo or $bar",
                      "Matches": [
                        "$foo: Image ~= 'C:\\\\Malware.exe'",
                        "$bar: TargetFilename ~= 'C:\\\\config.txt'"
                      ],
                      "Meta": {
                        "Computers": null,
                        "Criticality": 10,
                        "Disable": false,
                        "Events": {
                          "Microsoft-Windows-Sysmon/Operational": [
                            11,
                            23,
                            26
                          ]
                        },
                        "Filter": false,
                        "Schema": "2.0.0"
                      },
                      "Name": "TestRule",
                      "Tags": null
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Rules Management"
        ],
        "summary": "Delete rules from manager",
        "parameters": [
          {
            "name": "name",
            "in": "query",
            "description": "Name of the rule to delete. To avoid mistakes, this\n\t\t\t\tparameter cannot be a regex.",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "Actions": [
                        "memdump",
                        "kill"
                      ],
                      "Condition": "$foo or $bar",
                      "Matches": [
                        "$foo: Image ~= 'C:\\\\Malware.exe'",
                        "$bar: TargetFilename ~= 'C:\\\\config.txt'"
                      ],
                      "Meta": {
                        "Computers": null,
                        "Criticality": 10,
                        "Disable": false,
                        "Events": {
                          "Microsoft-Windows-Sysmon/Operational": [
                            11,
                            23,
                            26
                          ]
                        },
                        "Filter": false,
                        "Schema": "2.0.0"
                      },
                      "Name": "TestRule",
                      "Tags": null
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/stats": {
      "get": {
        "tags": [
          "Statistics about the manager"
        ],
        "summary": "Get statistics",
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "endpoint-count": 1,
                    "rule-count": 0
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/users": {
      "get": {
        "tags": [
          "Admin API User's Management"
        ],
        "summary": "List all users",
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": [
                    {
                      "description": "",
                      "group": "",
                      "identifier": "test",
                      "key": "plM6aQxHK74KL4MGlHL8OmYgRHiofhuKdid0PRYX7fTi6OrfQfmVUOOjhlnYBPCX",
                      "uuid": ""
                    }
                  ],
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "put": {
        "tags": [
          "Admin API User's Management"
        ],
        "summary": "Create a new user with identifier",
        "parameters": [
          {
            "name": "identifier",
            "in": "query",
            "description": "identifier query parameter",
            "required": true,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "description": "",
                    "group": "",
                    "identifier": "TestAdminUser",
                    "key": "XvObbqUrV9FQIJDpKSEmUPzgzPhzPEucwF8tV8bGgU9ev5VL7gblj47rzqoNfg08",
                    "uuid": "888cb092-a409-5ff4-4312-b30cfa1c0862"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "post": {
        "tags": [
          "Admin API User's Management"
        ],
        "summary": "Create a new user from POST data",
        "requestBody": {
          "description": "Data to create the user with. Fields uuid and key if empty will be generated.",
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "Item": {
                    "type": "object"
                  },
                  "description": {
                    "type": "string"
                  },
                  "group": {
                    "type": "string"
                  },
                  "identifier": {
                    "type": "string"
                  },
                  "key": {
                    "type": "string"
                  },
                  "uuid": {
                    "type": "string"
                  }
                }
              },
              "example": {
                "uuid": "0421fb00-28e4-b36f-2068-abe5201ecdce",
                "identifier": "SecondTestAdmin",
                "key": "ChangeMe",
                "group": "CSIRT",
                "description": "Second admin user"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "description": "Second admin user",
                    "group": "CSIRT",
                    "identifier": "SecondTestAdmin",
                    "key": "ChangeMe",
                    "uuid": "0421fb00-28e4-b36f-2068-abe5201ecdce"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    },
    "/users/{uuid}": {
      "post": {
        "tags": [
          "Admin API User's Management"
        ],
        "summary": "Modify existing admin API user",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "newkey",
            "in": "query",
            "description": "Generate a new random key for user",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "boolean"
            }
          }
        ],
        "requestBody": {
          "description": "Data to update user with",
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "Item": {
                    "type": "object"
                  },
                  "description": {
                    "type": "string"
                  },
                  "group": {
                    "type": "string"
                  },
                  "identifier": {
                    "type": "string"
                  },
                  "key": {
                    "type": "string"
                  },
                  "uuid": {
                    "type": "string"
                  }
                }
              },
              "example": {
                "uuid": "",
                "identifier": "",
                "key": "NewWeakKey",
                "group": "SOC",
                "description": "Second admin user changed"
              }
            }
          },
          "required": true
        },
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "description": "Second admin user changed",
                    "group": "SOC",
                    "identifier": "SecondTestAdmin",
                    "key": "NewWeakKey",
                    "uuid": "0421fb00-28e4-b36f-2068-abe5201ecdce"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      },
      "delete": {
        "tags": [
          "Admin API User's Management"
        ],
        "summary": "Delete an existing admin API user",
        "parameters": [
          {
            "name": "uuid",
            "in": "path",
            "description": "uuid path parameter",
            "required": true,
            "allowEmptyValue": false,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "HTTP 200 response",
            "content": {
              "application/json": {
                "example": {
                  "data": {
                    "description": "Second admin user changed",
                    "group": "SOC",
                    "identifier": "SecondTestAdmin",
                    "key": "NewWeakKey",
                    "uuid": "0421fb00-28e4-b36f-2068-abe5201ecdce"
                  },
                  "error": "",
                  "message": "OK"
                }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "ApiKeyAuth": {
        "type": "apiKey",
        "name": "X-Api-Key",
        "in": "header"
      }
    }
  },
  "security": [
    {
      "ApiKeyAuth": []
    }
  ]
}
`