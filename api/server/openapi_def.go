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
                      "criticality": 0,
                      "group": "",
                      "hostname": "OpenHappy",
                      "ip": "127.0.0.1",
                      "key": "f5s8HgzGzBetvBIHhsT2LrDX0N7sGXobQbxWuxrfjriD6kKarCifHq9HsEyKSPHT",
                      "last-connection": "2022-08-25T15:16:32.049198117Z",
                      "last-detection": "2022-08-25T17:16:30.985842372+02:00",
                      "last-event": "2022-08-25T17:16:30.985842372+02:00",
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
                    "criticality": 0,
                    "group": "",
                    "hostname": "",
                    "ip": "",
                    "key": "aEiMQPYozy80CBttLiWgfCF8zpDgYoIUWNQPKhTwjLWJGKn7YMh914TfDzuGDJRe",
                    "last-connection": "0001-01-01T00:00:00Z",
                    "last-detection": "0001-01-01T00:00:00Z",
                    "last-event": "0001-01-01T00:00:00Z",
                    "score": 0,
                    "status": "",
                    "uuid": "9c379554-6adc-e685-a137-85e058733860"
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
                        "creation": "2022-08-25T15:16:37.677528168Z",
                        "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                        "files": [
                          {
                            "name": "bar.txt",
                            "size": 4,
                            "timestamp": "2022-08-25T15:16:37.677528168Z"
                          },
                          {
                            "name": "foo.txt",
                            "size": 4,
                            "timestamp": "2022-08-25T15:16:37.677528168Z"
                          }
                        ],
                        "modification": "2022-08-25T15:16:37.677528168Z",
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
                        "DefenderConfigChanged": 4,
                        "NewAutorun": 23,
                        "SuspiciousService": 9,
                        "UnknownServices": 9,
                        "UntrustedDriverLoaded": 5
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-08-25T17:16:35.472131213+02:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "DefenderConfigChanged",
                        "SuspiciousService",
                        "NewAutorun",
                        "UntrustedDriverLoaded",
                        "UnknownServices"
                      ],
                      "start-time": "2022-08-25T17:16:35.470679762+02:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-08-25T17:16:35.473582664+02:00",
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
                    "uuid": "6e687d83-0b1c-71d1-c462-590934e8449a"
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
                    "uuid": "6e687d83-0b1c-71d1-c462-590934e8449a"
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
                    "uuid": "6e687d83-0b1c-71d1-c462-590934e8449a"
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
                    "uuid": "27e43f8d-785c-7e10-1969-469bdb795d73"
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
                    "uuid": "27e43f8d-785c-7e10-1969-469bdb795d73"
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
                    "uuid": "27e43f8d-785c-7e10-1969-469bdb795d73"
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
                    "criticality": 0,
                    "group": "",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-08-25T15:16:32.059915491Z",
                    "last-detection": "2022-08-25T17:16:30.985842372+02:00",
                    "last-event": "2022-08-25T17:16:30.985842372+02:00",
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
                  "config": {
                    "type": "object",
                    "properties": {
                      "actions": {
                        "type": "object",
                        "properties": {
                          "available-actions": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "critical": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "high": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "low": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "medium": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "audit": {
                        "type": "object",
                        "properties": {
                          "audit-dirs": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "audit-policies": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "enable": {
                            "type": "boolean"
                          }
                        }
                      },
                      "canaries": {
                        "type": "object",
                        "properties": {
                          "actions": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "enable": {
                            "type": "boolean"
                          },
                          "group": {
                            "type": "array",
                            "items": {
                              "type": "object",
                              "properties": {
                                "delete": {
                                  "type": "boolean"
                                },
                                "directories": {
                                  "type": "array",
                                  "items": {
                                    "type": "string"
                                  }
                                },
                                "files": {
                                  "type": "array",
                                  "items": {
                                    "type": "string"
                                  }
                                },
                                "hide-dirs": {
                                  "type": "boolean"
                                },
                                "hide-files": {
                                  "type": "boolean"
                                },
                                "set-audit-acl": {
                                  "type": "boolean"
                                }
                              }
                            }
                          },
                          "whitelist": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "criticality-treshold": {
                        "type": "integer",
                        "format": "int64"
                      },
                      "db-path": {
                        "type": "string"
                      },
                      "dump": {
                        "type": "object",
                        "properties": {
                          "compression": {
                            "type": "boolean"
                          },
                          "dir": {
                            "type": "string"
                          },
                          "dump-untracked": {
                            "type": "boolean"
                          },
                          "max-dumps": {
                            "type": "integer",
                            "format": "int64"
                          }
                        }
                      },
                      "en-filters": {
                        "type": "boolean"
                      },
                      "en-hooks": {
                        "type": "boolean"
                      },
                      "endpoint": {
                        "type": "boolean"
                      },
                      "etw": {
                        "type": "object",
                        "properties": {
                          "providers": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          },
                          "traces": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "forwarder": {
                        "type": "object",
                        "properties": {
                          "local": {
                            "type": "boolean"
                          },
                          "logging": {
                            "type": "object",
                            "properties": {
                              "dir": {
                                "type": "string"
                              },
                              "rotation-interval": {
                                "type": "object"
                              }
                            }
                          },
                          "manager": {
                            "type": "object",
                            "properties": {
                              "endpoint-key": {
                                "type": "string"
                              },
                              "endpoint-uuid": {
                                "type": "string"
                              },
                              "host": {
                                "type": "string"
                              },
                              "max-upload-size": {
                                "type": "integer",
                                "format": "int64"
                              },
                              "port": {
                                "type": "integer",
                                "format": "int64"
                              },
                              "proto": {
                                "type": "string"
                              },
                              "server-fingerprint": {
                                "type": "string"
                              },
                              "server-key": {
                                "type": "string"
                              },
                              "unsafe": {
                                "type": "boolean"
                              }
                            }
                          }
                        }
                      },
                      "log-all": {
                        "type": "boolean"
                      },
                      "logfile": {
                        "type": "string"
                      },
                      "report": {
                        "type": "object",
                        "properties": {
                          "commands": {
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
                          "en-reporting": {
                            "type": "boolean"
                          },
                          "osquery": {
                            "type": "object",
                            "properties": {
                              "tables": {
                                "type": "array",
                                "items": {
                                  "type": "string"
                                }
                              }
                            }
                          },
                          "timeout": {
                            "type": "object"
                          }
                        }
                      },
                      "rules": {
                        "type": "object",
                        "properties": {
                          "containers-db": {
                            "type": "string"
                          },
                          "rules-db": {
                            "type": "string"
                          },
                          "update-interval": {
                            "type": "object"
                          }
                        }
                      },
                      "sysmon": {
                        "type": "object",
                        "properties": {
                          "archive-directory": {
                            "type": "string"
                          },
                          "bin": {
                            "type": "string"
                          },
                          "clean-archived": {
                            "type": "boolean"
                          }
                        }
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
                    "criticality": 0,
                    "group": "New Group",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-08-25T15:16:32.059915491Z",
                    "last-detection": "2022-08-25T17:16:30.985842372+02:00",
                    "last-event": "2022-08-25T17:16:30.985842372+02:00",
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
                    "criticality": 0,
                    "group": "New Group",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-08-25T15:16:32.059915491Z",
                    "last-detection": "2022-08-25T17:16:30.985842372+02:00",
                    "last-event": "2022-08-25T17:16:30.985842372+02:00",
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
                      "creation": "2022-08-25T15:16:37.677528168Z",
                      "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                      "files": [
                        {
                          "name": "bar.txt",
                          "size": 4,
                          "timestamp": "2022-08-25T15:16:37.677528168Z"
                        },
                        {
                          "name": "foo.txt",
                          "size": 4,
                          "timestamp": "2022-08-25T15:16:37.677528168Z"
                        }
                      ],
                      "modification": "2022-08-25T15:16:37.677528168Z",
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
                    "sent-time": "2022-08-25T17:16:35.356293573+02:00",
                    "stderr": null,
                    "stdout": "SGVsbG8gV29ybGQ=",
                    "timeout": 0,
                    "uuid": "b70a9c39-f3b8-1cde-52c4-82722cc855a6"
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
                      "uuid": "b70a9c39-f3b8-1cde-52c4-82722cc855a6"
                    },
                    "criticality": 0,
                    "group": "",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "key": "IUh6ClwELVvP0XsNPnWkN7UPOE3OlIWcpGXqoYaPWzS73INXNq3rSsyBtWeCNUnS",
                    "last-connection": "2022-08-25T15:16:34.301452975Z",
                    "last-detection": "2022-08-25T17:16:33.245051327+02:00",
                    "last-event": "2022-08-25T17:16:33.245051327+02:00",
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
    "/endpoints/{uuid}/config": {
      "get": {
        "tags": [
          "Endpoint Configuration"
        ],
        "summary": "Get endpoint configuration",
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
            "name": "format",
            "in": "query",
            "description": "Select input and output format (allowed toml, json)",
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
                  "data": {
                    "actions": {
                      "available-actions": null,
                      "critical": [],
                      "high": [],
                      "low": [],
                      "medium": []
                    },
                    "audit": {
                      "audit-dirs": [],
                      "audit-policies": [],
                      "enable": false
                    },
                    "canaries": {
                      "actions": [],
                      "enable": false,
                      "group": null,
                      "whitelist": []
                    },
                    "criticality-treshold": 0,
                    "db-path": "somerandompath",
                    "dump": {
                      "compression": false,
                      "dir": "",
                      "dump-untracked": false,
                      "max-dumps": 0
                    },
                    "en-filters": false,
                    "en-hooks": false,
                    "endpoint": false,
                    "etw": {
                      "providers": [],
                      "traces": []
                    },
                    "forwarder": {
                      "local": false,
                      "logging": {
                        "dir": "",
                        "rotation-interval": 0
                      },
                      "manager": {
                        "endpoint-key": "",
                        "endpoint-uuid": "",
                        "host": "",
                        "max-upload-size": 0,
                        "port": 0,
                        "proto": "",
                        "server-fingerprint": "",
                        "server-key": "",
                        "unsafe": false
                      }
                    },
                    "log-all": false,
                    "logfile": "",
                    "report": {
                      "commands": null,
                      "en-reporting": false,
                      "osquery": {
                        "tables": []
                      },
                      "timeout": 0
                    },
                    "rules": {
                      "containers-db": "",
                      "rules-db": "",
                      "update-interval": 0
                    },
                    "sysmon": {
                      "archive-directory": "",
                      "bin": "",
                      "clean-archived": false
                    }
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
          "Endpoint Configuration"
        ],
        "summary": "Change endpoint configuration",
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
            "name": "format",
            "in": "query",
            "description": "Select input and output format (allowed toml, json)",
            "required": false,
            "allowEmptyValue": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "requestBody": {
          "description": "Configuration content",
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "actions": {
                    "type": "object",
                    "properties": {
                      "available-actions": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "critical": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "high": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "low": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "medium": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      }
                    }
                  },
                  "audit": {
                    "type": "object",
                    "properties": {
                      "audit-dirs": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "audit-policies": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "enable": {
                        "type": "boolean"
                      }
                    }
                  },
                  "canaries": {
                    "type": "object",
                    "properties": {
                      "actions": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "enable": {
                        "type": "boolean"
                      },
                      "group": {
                        "type": "array",
                        "items": {
                          "type": "object",
                          "properties": {
                            "delete": {
                              "type": "boolean"
                            },
                            "directories": {
                              "type": "array",
                              "items": {
                                "type": "string"
                              }
                            },
                            "files": {
                              "type": "array",
                              "items": {
                                "type": "string"
                              }
                            },
                            "hide-dirs": {
                              "type": "boolean"
                            },
                            "hide-files": {
                              "type": "boolean"
                            },
                            "set-audit-acl": {
                              "type": "boolean"
                            }
                          }
                        }
                      },
                      "whitelist": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      }
                    }
                  },
                  "criticality-treshold": {
                    "type": "integer",
                    "format": "int64"
                  },
                  "db-path": {
                    "type": "string"
                  },
                  "dump": {
                    "type": "object",
                    "properties": {
                      "compression": {
                        "type": "boolean"
                      },
                      "dir": {
                        "type": "string"
                      },
                      "dump-untracked": {
                        "type": "boolean"
                      },
                      "max-dumps": {
                        "type": "integer",
                        "format": "int64"
                      }
                    }
                  },
                  "en-filters": {
                    "type": "boolean"
                  },
                  "en-hooks": {
                    "type": "boolean"
                  },
                  "endpoint": {
                    "type": "boolean"
                  },
                  "etw": {
                    "type": "object",
                    "properties": {
                      "providers": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      },
                      "traces": {
                        "type": "array",
                        "items": {
                          "type": "string"
                        }
                      }
                    }
                  },
                  "forwarder": {
                    "type": "object",
                    "properties": {
                      "local": {
                        "type": "boolean"
                      },
                      "logging": {
                        "type": "object",
                        "properties": {
                          "dir": {
                            "type": "string"
                          },
                          "rotation-interval": {
                            "type": "object"
                          }
                        }
                      },
                      "manager": {
                        "type": "object",
                        "properties": {
                          "endpoint-key": {
                            "type": "string"
                          },
                          "endpoint-uuid": {
                            "type": "string"
                          },
                          "host": {
                            "type": "string"
                          },
                          "max-upload-size": {
                            "type": "integer",
                            "format": "int64"
                          },
                          "port": {
                            "type": "integer",
                            "format": "int64"
                          },
                          "proto": {
                            "type": "string"
                          },
                          "server-fingerprint": {
                            "type": "string"
                          },
                          "server-key": {
                            "type": "string"
                          },
                          "unsafe": {
                            "type": "boolean"
                          }
                        }
                      }
                    }
                  },
                  "log-all": {
                    "type": "boolean"
                  },
                  "logfile": {
                    "type": "string"
                  },
                  "report": {
                    "type": "object",
                    "properties": {
                      "commands": {
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
                      "en-reporting": {
                        "type": "boolean"
                      },
                      "osquery": {
                        "type": "object",
                        "properties": {
                          "tables": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            }
                          }
                        }
                      },
                      "timeout": {
                        "type": "object"
                      }
                    }
                  },
                  "rules": {
                    "type": "object",
                    "properties": {
                      "containers-db": {
                        "type": "string"
                      },
                      "rules-db": {
                        "type": "string"
                      },
                      "update-interval": {
                        "type": "object"
                      }
                    }
                  },
                  "sysmon": {
                    "type": "object",
                    "properties": {
                      "archive-directory": {
                        "type": "string"
                      },
                      "bin": {
                        "type": "string"
                      },
                      "clean-archived": {
                        "type": "boolean"
                      }
                    }
                  }
                }
              },
              "example": {
                "db-path": "somerandompath",
                "criticality-treshold": 0,
                "en-hooks": false,
                "en-filters": false,
                "logfile": "",
                "log-all": false,
                "endpoint": false,
                "etw": {
                  "providers": null,
                  "traces": null
                },
                "forwarder": {
                  "local": false,
                  "manager": {
                    "proto": "",
                    "host": "",
                    "port": 0,
                    "endpoint-uuid": "",
                    "endpoint-key": "",
                    "server-key": "",
                    "server-fingerprint": "",
                    "unsafe": false,
                    "max-upload-size": 0
                  },
                  "logging": {
                    "dir": "",
                    "rotation-interval": 0
                  }
                },
                "sysmon": {
                  "bin": "",
                  "archive-directory": "",
                  "clean-archived": false
                },
                "actions": {
                  "available-actions": null,
                  "low": null,
                  "medium": null,
                  "high": null,
                  "critical": null
                },
                "dump": {
                  "dir": "",
                  "max-dumps": 0,
                  "compression": false,
                  "dump-untracked": false
                },
                "report": {
                  "en-reporting": false,
                  "osquery": {
                    "tables": null
                  },
                  "commands": null,
                  "timeout": 0
                },
                "rules": {
                  "rules-db": "",
                  "containers-db": "",
                  "update-interval": 0
                },
                "audit": {
                  "enable": false,
                  "audit-policies": null,
                  "audit-dirs": null
                },
                "canaries": {
                  "enable": false,
                  "actions": null,
                  "whitelist": null,
                  "group": null
                }
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
                    "actions": {
                      "available-actions": null,
                      "critical": null,
                      "high": null,
                      "low": null,
                      "medium": null
                    },
                    "audit": {
                      "audit-dirs": null,
                      "audit-policies": null,
                      "enable": false
                    },
                    "canaries": {
                      "actions": null,
                      "enable": false,
                      "group": null,
                      "whitelist": null
                    },
                    "criticality-treshold": 0,
                    "db-path": "somerandompath",
                    "dump": {
                      "compression": false,
                      "dir": "",
                      "dump-untracked": false,
                      "max-dumps": 0
                    },
                    "en-filters": false,
                    "en-hooks": false,
                    "endpoint": false,
                    "etw": {
                      "providers": null,
                      "traces": null
                    },
                    "forwarder": {
                      "local": false,
                      "logging": {
                        "dir": "",
                        "rotation-interval": 0
                      },
                      "manager": {
                        "endpoint-key": "",
                        "endpoint-uuid": "",
                        "host": "",
                        "max-upload-size": 0,
                        "port": 0,
                        "proto": "",
                        "server-fingerprint": "",
                        "server-key": "",
                        "unsafe": false
                      }
                    },
                    "log-all": false,
                    "logfile": "",
                    "report": {
                      "commands": null,
                      "en-reporting": false,
                      "osquery": {
                        "tables": null
                      },
                      "timeout": 0
                    },
                    "rules": {
                      "containers-db": "",
                      "rules-db": "",
                      "update-interval": 0
                    },
                    "sysmon": {
                      "archive-directory": "",
                      "bin": "",
                      "clean-archived": false
                    }
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
          "Endpoint Configuration"
        ],
        "summary": "Delete endpoint configuration (this causes the endpoint to sync again its current configuration)",
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
            "name": "format",
            "in": "query",
            "description": "Select input and output format (allowed toml, json)",
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
                            "Hash": "812d7326b29a59d6a4aa84623ce052a9b17269ac",
                            "ReceiptTime": "2022-08-25T15:16:30.932036889Z"
                          }
                        },
                        "EventData": {
                          "Ancestors": "System|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\wininit.exe|C:\\Windows\\System32\\services.exe",
                          "CommandLine": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe\"",
                          "Company": "Microsoft Corporation",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Description": "Antimalware Service Executable",
                          "FileVersion": "4.18.2106.6 (WinBuild.160101.0800)",
                          "Hashes": "SHA1=FBF03B5D6DC1A7EDAB0BA8D4DD27291C739E5813,MD5=B1C15F9DB942B373B2FC468B7048E63F,SHA256=1DC05B6DD6281840CEB822604B0E403E499180D636D02EC08AD77B4EB56F1B9C,IMPHASH=8AA2B8727E6858A3557A4C09970B9A5D",
                          "Image": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe",
                          "ImageSize": "136640",
                          "IntegrityLevel": "System",
                          "LogonGuid": "{515cd0d1-7667-6123-e703-000000000000}",
                          "LogonId": "0x3E7",
                          "OriginalFileName": "MsMpEng.exe",
                          "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
                          "ParentImage": "C:\\Windows\\System32\\services.exe",
                          "ParentIntegrityLevel": "System",
                          "ParentProcessGuid": "{515cd0d1-7666-6123-0b00-000000007300}",
                          "ParentProcessId": "692",
                          "ParentServices": "N/A",
                          "ParentUser": "NT AUTHORITY\\SYSTEM",
                          "ProcessGuid": "{515cd0d1-7669-6123-4e00-000000007300}",
                          "ProcessId": "3276",
                          "Product": "Microsoft® Windows® Operating System",
                          "RuleName": "-",
                          "Services": "WinDefend",
                          "TerminalSessionId": "0",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:25.475"
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
                            "SystemTime": "2022-08-25T17:16:29.880615209+02:00"
                          }
                        }
                      }
                    },
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
                            "Hash": "1373ccc3a3f3f97575af79ca8e77ad341cefc177",
                            "ReceiptTime": "2022-08-25T15:16:30.932574287Z"
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
                            "SystemTime": "2022-08-25T17:16:29.880658585+02:00"
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
                            "Hash": "b719cf83208f1d828995cf029761efb55b69dff5",
                            "ReceiptTime": "2022-08-25T15:16:30.925770826Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\system32\\svchost.exe -k appmodel -p -s StateRepository",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy",
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
                          "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\Package\\Data\\21\\InstalledLocation",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:29.754"
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
                            "SystemTime": "2022-08-25T17:16:29.879781042+02:00"
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
                            "Hash": "a381b25f9df0bf5c895e487f61e97fbbb938322f",
                            "ReceiptTime": "2022-08-25T15:16:30.92623972Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Device": "\\Device\\HarddiskVolume2",
                          "Image": "C:\\Windows\\System32\\svchost.exe",
                          "ImageHashes": "SHA1=75C5A97F521F760E32A4A9639A653EED862E9C61,MD5=9520A99E77D6196D0D09833146424113,SHA256=DD191A5B23DF92E12A8852291F9FB5ED594B76A28A5A464418442584AFD1E048,IMPHASH=247B9220E5D9B720A82B2C8B5069AD69",
                          "ImageSignature": "?",
                          "ImageSignatureStatus": "?",
                          "ImageSigned": "false",
                          "IntegrityLevel": "System",
                          "ProcessGuid": "{515cd0d1-766a-6123-5400-000000007300}",
                          "ProcessId": "3788",
                          "ProcessThreatScore": "0",
                          "RuleName": "-",
                          "Services": "StorSvc",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:31.536"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
                          "Correlation": {
                            "ActivityID": "",
                            "RelatedActivityID": ""
                          },
                          "EventID": 9,
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
                            "SystemTime": "2022-08-25T17:16:29.879783302+02:00"
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
                      "DefenderConfigChanged": 4,
                      "NewAutorun": 23,
                      "SuspiciousService": 9,
                      "UnknownServices": 9,
                      "UntrustedDriverLoaded": 5
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-08-25T17:16:35.472131213+02:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "UnknownServices",
                      "DefenderConfigChanged",
                      "SuspiciousService",
                      "NewAutorun",
                      "UntrustedDriverLoaded"
                    ],
                    "start-time": "2022-08-25T17:16:35.470679762+02:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-08-25T17:16:35.473582664+02:00",
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
                      "DefenderConfigChanged": 4,
                      "NewAutorun": 23,
                      "SuspiciousService": 9,
                      "UnknownServices": 9,
                      "UntrustedDriverLoaded": 5
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-08-25T17:16:35.472131213+02:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "UnknownServices",
                      "DefenderConfigChanged",
                      "SuspiciousService",
                      "NewAutorun",
                      "UntrustedDriverLoaded"
                    ],
                    "start-time": "2022-08-25T17:16:35.470679762+02:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-08-25T17:16:35.473582664+02:00",
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
                      "archived-time": "2022-08-25T17:16:36.540475659+02:00",
                      "avg-alert-criticality": 0,
                      "avg-signature-criticality": 0,
                      "bounded-score": 0,
                      "count-by-signature": {
                        "DefenderConfigChanged": 4,
                        "NewAutorun": 23,
                        "SuspiciousService": 9,
                        "UnknownServices": 9,
                        "UntrustedDriverLoaded": 5
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-08-25T17:16:35.472131213+02:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "UnknownServices",
                        "DefenderConfigChanged",
                        "SuspiciousService",
                        "NewAutorun",
                        "UntrustedDriverLoaded"
                      ],
                      "start-time": "2022-08-25T17:16:35.470679762+02:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-08-25T17:16:35.473582664+02:00",
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
                      "guuid": "1bc4351d-8302-6e80-7648-10f8842695a8",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "d673f6ee-4a92-a5f9-a665-c3abc4a8bf87",
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
                  "uuid": "d673f6ee-4a92-a5f9-a665-c3abc4a8bf87",
                  "guuid": "1bc4351d-8302-6e80-7648-10f8842695a8",
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
                      "guuid": "1bc4351d-8302-6e80-7648-10f8842695a8",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "d673f6ee-4a92-a5f9-a665-c3abc4a8bf87",
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
                    "key": "HxQMrEXiGTTBHxcarw4fcsEus8QRpuoE1vc3DGLjx7suOpajDnX1M2DNs7r0aGcf",
                    "uuid": "953c4e69-ba7f-e621-c8f5-db971bdcc313"
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
                "uuid": "b88b47af-6936-49fd-e7ce-4741583ba5bd",
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
                    "uuid": "b88b47af-6936-49fd-e7ce-4741583ba5bd"
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
                    "uuid": "b88b47af-6936-49fd-e7ce-4741583ba5bd"
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
                    "uuid": "b88b47af-6936-49fd-e7ce-4741583ba5bd"
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
