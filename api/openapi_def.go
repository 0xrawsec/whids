package api

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
                      "key": "Gy5IN2aVP4Nkr0TKUmnmDQKVNmppNpwTVa2pb4jQknd3fiMpboSLLvsRgWBMjOMa",
                      "last-connection": "2022-05-18T15:37:04.67962324Z",
                      "last-detection": "2022-05-18T17:37:03.65200333+02:00",
                      "last-event": "2022-05-18T17:37:03.65200333+02:00",
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
                          "commit": "",
                          "version": ""
                        },
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
                    "key": "bRyYR3EsHOS21jH4REpcqeKe71M7WsXKqhBkK2irxFsofl9wzO9R6WVF6ECd1jPw",
                    "last-connection": "0001-01-01T00:00:00Z",
                    "last-detection": "0001-01-01T00:00:00Z",
                    "last-event": "0001-01-01T00:00:00Z",
                    "score": 0,
                    "status": "",
                    "uuid": "c3893f7b-9db3-3681-3ba2-db3e9c80b7a9"
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
                        "creation": "2022-05-18T15:37:08.11753367Z",
                        "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                        "files": [
                          {
                            "name": "bar.txt",
                            "size": 4,
                            "timestamp": "2022-05-18T15:37:08.130867042Z"
                          },
                          {
                            "name": "foo.txt",
                            "size": 4,
                            "timestamp": "2022-05-18T15:37:08.11753367Z"
                          }
                        ],
                        "modification": "2022-05-18T15:37:08.130867042Z",
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
                        "SuspiciousService": 5,
                        "UnknownServices": 7,
                        "UntrustedDriverLoaded": 11
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-05-18T17:37:05.886831053+02:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "SuspiciousService",
                        "DefenderConfigChanged",
                        "NewAutorun",
                        "UnknownServices",
                        "UntrustedDriverLoaded"
                      ],
                      "start-time": "2022-05-18T17:37:05.88545256+02:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-05-18T17:37:05.888209546+02:00",
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
          "Managing OSQueryi binary deployed on endpoints"
        ],
        "summary": "Get information about OSQueryi binary to be deployed on endpoints",
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
                    "uuid": "63410f4c-8e5c-d8b7-5e8c-f2bdb8c8355d"
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
          "Managing OSQueryi binary deployed on endpoints"
        ],
        "summary": "Add or update OSQueryi binary to deploy on all endpoints",
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
                    "uuid": "63410f4c-8e5c-d8b7-5e8c-f2bdb8c8355d"
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
          "Managing OSQueryi binary deployed on endpoints"
        ],
        "summary": "Delete OSQueryi binary from manager server",
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
                    "uuid": "63410f4c-8e5c-d8b7-5e8c-f2bdb8c8355d"
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
          "Manage sysmon deployment"
        ],
        "summary": "Get information about sysmon binary",
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
                    "uuid": "91d77bf6-d147-a036-2ce8-2fe2db274c0a"
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
          "Manage sysmon deployment"
        ],
        "summary": "Add or update sysmon binary to deploy on all endpoints",
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
                    "uuid": "91d77bf6-d147-a036-2ce8-2fe2db274c0a"
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
          "Manage sysmon deployment"
        ],
        "summary": "Delete Sysmon binary",
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
                    "uuid": "91d77bf6-d147-a036-2ce8-2fe2db274c0a"
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
          "Manage sysmon deployment"
        ],
        "summary": "Get a sysmon configuration",
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
          "Manage sysmon deployment"
        ],
        "summary": "Add or update a sysmon configuration",
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
          "Manage sysmon deployment"
        ],
        "summary": "Delete a sysmon configuration",
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
                    "command": {
                      "args": [],
                      "background": false,
                      "completed": false,
                      "drop": [],
                      "error": "",
                      "expect-json": false,
                      "fetch": {},
                      "json": null,
                      "name": "",
                      "sent": false,
                      "sent-time": "0001-01-01T00:00:00Z",
                      "stderr": "",
                      "stdout": "",
                      "timeout": 0,
                      "uuid": ""
                    },
                    "criticality": 0,
                    "group": "",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-05-18T15:37:04.695661935Z",
                    "last-detection": "2022-05-18T17:37:03.65200333+02:00",
                    "last-event": "2022-05-18T17:37:03.65200333+02:00",
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
                        "commit": "",
                        "version": ""
                      },
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
                          "error": {
                            "type": "object"
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
                    "command": {
                      "args": [],
                      "background": false,
                      "completed": false,
                      "drop": [],
                      "error": "",
                      "expect-json": false,
                      "fetch": {},
                      "json": null,
                      "name": "",
                      "sent": false,
                      "sent-time": "0001-01-01T00:00:00Z",
                      "stderr": "",
                      "stdout": "",
                      "timeout": 0,
                      "uuid": ""
                    },
                    "criticality": 0,
                    "group": "New Group",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-05-18T15:37:04.695661935Z",
                    "last-detection": "2022-05-18T17:37:03.65200333+02:00",
                    "last-event": "2022-05-18T17:37:03.65200333+02:00",
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
                        "commit": "",
                        "version": ""
                      },
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
                    "command": {
                      "args": [],
                      "background": false,
                      "completed": false,
                      "drop": [],
                      "error": "",
                      "expect-json": false,
                      "fetch": {},
                      "json": null,
                      "name": "",
                      "sent": false,
                      "sent-time": "0001-01-01T00:00:00Z",
                      "stderr": "",
                      "stdout": "",
                      "timeout": 0,
                      "uuid": ""
                    },
                    "criticality": 0,
                    "group": "New Group",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "last-connection": "2022-05-18T15:37:04.695661935Z",
                    "last-detection": "2022-05-18T17:37:03.65200333+02:00",
                    "last-event": "2022-05-18T17:37:03.65200333+02:00",
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
                        "commit": "",
                        "version": ""
                      },
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
                      "creation": "2022-05-18T15:37:08.11753367Z",
                      "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                      "files": [
                        {
                          "name": "bar.txt",
                          "size": 4,
                          "timestamp": "2022-05-18T15:37:08.130867042Z"
                        },
                        {
                          "name": "foo.txt",
                          "size": 4,
                          "timestamp": "2022-05-18T15:37:08.11753367Z"
                        }
                      ],
                      "modification": "2022-05-18T15:37:08.130867042Z",
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
          "Endpoint Execution"
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
                    "sent-time": "2022-05-18T17:37:05.813291457+02:00",
                    "stderr": "",
                    "stdout": "SGVsbG8gV29ybGQ=",
                    "timeout": 0,
                    "uuid": "926fcc99-c170-830f-48aa-01f97d61a6a9"
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
          "Endpoint Execution"
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
          "description": "Command to be executed. One can also specify files \n\t\t\t\tto drop from the manager to the endpoint prior to command execution \n\t\t\t\tand files to fetch after execution. A timeout for the can also \n\t\t\t\tbe specified, if zero there will be no timeout.",
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
                      "uuid": "926fcc99-c170-830f-48aa-01f97d61a6a9"
                    },
                    "criticality": 0,
                    "group": "",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "key": "U9OOmJjOXG5NEoqNGDvTwq8vuntYVe8q3vCjxXWxkt9lm4DqxpXEeHCxoJ8YfMhY",
                    "last-connection": "2022-05-18T15:37:05.803585567Z",
                    "last-detection": "2022-05-18T17:37:04.742498134+02:00",
                    "last-event": "2022-05-18T17:37:04.742498134+02:00",
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
                        "commit": "",
                        "version": ""
                      },
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
          "Endpoint Execution"
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
                          "Criticality": 8,
                          "Signature": [
                            "NewAutorun"
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
                            "Hash": "db68d29362f74da045df2c2d81f057632d5f7c34",
                            "ReceiptTime": "2022-05-18T15:37:03.593672747Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe\"",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "PSFactoryBuffer",
                          "EventType": "SetValue",
                          "Image": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe",
                          "ImageHashes": "SHA1=FBF03B5D6DC1A7EDAB0BA8D4DD27291C739E5813,MD5=B1C15F9DB942B373B2FC468B7048E63F,SHA256=1DC05B6DD6281840CEB822604B0E403E499180D636D02EC08AD77B4EB56F1B9C,IMPHASH=8AA2B8727E6858A3557A4C09970B9A5D",
                          "ImageSignature": "?",
                          "ImageSignatureStatus": "?",
                          "ImageSigned": "false",
                          "IntegrityLevel": "System",
                          "ProcessGuid": "{515cd0d1-7669-6123-4e00-000000007300}",
                          "ProcessId": "3276",
                          "ProcessThreatScore": "48",
                          "RuleName": "-",
                          "Services": "WinDefend",
                          "TargetObject": "HKCR\\CLSID\\{4DB116D1-9B24-4DFC-946B-BFE03E852002}\\(Default)",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:25.878"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
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
                            "SystemTime": "2022-05-18T17:37:02.575018871+02:00"
                          }
                        }
                      }
                    },
                    {
                      "Event": {
                        "Detection": {
                          "Actions": [],
                          "Criticality": 8,
                          "Signature": [
                            "NewAutorun"
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
                            "Hash": "5c33226802ffddea0afcabf997deeb328c54ccae",
                            "ReceiptTime": "2022-05-18T15:37:03.59401868Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe\"",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "Both",
                          "EventType": "SetValue",
                          "Image": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe",
                          "ImageHashes": "SHA1=FBF03B5D6DC1A7EDAB0BA8D4DD27291C739E5813,MD5=B1C15F9DB942B373B2FC468B7048E63F,SHA256=1DC05B6DD6281840CEB822604B0E403E499180D636D02EC08AD77B4EB56F1B9C,IMPHASH=8AA2B8727E6858A3557A4C09970B9A5D",
                          "ImageSignature": "?",
                          "ImageSignatureStatus": "?",
                          "ImageSigned": "false",
                          "IntegrityLevel": "System",
                          "ProcessGuid": "{515cd0d1-7669-6123-4e00-000000007300}",
                          "ProcessId": "3276",
                          "ProcessThreatScore": "40",
                          "RuleName": "-",
                          "Services": "WinDefend",
                          "TargetObject": "HKCR\\CLSID\\{4DB116D1-9B24-4DFC-946B-BFE03E852002}\\InProcServer32\\ThreadingModel",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:25.878"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
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
                            "SystemTime": "2022-05-18T17:37:02.575090252+02:00"
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
                            "Hash": "5635b3eff0d2e146a57aa675a04e7d438affd833",
                            "ReceiptTime": "2022-05-18T15:37:03.589492108Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\system32\\svchost.exe -k appmodel -p -s StateRepository",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "DWORD (0x00000009)",
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
                          "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\ApplicationExtension\\Data\\523\\Index",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:30.785"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
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
                            "SystemTime": "2022-05-18T17:37:02.574155757+02:00"
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
                            "Hash": "5fb142866f9d3b1f77416a826ac0cb935305f6ff",
                            "ReceiptTime": "2022-05-18T15:37:03.589847319Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\Explorer.EXE",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "Binary Data",
                          "EventType": "SetValue",
                          "Image": "C:\\Windows\\Explorer.EXE",
                          "ImageHashes": "SHA1=0524ADAB740ED73E0B17168F7F68A36B6D0CC5D6,MD5=9FBBF189473A313776019D2EAA72A47A,SHA256=CEF64201A97E08834F5C8952907A1719531A7D99B53309CB2E2956F40CFF3486,IMPHASH=D505016A935B17367AA0263582F3F1E2",
                          "ImageSignature": "?",
                          "ImageSignatureStatus": "?",
                          "ImageSigned": "false",
                          "IntegrityLevel": "Medium",
                          "ProcessGuid": "{515cd0d1-766f-6123-6e00-000000007300}",
                          "ProcessId": "5292",
                          "ProcessThreatScore": "0",
                          "RuleName": "-",
                          "Services": "N/A",
                          "TargetObject": "HKU\\S-1-5-21-2915380141-4195670196-3871645020-1001_Classes\\Local Settings\\MuiCache\\2f\\52C64B7E\\LanguageList",
                          "User": "DESKTOP-LJRVE06\\Generic",
                          "UtcTime": "2021-08-23 10:20:31.937"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
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
                            "SystemTime": "2022-05-18T17:37:02.574156275+02:00"
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
                      "SuspiciousService": 5,
                      "UnknownServices": 7,
                      "UntrustedDriverLoaded": 11
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-05-18T17:37:05.886831053+02:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "UntrustedDriverLoaded",
                      "SuspiciousService",
                      "DefenderConfigChanged",
                      "NewAutorun",
                      "UnknownServices"
                    ],
                    "start-time": "2022-05-18T17:37:05.88545256+02:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-05-18T17:37:05.888209546+02:00",
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
                      "SuspiciousService": 5,
                      "UnknownServices": 7,
                      "UntrustedDriverLoaded": 11
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-05-18T17:37:05.886831053+02:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "NewAutorun",
                      "UnknownServices",
                      "UntrustedDriverLoaded",
                      "SuspiciousService",
                      "DefenderConfigChanged"
                    ],
                    "start-time": "2022-05-18T17:37:05.88545256+02:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-05-18T17:37:05.888209546+02:00",
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
                      "archived-time": "2022-05-18T17:37:06.956898734+02:00",
                      "avg-alert-criticality": 0,
                      "avg-signature-criticality": 0,
                      "bounded-score": 0,
                      "count-by-signature": {
                        "DefenderConfigChanged": 4,
                        "NewAutorun": 23,
                        "SuspiciousService": 5,
                        "UnknownServices": 7,
                        "UntrustedDriverLoaded": 11
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-05-18T17:37:05.886831053+02:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "NewAutorun",
                        "UnknownServices",
                        "UntrustedDriverLoaded",
                        "SuspiciousService",
                        "DefenderConfigChanged"
                      ],
                      "start-time": "2022-05-18T17:37:05.88545256+02:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-05-18T17:37:05.888209546+02:00",
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
                      "guuid": "6cf40acc-a7d3-f9e1-fd84-0d5e1b0d8c79",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "5210450c-d56a-097c-e827-fe1f27834abd",
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
                  "uuid": "5210450c-d56a-097c-e827-fe1f27834abd",
                  "guuid": "6cf40acc-a7d3-f9e1-fd84-0d5e1b0d8c79",
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
                      "guuid": "6cf40acc-a7d3-f9e1-fd84-0d5e1b0d8c79",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "5210450c-d56a-097c-e827-fe1f27834abd",
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
                    "key": "qUGunK846BHlgLlLWi2sHVYtfpIzt9qtlTL4ChuFgR4kaDMsvilkh3YPWrblRPyR",
                    "uuid": "8c5ee51a-f4b0-ab64-98f4-da00e77af112"
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
        "summary": "Create a new user from POST data",
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
                "uuid": "a034a375-3775-74e9-0e24-8f0defbabfeb",
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
                    "uuid": "a034a375-3775-74e9-0e24-8f0defbabfeb"
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
                    "uuid": "a034a375-3775-74e9-0e24-8f0defbabfeb"
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
                    "uuid": "a034a375-3775-74e9-0e24-8f0defbabfeb"
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
