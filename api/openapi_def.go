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
                      "key": "Rw8FElmRch4K7PmpLBIR1gRlDJys74KSyBtnHlJaDGOfMMyDXd4H2G7Y0WerVFCj",
                      "last-connection": "2022-01-28T10:58:38.403781409Z",
                      "last-detection": "2022-01-28T11:58:37.309299837+01:00",
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
                    "key": "wS4IhUxEQumnviTeBpPVj0w9Phhz7PncrPYvfx4IYutaDrh7HKaErGadoa29no7s",
                    "last-connection": "0001-01-01T00:00:00Z",
                    "last-detection": "0001-01-01T00:00:00Z",
                    "score": 0,
                    "status": "",
                    "uuid": "e0ac3b8e-5f18-e2fa-13ad-2277d5287816"
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
                        "creation": "2022-01-28T10:58:43.001721634Z",
                        "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                        "files": [
                          {
                            "name": "bar.txt",
                            "size": 4,
                            "timestamp": "2022-01-28T10:58:43.011721641Z"
                          },
                          {
                            "name": "foo.txt",
                            "size": 4,
                            "timestamp": "2022-01-28T10:58:43.001721634Z"
                          }
                        ],
                        "modification": "2022-01-28T10:58:43.011721641Z",
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
                        "NewAutorun": 16,
                        "SuspiciousService": 8,
                        "UnknownServices": 5,
                        "UntrustedDriverLoaded": 17
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-01-28T11:58:39.634708357+01:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "NewAutorun",
                        "UntrustedDriverLoaded",
                        "DefenderConfigChanged",
                        "SuspiciousService",
                        "UnknownServices"
                      ],
                      "start-time": "2022-01-28T11:58:39.632420476+01:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-01-28T11:58:39.636996239+01:00",
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
                    "last-connection": "2022-01-28T10:58:38.403781409Z",
                    "last-detection": "2022-01-28T11:58:37.309299837+01:00",
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
                    "last-connection": "2022-01-28T10:58:38.403781409Z",
                    "last-detection": "2022-01-28T11:58:37.309299837+01:00",
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
                    "last-connection": "2022-01-28T10:58:38.403781409Z",
                    "last-detection": "2022-01-28T11:58:37.309299837+01:00",
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
                      "creation": "2022-01-28T10:58:43.001721634Z",
                      "event-hash": "3d8441643c204ba9b9dcb5c414b25a3129f66f6c",
                      "files": [
                        {
                          "name": "bar.txt",
                          "size": 4,
                          "timestamp": "2022-01-28T10:58:43.011721641Z"
                        },
                        {
                          "name": "foo.txt",
                          "size": 4,
                          "timestamp": "2022-01-28T10:58:43.001721634Z"
                        }
                      ],
                      "modification": "2022-01-28T10:58:43.011721641Z",
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
                    "sent-time": "2022-01-28T11:58:39.546313284+01:00",
                    "stderr": null,
                    "stdout": "SGVsbG8gV29ybGQ=",
                    "timeout": 0,
                    "uuid": "a4231065-f12b-cbf1-2fb5-6456f8665e6c"
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
                      "uuid": "a4231065-f12b-cbf1-2fb5-6456f8665e6c"
                    },
                    "criticality": 0,
                    "group": "",
                    "hostname": "OpenHappy",
                    "ip": "127.0.0.1",
                    "key": "B9sah5THLSdSoiRLz9Ri3TIkhUoWuLUQJTJYaBfaCjJR1fR99T2s1YynwXQXyReN",
                    "last-connection": "2022-01-28T10:58:39.522675194Z",
                    "last-detection": "2022-01-28T11:58:38.432535508+01:00",
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
                            "Hash": "85c1893511233162eb4d28719de480400b475521",
                            "ReceiptTime": "2022-01-28T10:58:37.208588752Z"
                          }
                        },
                        "EventData": {
                          "Ancestors": "System|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\smss.exe|C:\\Windows\\System32\\wininit.exe|C:\\Windows\\System32\\services.exe",
                          "CommandLine": "\"C:\\Program Files\\osquery\\osqueryd\\osqueryd.exe\" --flagfile=\"C:\\Program Files\\osquery\\osquery.flags\"",
                          "Company": "Facebook",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Description": "osquery daemon and shell",
                          "FileVersion": "4.8.0.0",
                          "Hashes": "SHA1=ED57ADE89F017B9020D727749EC32EA6646DE163,MD5=50D99BE393641C95354D00DD9DB11F72,SHA256=4FE020D36C4031FC7E4D0AED28A1C1AABD157CAF49B2C9D16DBDDD4AAB19FA86,IMPHASH=27E96EFBAE3B96032D450234A10EDE3B",
                          "Image": "C:\\Program Files\\osquery\\osqueryd\\osqueryd.exe",
                          "ImageSize": "21713568",
                          "IntegrityLevel": "System",
                          "LogonGuid": "{515cd0d1-7667-6123-e703-000000000000}",
                          "LogonId": "0x3E7",
                          "OriginalFileName": "osqueryd.exe",
                          "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
                          "ParentImage": "C:\\Windows\\System32\\services.exe",
                          "ParentIntegrityLevel": "System",
                          "ParentProcessGuid": "{515cd0d1-7666-6123-0b00-000000007300}",
                          "ParentProcessId": "692",
                          "ParentServices": "N/A",
                          "ParentUser": "NT AUTHORITY\\SYSTEM",
                          "ProcessGuid": "{515cd0d1-7669-6123-4800-000000007300}",
                          "ProcessId": "3184",
                          "Product": "osquery",
                          "RuleName": "-",
                          "Services": "osqueryd",
                          "TerminalSessionId": "0",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:25.415"
                        },
                        "System": {
                          "Channel": "Microsoft-Windows-Sysmon/Operational",
                          "Computer": "DESKTOP-LJRVE06",
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
                            "SystemTime": "2022-01-28T11:58:36.168606639+01:00"
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
                            "Hash": "f4e660c5c21dec2e28a2a32a9274f180618a5d2d",
                            "ReceiptTime": "2022-01-28T10:58:37.2089718Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe\"",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MPUXAGENT.DLL",
                          "EventType": "SetValue",
                          "Image": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2106.6-0\\MsMpEng.exe",
                          "ImageHashes": "SHA1=FBF03B5D6DC1A7EDAB0BA8D4DD27291C739E5813,MD5=B1C15F9DB942B373B2FC468B7048E63F,SHA256=1DC05B6DD6281840CEB822604B0E403E499180D636D02EC08AD77B4EB56F1B9C,IMPHASH=8AA2B8727E6858A3557A4C09970B9A5D",
                          "ImageSignature": "?",
                          "ImageSignatureStatus": "?",
                          "ImageSigned": "false",
                          "IntegrityLevel": "System",
                          "ProcessGuid": "{515cd0d1-7669-6123-4e00-000000007300}",
                          "ProcessId": "3276",
                          "ProcessThreatScore": "32",
                          "RuleName": "-",
                          "Services": "WinDefend",
                          "TargetObject": "HKCR\\CLSID\\{4DB116D1-9B24-4DFC-946B-BFE03E852002}\\InProcServer32\\(Default)",
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
                            "SystemTime": "2022-01-28T11:58:36.168649437+01:00"
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
                            "Hash": "82b96ac17d1f3d992752db30192334cf6aebb983",
                            "ReceiptTime": "2022-01-28T10:58:37.203669307Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\system32\\svchost.exe -k appmodel -p -s StateRepository",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "DWORD (0x00000003)",
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
                          "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\PackageUser\\Data\\531\\User",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:30.490"
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
                            "SystemTime": "2022-01-28T11:58:36.167812151+01:00"
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
                            "Hash": "c9d53e1e361434e93296ffbf74fe7d4b11945f79",
                            "ReceiptTime": "2022-01-28T10:58:37.204205048Z"
                          }
                        },
                        "EventData": {
                          "CommandLine": "C:\\Windows\\system32\\svchost.exe -k appmodel -p -s StateRepository",
                          "CurrentDirectory": "C:\\Windows\\system32\\",
                          "Details": "DWORD (0x00000014)",
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
                          "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel\\StateRepository\\Cache\\Application\\Data\\17\\Package",
                          "User": "NT AUTHORITY\\SYSTEM",
                          "UtcTime": "2021-08-23 10:20:30.146"
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
                            "SystemTime": "2022-01-28T11:58:36.167812525+01:00"
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
                      "NewAutorun": 16,
                      "SuspiciousService": 8,
                      "UnknownServices": 5,
                      "UntrustedDriverLoaded": 17
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-01-28T11:58:39.634708357+01:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "UnknownServices",
                      "NewAutorun",
                      "UntrustedDriverLoaded",
                      "DefenderConfigChanged",
                      "SuspiciousService"
                    ],
                    "start-time": "2022-01-28T11:58:39.632420476+01:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-01-28T11:58:39.636996239+01:00",
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
                      "NewAutorun": 16,
                      "SuspiciousService": 8,
                      "UnknownServices": 5,
                      "UntrustedDriverLoaded": 17
                    },
                    "count-uniq-signatures": 5,
                    "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                    "median-time": "2022-01-28T11:58:39.634708357+01:00",
                    "score": 0,
                    "signature-count": 50,
                    "signature-criticality-metric": 0,
                    "signature-diversity": 100,
                    "signatures": [
                      "UnknownServices",
                      "NewAutorun",
                      "UntrustedDriverLoaded",
                      "DefenderConfigChanged",
                      "SuspiciousService"
                    ],
                    "start-time": "2022-01-28T11:58:39.632420476+01:00",
                    "std-dev-alert-criticality": 0,
                    "std-dev-signature-criticality": -92233720368547760,
                    "stop-time": "2022-01-28T11:58:39.636996239+01:00",
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
                      "archived-time": "2022-01-28T11:58:40.725833736+01:00",
                      "avg-alert-criticality": 0,
                      "avg-signature-criticality": 0,
                      "bounded-score": 0,
                      "count-by-signature": {
                        "DefenderConfigChanged": 4,
                        "NewAutorun": 16,
                        "SuspiciousService": 8,
                        "UnknownServices": 5,
                        "UntrustedDriverLoaded": 17
                      },
                      "count-uniq-signatures": 5,
                      "identifier": "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
                      "median-time": "2022-01-28T11:58:39.634708357+01:00",
                      "score": 0,
                      "signature-count": 50,
                      "signature-criticality-metric": 0,
                      "signature-diversity": 100,
                      "signatures": [
                        "UnknownServices",
                        "NewAutorun",
                        "UntrustedDriverLoaded",
                        "DefenderConfigChanged",
                        "SuspiciousService"
                      ],
                      "start-time": "2022-01-28T11:58:39.632420476+01:00",
                      "std-dev-alert-criticality": 0,
                      "std-dev-signature-criticality": -92233720368547760,
                      "stop-time": "2022-01-28T11:58:39.636996239+01:00",
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
                      "guuid": "234351cd-4fea-417e-eb0e-6c6fd1206dcf",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "0a9b375c-5ad9-13f7-cba9-b43f695bb52d",
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
                  "uuid": "0a9b375c-5ad9-13f7-cba9-b43f695bb52d",
                  "guuid": "234351cd-4fea-417e-eb0e-6c6fd1206dcf",
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
                      "guuid": "234351cd-4fea-417e-eb0e-6c6fd1206dcf",
                      "source": "XyzTIProvider",
                      "type": "domain",
                      "uuid": "0a9b375c-5ad9-13f7-cba9-b43f695bb52d",
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
                    "key": "WGtD4Q4RKSMVQwch3Grbt5MqhuT0zp1whOIvxqwLzmVN5vgIevUyfCKemMmDS7FW",
                    "uuid": "4257662a-a230-6f26-b24b-b98bb917b80a"
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
                "uuid": "9acbe672-c255-da79-7c11-55ea9cb8b25e",
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
                    "uuid": "9acbe672-c255-da79-7c11-55ea9cb8b25e"
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
                    "uuid": "9acbe672-c255-da79-7c11-55ea9cb8b25e"
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
                    "uuid": "9acbe672-c255-da79-7c11-55ea9cb8b25e"
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
