package api

import "time"

var (
	mconf = ManagerConfig{
		AdminAPI: AdminAPIConfig{
			Host: "localhost",
			Port: randport(),
		},
		EndpointAPI: EndpointAPIConfig{
			Host: "",
			Port: randport(),
		},
		Logging: ManagerLogConfig{
			Root:        "./data/logs",
			LogBasename: "alerts",
		},
		Database: "./data/database",
		DumpDir:  "./data/uploads/",
		TLS: TLSConfig{
			Cert: "./data/cert.pem",
			Key:  "./data/key.pem",
		},
	}

	cconf = makeClientConfig(&mconf)

	fconf = makeForwarderConfig(&mconf)
)

func makeClientConfig(mc *ManagerConfig) ClientConfig {
	return ClientConfig{
		Proto:             "https",
		Host:              "localhost",
		Port:              mc.EndpointAPI.Port,
		UUID:              "5a92baeb-9384-47d3-92b4-a0db6f9b8c6d",
		Key:               "don'tcomplain",
		ServerFingerprint: "511dc40cb2363974a97dfd47437feb8307cbd9d938645e1442775aa97ec14227",
		Unsafe:            true,
	}
}

func makeForwarderConfig(mc *ManagerConfig) ForwarderConfig {
	return ForwarderConfig{
		Client: cconf,
		Logging: LoggingConfig{
			Dir:              "./data/Queued",
			RotationInterval: time.Second * 2,
		},
	}
}
