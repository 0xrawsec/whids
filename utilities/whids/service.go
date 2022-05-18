package main

//build +windows

import (
	"golang.org/x/sys/windows/svc"
)

type WhidsService struct{}

// Execute kind of main function for the service
func (m *WhidsService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop
	changes <- svc.Status{State: svc.StartPending}

	// Start up WHIDS without waiting the engine to be done
	runHids(true)

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	/*for {
	select {
	case c := <-r:*/
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop:
			changes <- svc.Status{State: svc.StopPending}
			// Stop WHIDS there
			hostIDS.Stop()
			hostIDS.Wait()
			hostIDS.LogStats()
			break loop
		}
		//	}
	}
	changes <- svc.Status{State: svc.Stopped}
	return
}

func runService(name string, isDebug bool) {
	var err error

	run := svc.Run
	err = run(name, &WhidsService{})

	if err != nil {
		return
	}
}
