// +build windows

package pkg

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/imgk/shadow/app"
)

type Service struct {
	Log  debug.Log
	File string
}

func (m Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	b, err := ioutil.ReadFile(m.File)
	if err != nil {
		m.Log.Error(1, fmt.Sprintf("read config file error: %v", err))
		return
	}

	conf := &app.Conf{}
	if err := conf.Unmarshal(b); err != nil {
		m.Log.Error(1, fmt.Sprintf("unmarshal config file error: %v", err))
		return
	}
	b = nil

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	opt := app.Option{
		Conf:    conf,
		Writer:  writer{},
		Ctx:     ctx,
		Reload:  make(chan struct{}),
		Done:    done,
		Timeout: time.Minute,
	}
	go m.Run(opt)

	m.Log.Info(1, "shadow - a transparent proxy for Windows, Linux and macOS")
	m.Log.Info(1, "shadow is running...")
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue}

LOOP:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break LOOP
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue}
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue}
			default:
				m.Log.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}

	m.Log.Info(1, "shadow is closing...")
	changes <- svc.Status{State: svc.StopPending}

	cancel()
	select {
	case <-time.After(time.Second * 10):
		buf := make([]byte, 1024)
		for {
			n := runtime.Stack(buf, true)
			if n < len(buf) {
				buf = buf[:n]
				break
			}
			buf = make([]byte, 2*len(buf))
		}
		lines := bytes.Split(buf, []byte{'\n'})
		m.Log.Info(1, "Failed to shutdown after 10 seconds. Probably dead locked. Printing stack and killing.")
		for _, line := range lines {
			if len(bytes.TrimSpace(line)) > 0 {
				m.Log.Info(1, string(line))
			}
		}
		os.Exit(777)
	case <-done:
	}

	changes <- svc.Status{State: svc.Stopped}
	return
}

func (m Service) Run(option app.Option) {
	if err := app.Run(option); err != nil {
		m.Log.Error(1, err.Error())
		os.Exit(777)
	}
}

func IsExistService(name string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return false, nil
	}
	s.Close()
	return true, nil
}

func IsRunningService(name string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return false, fmt.Errorf("service %s is not installed", name)
	}
	defer s.Close()

	t, err := s.Query()
	if err != nil {
		return false, err
	}

	return t.State == svc.Running, nil
}

func InstallService(name, desc string, args []string) error {
	exepath, err := os.Executable()
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", name)
	}

	if s, err = m.CreateService(name, exepath, mgr.Config{DisplayName: desc}, args...); err != nil {
		return err
	}
	defer s.Close()

	if err = eventlog.InstallAsEventCreate(name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		s.Delete()
		return fmt.Errorf("SetupEventLogSource() failed: %s", err)
	}
	return nil
}

func RemoveService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", name)
	}
	defer s.Close()

	if err = s.Delete(); err != nil {
		return err
	}

	if err = eventlog.Remove(name); err != nil {
		return fmt.Errorf("RemoveEventLogSource() failed: %s", err)
	}
	return nil
}

func StartService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer s.Close()

	if err = s.Start(); err != nil {
		return fmt.Errorf("could not start service: %v", err)
	}
	return nil
}

func ControlService(name string, c svc.Cmd, to svc.State) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("could not access service: %v", err)
	}
	defer s.Close()

	status, err := s.Control(c)
	if err != nil {
		return fmt.Errorf("could not send control=%d: %v", c, err)
	}

	timeout := time.Now().Add(10 * time.Second)
	for status.State != to {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to go to state=%d", to)
		}
		time.Sleep(300 * time.Millisecond)

		if status, err = s.Query(); err != nil {
			return fmt.Errorf("could not retrieve service status: %v", err)
		}
	}
	return nil
}

type writer struct{}

func (w writer) Write(b []byte) (int, error) { return len(b), nil }
func (w writer) Sync() error                 { return nil }
