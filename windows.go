package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
	"log"
	"slices"
	"strings"
	"syscall"
	"unsafe"
)

// https://github.com/golang/go/issues/28804
func areWeAdmin() bool {
	var sid *windows.SID
	// Although this looks scary, it is directly copied from the
	// official windows documentation. The Go API for this is a
	// direct wrap around the official C++ API.
	// See https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		log.Fatalf("SID Error: %s", err)
		return false
	}
	defer windows.FreeSid(sid)

	// This appears to cast a null pointer so I'm not sure why this
	// works, but this guy says it does and it Works for Me™:
	// https://github.com/golang/go/issues/28804#issuecomment-438838144
	token := windows.Token(0)

	member, err := token.IsMember(sid)
	if err != nil {
		log.Fatalf("Token Membership Error: %s", err)
		return false
	}

	// Also note that an admin is _not_ necessarily considered
	// elevated.
	// For elevation see https://github.com/mozey/run-as-admin
	//fmt.Println("Elevated?", token.IsElevated())

	//fmt.Println("Admin?", member)
	return member
}

func stopServices(config *Config) {
	serviceList := make([]string, 0)
	for _, v := range config.ServiceKillNames {
		serviceList = append(serviceList, strings.ToLower(v))
	}
	fmt.Println(serviceList)

	scm, err := mgr.Connect()
	if err != nil {
		return
	}
	services, err := scm.ListServices()
	if err != nil {
		return
	}
	for _, service := range services {
		func() {
			if !slices.Contains(serviceList, strings.ToLower(service)) {
				return
			}
			s, err := scm.OpenService(service)
			if err != nil {
				printFormattedMessage(fmt.Sprintf("Error opening service %s: %s", service, err.Error()), ERROR)
				return
			}
			defer s.Close()
			query, err := s.Query()
			if err != nil {
				printFormattedMessage(fmt.Sprintf("Error querying service %s: %s", service, err.Error()), ERROR)
				return
			}
			var bytesNeeded uint32
			err = windows.QueryServiceConfig(s.Handle, nil, 0, &bytesNeeded)
			if err != syscall.ERROR_INSUFFICIENT_BUFFER {
				printFormattedMessage(fmt.Sprintf("Error querying service config %s: %s", service, err.Error()), ERROR)
				return
			}

			sc := make([]byte, bytesNeeded)
			err = windows.QueryServiceConfig(s.Handle, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&sc[0])), bytesNeeded, &bytesNeeded)
			if err != nil {
				printFormattedMessage(fmt.Sprintf("Error querying service config %s: %s", service, err.Error()), ERROR)
				return
			}

			//serviceConfig := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&sc[0]))
			//path := windows.UTF16PtrToString(serviceConfig.BinaryPathName)
			// path represents the command-line used to start the service

			// service represent actual service name, path represents command-line
			// We can now attempt to kill processes associated with each service and then stop if

			if query.ProcessId != 0 {
				err = KillProcess(int(query.ProcessId))
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Error killing process %d: %s", query.ProcessId, err.Error()), ERROR)
				}
			}
			_, err = s.Control(windows.SERVICE_CONTROL_STOP)
			if err != nil {
				printFormattedMessage(fmt.Sprintf("Error stopping service %s: %s", service, err.Error()), ERROR)
			}
		}()
	}
}
