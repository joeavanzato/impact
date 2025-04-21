package main

import (
	"fmt"
	"log"
	"syscall"
	"time"
	"unsafe"
)

// Windows API constants for service control
const (
	// Access rights for Service Control Manager
	SC_MANAGER_CONNECT            = 0x0001
	SC_MANAGER_CREATE_SERVICE     = 0x0002
	SC_MANAGER_ENUMERATE_SERVICE  = 0x0004
	SC_MANAGER_LOCK               = 0x0008
	SC_MANAGER_QUERY_LOCK_STATUS  = 0x0010
	SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020
	SC_MANAGER_ALL_ACCESS         = 0xF003F

	// Access rights for service
	SERVICE_QUERY_CONFIG         = 0x0001
	SERVICE_CHANGE_CONFIG        = 0x0002
	SERVICE_QUERY_STATUS         = 0x0004
	SERVICE_ENUMERATE_DEPENDENTS = 0x0008
	SERVICE_START                = 0x0010
	SERVICE_STOP                 = 0x0020
	SERVICE_PAUSE_CONTINUE       = 0x0040
	SERVICE_INTERROGATE          = 0x0080
	SERVICE_USER_DEFINED_CONTROL = 0x0100
	SERVICE_ALL_ACCESS           = 0xF01FF

	// Service types
	SERVICE_KERNEL_DRIVER       = 0x00000001
	SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002
	SERVICE_ADAPTER             = 0x00000004
	SERVICE_RECOGNIZER_DRIVER   = 0x00000008
	SERVICE_DRIVER              = SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER
	SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	SERVICE_WIN32               = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS
	SERVICE_INTERACTIVE_PROCESS = 0x00000100
	SERVICE_TYPE_ALL            = SERVICE_WIN32 | SERVICE_ADAPTER | SERVICE_DRIVER | SERVICE_INTERACTIVE_PROCESS

	// Service start types
	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004

	// Service error control
	SERVICE_ERROR_IGNORE   = 0x00000000
	SERVICE_ERROR_NORMAL   = 0x00000001
	SERVICE_ERROR_SEVERE   = 0x00000002
	SERVICE_ERROR_CRITICAL = 0x00000003

	// Service control codes
	SERVICE_CONTROL_STOP                  = 0x00000001
	SERVICE_CONTROL_PAUSE                 = 0x00000002
	SERVICE_CONTROL_CONTINUE              = 0x00000003
	SERVICE_CONTROL_INTERROGATE           = 0x00000004
	SERVICE_CONTROL_SHUTDOWN              = 0x00000005
	SERVICE_CONTROL_PARAMCHANGE           = 0x00000006
	SERVICE_CONTROL_NETBINDADD            = 0x00000007
	SERVICE_CONTROL_NETBINDREMOVE         = 0x00000008
	SERVICE_CONTROL_NETBINDENABLE         = 0x00000009
	SERVICE_CONTROL_NETBINDDISABLE        = 0x0000000A
	SERVICE_CONTROL_DEVICEEVENT           = 0x0000000B
	SERVICE_CONTROL_HARDWAREPROFILECHANGE = 0x0000000C
	SERVICE_CONTROL_POWEREVENT            = 0x0000000D
	SERVICE_CONTROL_SESSIONCHANGE         = 0x0000000E

	// Service state
	SERVICE_STOPPED          = 0x00000001
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_RUNNING          = 0x00000004
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007

	// Service config information
	SERVICE_CONFIG_DESCRIPTION     = 1
	SERVICE_CONFIG_FAILURE_ACTIONS = 2
)

// Windows API function pointers
var (
	modadvapi32               = syscall.NewLazyDLL("advapi32.dll")
	procOpenSCManagerW        = modadvapi32.NewProc("OpenSCManagerW")
	procCreateServiceW        = modadvapi32.NewProc("CreateServiceW")
	procOpenServiceW          = modadvapi32.NewProc("OpenServiceW")
	procStartServiceW         = modadvapi32.NewProc("StartServiceW")
	procQueryServiceStatus    = modadvapi32.NewProc("QueryServiceStatus")
	procCloseServiceHandle    = modadvapi32.NewProc("CloseServiceHandle")
	procDeleteService         = modadvapi32.NewProc("DeleteService")
	procChangeServiceConfig2W = modadvapi32.NewProc("ChangeServiceConfig2W")
	procControlService        = modadvapi32.NewProc("ControlService")
)

// SERVICE_STATUS represents the status of a service
type SERVICE_STATUS struct {
	DwServiceType             uint32
	DwCurrentState            uint32
	DwControlsAccepted        uint32
	DwWin32ExitCode           uint32
	DwServiceSpecificExitCode uint32
	DwCheckPoint              uint32
	DwWaitHint                uint32
}

// SERVICE_DESCRIPTION structure used for setting service description
type SERVICE_DESCRIPTION struct {
	LpDescription *uint16
}

// UTF16PtrFromString creates a pointer to a UTF16 string
func UTF16PtrFromString(s string) *uint16 {
	ptr, _ := syscall.UTF16PtrFromString(s)
	return ptr
}

// CreateAndStartRemoteWindowsService creates and starts a Windows service on a remote computer using the native Service Control Manager API
func CreateAndStartRemoteWindowsService(machineName, serviceName, displayName, description, binPath string) error {
	// Open Service Control Manager on remote machine
	var machineNamePtr *uint16
	if machineName != "" {
		machineNamePtr = UTF16PtrFromString(machineName)
	}

	// Connect to the Service Control Manager on the specified machine
	scmHandle, _, err := procOpenSCManagerW.Call(
		uintptr(unsafe.Pointer(machineNamePtr)),
		uintptr(unsafe.Pointer(UTF16PtrFromString("ServicesActive"))),
		uintptr(SC_MANAGER_ALL_ACCESS),
	)

	if scmHandle == 0 {
		return fmt.Errorf("failed to open Service Control Manager: %v (Error code: %d)", err, syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(scmHandle)

	log.Printf("Successfully opened Service Control Manager on %s\n", machineName)

	// Check if service already exists and try to open it
	serviceHandle, _, _ := procOpenServiceW.Call(
		scmHandle,
		uintptr(unsafe.Pointer(UTF16PtrFromString(serviceName))),
		uintptr(SERVICE_ALL_ACCESS),
	)

	if serviceHandle != 0 {
		// Service exists, attempt to stop it first if it's running
		var serviceStatus SERVICE_STATUS
		procQueryServiceStatus.Call(serviceHandle, uintptr(unsafe.Pointer(&serviceStatus)))

		if serviceStatus.DwCurrentState != SERVICE_STOPPED {
			log.Printf("Service '%s' is running, attempting to stop it\n", serviceName)
			success, _, stopErr := procControlService.Call(
				serviceHandle,
				uintptr(SERVICE_CONTROL_STOP),
				uintptr(unsafe.Pointer(&serviceStatus)),
			)

			if success == 0 {
				log.Printf("Warning: Failed to stop service: %v\n", stopErr)
			} else {
				// Wait for service to stop (with timeout)
				stopTimeout := time.Now().Add(30 * time.Second)
				for serviceStatus.DwCurrentState != SERVICE_STOPPED {
					if time.Now().After(stopTimeout) {
						log.Printf("Warning: Timeout waiting for service to stop\n")
						break
					}

					time.Sleep(500 * time.Millisecond)
					procQueryServiceStatus.Call(serviceHandle, uintptr(unsafe.Pointer(&serviceStatus)))
				}
			}
		}

		// Delete the service
		success, _, delErr := procDeleteService.Call(serviceHandle)
		procCloseServiceHandle.Call(serviceHandle)

		if success == 0 {
			return fmt.Errorf("failed to delete existing service: %v (Error code: %d)", delErr, syscall.GetLastError())
		}

		log.Printf("Successfully deleted existing service: %s\n", serviceName)

		// Brief delay to ensure service is fully removed
		time.Sleep(1 * time.Second)
	}

	// Create the new service
	serviceHandle, _, err = procCreateServiceW.Call(
		scmHandle,
		uintptr(unsafe.Pointer(UTF16PtrFromString(serviceName))),
		uintptr(unsafe.Pointer(UTF16PtrFromString(displayName))),
		uintptr(SERVICE_ALL_ACCESS),
		uintptr(SERVICE_WIN32_OWN_PROCESS),
		uintptr(SERVICE_DEMAND_START),
		uintptr(SERVICE_ERROR_NORMAL),
		uintptr(unsafe.Pointer(UTF16PtrFromString(binPath))),
		0, // lpLoadOrderGroup
		0, // lpdwTagId
		0, // lpDependencies
		0, // lpServiceStartName (account name)
		0, // lpPassword
	)

	if serviceHandle == 0 {
		return fmt.Errorf("failed to create service: %v (Error code: %d)", err, syscall.GetLastError())
	}
	defer procCloseServiceHandle.Call(serviceHandle)

	// Set service description if provided
	if description != "" {
		// Create SERVICE_DESCRIPTION struct with description
		descPtr := UTF16PtrFromString(description)
		svcDesc := SERVICE_DESCRIPTION{
			LpDescription: descPtr,
		}

		// Call ChangeServiceConfig2W to set the description
		success, _, err := procChangeServiceConfig2W.Call(
			serviceHandle,
			uintptr(SERVICE_CONFIG_DESCRIPTION),
			uintptr(unsafe.Pointer(&svcDesc)),
		)

		// Non-fatal error
		if success == 0 {
			printFormattedMessage(fmt.Sprintf("Failed to set service description: %v (Error code: %d)", err, syscall.GetLastError()), ERROR)
		}
	}

	// Start the service
	success, _, err := procStartServiceW.Call(
		serviceHandle,
		0, // number of arguments
		0, // pointer to arguments
	)
	if success == 0 {
		return fmt.Errorf("failed to start service: %v (Error code: %d)", err, syscall.GetLastError())
	}

	var serviceStatus SERVICE_STATUS
	success, _, err = procQueryServiceStatus.Call(
		serviceHandle,
		uintptr(unsafe.Pointer(&serviceStatus)),
	)
	if success == 0 {
		return fmt.Errorf("failed to query service status: %v (Error code: %d)", err, syscall.GetLastError())
	}

	// Wait for service to start or timeout
	startTimeout := time.Now().Add(60 * time.Second)
	for serviceStatus.DwCurrentState == SERVICE_STOPPED || serviceStatus.DwCurrentState == SERVICE_START_PENDING {
		if time.Now().After(startTimeout) {
			return fmt.Errorf("timeout waiting for service to start")
		}

		// Get current checkpoint and wait hint
		checkpoint := serviceStatus.DwCheckPoint
		waitHint := serviceStatus.DwWaitHint

		waitTime := 1000 * time.Millisecond
		if waitHint > 0 {
			// Wait hint is in milliseconds, add 10% buffer
			waitTime = time.Duration(waitHint) * time.Millisecond / 10

			// Don't wait less than 1 second or more than 10 seconds
			if waitTime < time.Second {
				waitTime = time.Second
			} else if waitTime > 10*time.Second {
				waitTime = 10 * time.Second
			}
		}

		time.Sleep(waitTime)

		// Query service status again
		success, _, _ = procQueryServiceStatus.Call(
			serviceHandle,
			uintptr(unsafe.Pointer(&serviceStatus)),
		)
		if success == 0 {
			return fmt.Errorf("failed to query service status while waiting: %v", err)
		}

		// If checkpoint hasn't increased after waiting, service start may be hung
		if serviceStatus.DwCheckPoint <= checkpoint && waitHint > 0 {
			printFormattedMessage(fmt.Sprintf("Service start is hung, current state: %s, checkpoint: %d", ServiceStateToString(serviceStatus.DwCurrentState), serviceStatus.DwCheckPoint), ERROR)
		}
	}

	if serviceStatus.DwCurrentState != SERVICE_RUNNING {
		return fmt.Errorf("service failed to start: current state = %d", serviceStatus.DwCurrentState)
	}

	return nil
}

// ServiceStateToString converts a service state code to a human-readable string
func ServiceStateToString(state uint32) string {
	switch state {
	case SERVICE_STOPPED:
		return "Stopped"
	case SERVICE_START_PENDING:
		return "Start Pending"
	case SERVICE_STOP_PENDING:
		return "Stop Pending"
	case SERVICE_RUNNING:
		return "Running"
	case SERVICE_CONTINUE_PENDING:
		return "Continue Pending"
	case SERVICE_PAUSE_PENDING:
		return "Pause Pending"
	case SERVICE_PAUSED:
		return "Paused"
	default:
		return fmt.Sprintf("Unknown (%d)", state)
	}
}
