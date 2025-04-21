package main

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"unsafe"
)

// Assumes that WMI is accessible and current user has permissions to run commands
func executeRemoteWMI(remoteHost, command string) error {
	// Initialize COM
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		return fmt.Errorf("failed to initialize COM: %v", err)
	}
	defer ole.CoUninitialize()

	// Connect to WMI on remote host
	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return fmt.Errorf("failed to create WbemScripting object: %v", err)
	}
	defer unknown.Release()

	wmi, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("failed to query WMI interface: %v", err)
	}
	defer wmi.Release()

	// Connect to the remote host
	serviceRaw, err := oleutil.CallMethod(wmi, "ConnectServer", remoteHost, "root\\cimv2")
	if err != nil {
		return fmt.Errorf("failed to connect to remote host %s: %v", remoteHost, err)
	}
	service := serviceRaw.ToIDispatch()
	defer service.Release()

	// Create and execute the process
	processStartup := ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(ole.SysAllocString("Win32_ProcessStartup")))))
	defer processStartup.Clear()

	processClass := oleutil.MustCallMethod(service, "Get", processStartup).ToIDispatch()
	defer processClass.Release()

	processInstance := oleutil.MustCallMethod(processClass, "SpawnInstance_").ToIDispatch()
	defer processInstance.Release()

	// Set process properties to hide window
	oleutil.PutProperty(processInstance, "ShowWindow", ole.NewVariant(ole.VT_I4, 0))

	// Create process
	process := ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(ole.SysAllocString("Win32_Process")))))
	defer process.Clear()

	processClass = oleutil.MustCallMethod(service, "Get", process).ToIDispatch()
	defer processClass.Release()

	// Execute the command
	methodName := ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(ole.SysAllocString("Create")))))
	defer methodName.Clear()

	cmd := ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(ole.SysAllocString(command)))))
	defer cmd.Clear()

	currentDir := ole.NewVariant(ole.VT_BSTR, int64(uintptr(unsafe.Pointer(ole.SysAllocString("")))))
	defer currentDir.Clear()

	result, err := oleutil.CallMethod(processClass, "Create", cmd, currentDir, processInstance, 0)
	if err != nil {
		return fmt.Errorf("failed to execute command: %v", err)
	}

	// Get return code
	returnValue := int(result.Val)
	if returnValue != 0 {
		return fmt.Errorf("process creation failed with code %d", returnValue)
	}

	return nil
}
