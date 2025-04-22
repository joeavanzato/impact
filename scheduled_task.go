package main

import (
	"fmt"
	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"time"
)

// TODO - Get this to run whether user is logged on or not - maybe via schtasks directly
// Right now it only works if user logs on

func createRemoteScheduledTask(hostname, taskName, commandLine string) error {
	ole.CoInitialize(0)
	defer ole.CoUninitialize()

	unknown, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("failed to create Schedule.Service: %v", err)
	}
	defer unknown.Release()

	service, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("failed to query IDispatch: %v", err)
	}
	defer service.Release()

	_, err = oleutil.CallMethod(service, "Connect", hostname)
	if err != nil {
		return fmt.Errorf("failed to connect to scheduler on %s: %v", hostname, err)
	}

	rootFolderDisp, err := oleutil.CallMethod(service, "GetFolder", `\`)
	if err != nil {
		return fmt.Errorf("failed to get root folder: %v", err)
	}
	rootFolder := rootFolderDisp.ToIDispatch()
	defer rootFolder.Release()

	taskDefDisp, err := oleutil.CallMethod(service, "NewTask", 0)
	if err != nil {
		return fmt.Errorf("failed to create new task: %v", err)
	}
	taskDef := taskDefDisp.ToIDispatch()
	defer taskDef.Release()

	// Principal
	principalDisp, err := oleutil.GetProperty(taskDef, "Principal")
	if err != nil {
		return fmt.Errorf("failed to get Principal: %v", err)
	}
	principal := principalDisp.ToIDispatch()
	//oleutil.PutProperty(principal, "LogonType", 3) // TASK_LOGON_INTERACTIVE_TOKEN
	oleutil.PutProperty(principal, "UserId", "SYSTEM")
	oleutil.PutProperty(principal, "LogonType", 5) // TASK_LOGON_SERVICE_ACCOUNT
	oleutil.PutProperty(principal, "RunLevel", 1)  // TASK_RUNLEVEL_HIGHEST
	principal.Release()

	// RegistrationInfo (optional)
	regInfoDisp, _ := oleutil.GetProperty(taskDef, "RegistrationInfo")
	regInfo := regInfoDisp.ToIDispatch()
	oleutil.PutProperty(regInfo, "Description", "Self-deleting one-time task")
	regInfo.Release()

	// Settings
	settingsDisp, _ := oleutil.GetProperty(taskDef, "Settings")
	settings := settingsDisp.ToIDispatch()
	oleutil.PutProperty(settings, "Enabled", true)
	oleutil.PutProperty(settings, "StartWhenAvailable", true)
	oleutil.PutProperty(settings, "Hidden", false)
	oleutil.PutProperty(settings, "DeleteExpiredTaskAfter", "PT1M") // Delete 1 minute after end
	settings.Release()

	// Trigger
	triggersDisp, _ := oleutil.GetProperty(taskDef, "Triggers")
	triggers := triggersDisp.ToIDispatch()
	defer triggers.Release()

	startTime := time.Now().UTC().Add(1 * time.Minute)
	endTime := startTime.Add(5 * time.Minute)

	startBoundary := startTime.Format("2006-01-02T15:04:05")
	endBoundary := endTime.Format("2006-01-02T15:04:05")

	triggerDisp, _ := oleutil.CallMethod(triggers, "Create", 1) // TIME_TRIGGER_ONCE
	trigger := triggerDisp.ToIDispatch()
	oleutil.PutProperty(trigger, "StartBoundary", startBoundary)
	oleutil.PutProperty(trigger, "EndBoundary", endBoundary)
	oleutil.PutProperty(trigger, "Enabled", true)
	trigger.Release()

	// Actions
	actionsDisp, _ := oleutil.GetProperty(taskDef, "Actions")
	actions := actionsDisp.ToIDispatch()
	defer actions.Release()

	actionDisp, _ := oleutil.CallMethod(actions, "Create", 0) // TASK_ACTION_EXEC
	action := actionDisp.ToIDispatch()
	oleutil.PutProperty(action, "Path", "cmd.exe")
	oleutil.PutProperty(action, "Arguments", fmt.Sprintf("/c %s", commandLine))
	action.Release()

	// Register task
	var registeredTask *ole.VARIANT
	registeredTask, err = oleutil.CallMethod(
		rootFolder,
		"RegisterTaskDefinition",
		taskName,
		taskDef,
		6,   // TASK_CREATE_OR_UPDATE | TASK_RUN
		nil, // No user
		nil, // No password
		5,   // TASK_LOGON_SERVICE_ACCOUNT
		"",
	)
	if err != nil {
		if comErr, ok := err.(*ole.OleError); ok {
			return fmt.Errorf("failed to register task: HRESULT 0x%X (%v)", comErr.Code(), comErr)
		}
		return fmt.Errorf("failed to register task: %v", err)
	}
	defer registeredTask.Clear()

	// Retrieve task instance
	taskDisp, err := oleutil.CallMethod(rootFolder, "GetTask", taskName)
	if err != nil {
		return fmt.Errorf("failed to get task: %v", err)
	}
	task := taskDisp.ToIDispatch()
	defer task.Release()

	// Run task
	runningDisp, err := oleutil.CallMethod(task, "Run", nil)
	if err != nil {
		return fmt.Errorf("failed to run task: %v", err)
	}
	running := runningDisp.ToIDispatch()
	defer running.Release()

	return nil
}
