package main

import (
	"fmt"
	"github.com/gentlemanautomaton/winproc"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"slices"
	"strconv"
)

//https://github.com/capnspacehook/taskmaster

// unsafe.Sizeof(windows.ProcessEntry32{})
const processEntrySize = 568

func KillTargetProcesses(processNames []string, isRemoteHost bool, hostname string) error {
	procs, err := winproc.List(
		//winproc.Include(winproc.ContainsName("winlogon")),
		winproc.IncludeAncestors)
	if err != nil {
		fmt.Printf("Failed to retrieve process list: %v\n", err)
		return err
	}
	pidsKilled := make([]int, 0)

	for _, proc := range procs {
		if slices.Contains(processNames, proc.Name) {
			pid, err := strconv.Atoi(proc.ID.String())
			if err != nil {
				continue
			}
			if slices.Contains(pidsKilled, pid) {
				continue
			}
			fmt.Printf("Killing: %d, %s\n", pid, proc.Name)
			pidsKilled = append(pidsKilled, pid)
			err = KillProcess(pid)
			if err != nil {
				fmt.Println("Error killing process ID %d, %s", pid, err.Error())
			}
		}
	}
	return nil
}

func getRunningProcesses() ([]windows.ProcessEntry32, error) {
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, e
	}
	processList := make([]windows.ProcessEntry32, 0)
	p := windows.ProcessEntry32{Size: processEntrySize}
	for {
		e := windows.Process32Next(h, &p)
		if e != nil {
			return nil, e
		}
		processList = append(processList, p)
	}
	return processList, nil
}

func KillProcess(pid int) error {
	kill := exec.Command("TASKKILL", "/T", "/F", "/PID", strconv.Itoa(pid))
	kill.Stderr = os.Stderr
	kill.Stdout = os.Stdout
	return kill.Run()
}
