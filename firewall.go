package main

import (
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Constants for the Windows Firewall API
const (
	NET_FW_PROFILE2_DOMAIN  = 1
	NET_FW_PROFILE2_PRIVATE = 2
	NET_FW_PROFILE2_PUBLIC  = 4
)

// Check if Windows Firewall is enabled using WMI
func IsWindowsFirewallEnabled() (bool, error) {
	// Option 1: Check directly in the registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`, registry.QUERY_VALUE)
	if err != nil {
		return false, fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	// Read the EnableFirewall value
	enableFirewall, _, err := key.GetIntegerValue("EnableFirewall")
	if err != nil {
		return false, fmt.Errorf("failed to read EnableFirewall value: %w", err)
	} else if enableFirewall == 1 {
		return true, nil
	}

	// Also check the public profile (common in Windows 10+)
	publicKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile`, registry.QUERY_VALUE)
	if err == nil {
		defer publicKey.Close()
		publicEnableFirewall, _, err := publicKey.GetIntegerValue("EnableFirewall")
		if err == nil && publicEnableFirewall == 1 {
			return true, nil
		}
	}

	// Also check the domain profile
	domainKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile`, registry.QUERY_VALUE)
	if err == nil {
		defer domainKey.Close()
		domainEnableFirewall, _, err := domainKey.GetIntegerValue("EnableFirewall")
		if err == nil && domainEnableFirewall == 1 {
			return true, nil
		}
	}

	return enableFirewall == 1, nil
}

func IsWindowsFirewallEnabledCOM() (bool, error) {
	// Initialize COM
	err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED)
	if err != nil {
		return false, fmt.Errorf("failed to initialize COM: %w", err)
	}
	defer windows.CoUninitialize()

	// Define the GUIDs
	CLSID_NetFwPolicy2 := windows.GUID{
		Data1: 0xE2B3C97F,
		Data2: 0x6AE1,
		Data3: 0x41FF,
		Data4: [8]byte{0x6E, 0x89, 0xD3, 0xD3, 0x95, 0x4C, 0x29, 0x44},
	}
	IID_INetFwPolicy2 := windows.GUID{
		Data1: 0x98325047,
		Data2: 0xC671,
		Data3: 0x4174,
		Data4: [8]byte{0x8D, 0x74, 0xC9, 0xE6, 0x20, 0x78, 0x39, 0x34},
	}

	// COM interface definition
	type INetFwPolicy2Vtbl struct {
		QueryInterface              uintptr
		AddRef                      uintptr
		Release                     uintptr
		GetTypeInfoCount            uintptr
		GetTypeInfo                 uintptr
		GetIDsOfNames               uintptr
		Invoke                      uintptr
		GetCurrentProfileTypes      uintptr
		BlockAllInboundTraffic      uintptr
		NotificationsDisabled       uintptr
		UnicastResponsesToMulticast uintptr
		Rules                       uintptr
		ServiceRestriction          uintptr
		DefaultInboundAction        uintptr
		DefaultOutboundAction       uintptr
		IsRuleGroupEnabled          uintptr
		LocalPolicyModifyState      uintptr
		EnableRuleGroup             uintptr
		IsFirewallEnabled           uintptr
	}

	type INetFwPolicy2 struct {
		Vtbl *INetFwPolicy2Vtbl
	}

	var policy *INetFwPolicy2
	hr, _, _ := syscall.Syscall6(
		windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance").Addr(),
		5,
		uintptr(unsafe.Pointer(&CLSID_NetFwPolicy2)),
		0,
		uintptr(windows.CLSCTX_INPROC_SERVER),
		uintptr(unsafe.Pointer(&IID_INetFwPolicy2)),
		uintptr(unsafe.Pointer(&policy)),
		0,
	)
	if hr != 0 {
		return false, fmt.Errorf("failed to create NetFwPolicy2 instance: %d", hr)
	}
	if policy == nil {
		return false, fmt.Errorf("failed to create NetFwPolicy2 instance: policy is nil")
	}
	defer func() {
		syscall.Syscall(policy.Vtbl.Release, 1, uintptr(unsafe.Pointer(policy)), 0, 0)
	}()

	// Check each profile
	domains := []int32{NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC}
	for _, domain := range domains {
		var enabled int32
		hr, _, _ = syscall.Syscall(
			policy.Vtbl.IsFirewallEnabled,
			3,
			uintptr(unsafe.Pointer(policy)),
			uintptr(domain),
			uintptr(unsafe.Pointer(&enabled)),
		)
		if hr != 0 {
			continue
		}
		if enabled != 0 {
			return true, nil
		}
	}

	return false, nil
}

func handlePortBlocking(decrypting bool, config *Config) {
	// If we are decrypting, we should attempt to REMOVE any firewall rule added
	printFormattedMessage("Checking Windows Firewall status", INFO)
	enabled, err := IsWindowsFirewallEnabled()
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error checking firewall status: %v", err.Error()), ERROR)
		return
	}
	if !enabled {
		printFormattedMessage("Windows Firewall is not enabled", INFO)
		return
	}
	ports := ""
	for i, port := range config.Ports {
		if i == len(config.Ports)-1 {
			ports += fmt.Sprintf("%d", port)
		} else {
			ports += fmt.Sprintf("%d,", port)
		}
	}
	if enabled && !decrypting {
		// Add Rule
		cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+config.FWRuleName, "dir=out", "remoteport="+ports, "action=block", "interfacetype=any", "protocol=tcp")
		err = cmd.Run()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error adding firewall rule: %s", err.Error()), ERROR)
		}
	} else if enabled && decrypting {
		// Remove Rule
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+config.FWRuleName)
		err = cmd.Run()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error removing firewall rule: %s", err.Error()), ERROR)
		}
	}

}

func editHosts(config Config, decrypting bool) {
	// If we are decrypting, we should attempt to REMOVE any hosts.etc section that may have been added
}

func handleDomainBlocking(decrypting bool, config *Config) {
	// If we are decrypting, we should attempt to REMOVE any firewall rule added
	printFormattedMessage("Checking Windows Firewall status", INFO)
	enabled, err := IsWindowsFirewallEnabled()
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error checking firewall status: %v", err.Error()), ERROR)
		return
	}
	if !enabled {
		// TODO - Should we enable?
		printFormattedMessage("Windows Firewall is not enabled", INFO)
		return
	}
	ipsToBlock := make([]string, 0)
	// We need to do a DNS lookup on the configured domains
	// TODO - Add concurrency inline
	for _, v := range config.Domains {
		ips, err := net.LookupIP(v)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error looking up domain %s: %s", v, err.Error()), ERROR)
			continue
		}
		for _, ip := range ips {
			fmt.Println(ip)
			ipsToBlock = append(ipsToBlock, ip.String())
		}
	}

	ips := ""
	for i, ip := range ipsToBlock {
		if i == len(ipsToBlock)-1 {
			ips += fmt.Sprintf("%s", ip)
		} else {
			ips += fmt.Sprintf("%s,", ip)
		}
	}

	if enabled && !decrypting {
		// Add Rule
		cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+config.FWDomainRuleName, "dir=out", "remoteip="+ips, "action=block", "interfacetype=any")
		fmt.Println(cmd)
		err = cmd.Run()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error adding firewall rule: %s", err.Error()), ERROR)
		}
	} else if enabled && decrypting {
		// Remove Rule
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+config.FWDomainRuleName)
		err = cmd.Run()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error removing firewall rule: %s", err.Error()), ERROR)
		}
	}

}
