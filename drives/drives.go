// Package drives provides functionality to enumerate local drives and network shares.
package drives

// DriveInfo represents information about a logical drive
type DriveInfo struct {
	Name        string // Drive name/letter (e.g., "C:", "/dev/sda1")
	MountPoint  string // Mount point (e.g., "C:\", "/mnt/data")
	FileSystem  string // File system type (e.g., "NTFS", "ext4")
	TotalSpace  uint64 // Total space in bytes
	FreeSpace   uint64 // Free space in bytes
	IsRemovable bool   // Whether the drive is removable
}

// NetworkShareInfo represents information about a network share
type NetworkShareInfo struct {
	Name        string // Share name
	RemotePath  string // Remote path (e.g., "\\server\share")
	MountPoint  string // Local mount point (if applicable)
	Description string // Share description
}

// GetLocalDrives returns a list of all logical drives in the system
func GetLocalDrives() ([]DriveInfo, error) {
	return getLocalDrivesImpl()
}

// GetNetworkShares returns a list of all connected network shares
func GetNetworkShares() ([]NetworkShareInfo, error) {
	return getNetworkSharesImpl()
}

/*	logicalDisks := make([]string, 0)
	if target_dir == "*" {
		//enumerateDrives()
		//drives.TryGetDrives()
		// Get local drives
		localDrives, err := drives.GetLocalDrives()
		if err != nil {
			log.Fatalf("Error getting local drives: %v", err)
		}

		fmt.Println("=== Local Drives ===")
		for i, drive := range localDrives {
			fmt.Printf("%d. Drive: %s\n", i+1, drive.Name)
			fmt.Printf("   Mount Point: %s\n", drive.MountPoint)
			fmt.Printf("   File System: %s\n", drive.FileSystem)
			fmt.Printf("   Total Space: %.2f GB\n", float64(drive.TotalSpace)/(1024*1024*1024))
			fmt.Printf("   Free Space: %.2f GB\n", float64(drive.FreeSpace)/(1024*1024*1024))
			fmt.Printf("   Removable: %t\n\n", drive.IsRemovable)
		}

		// Get network shares
		networkShares, err := drives.GetNetworkShares()
		if err != nil {
			log.Fatalf("Error getting network shares: %v", err)
		}

		fmt.Println("=== Network Shares ===")
		for i, share := range networkShares {
			fmt.Printf("%d. Share: %s\n", i+1, share.Name)
			fmt.Printf("   Remote Path: %s\n", share.RemotePath)
			fmt.Printf("   Mount Point: %s\n", share.MountPoint)
			fmt.Printf("   Description: %s\n\n", share.Description)
		}
	}*/
