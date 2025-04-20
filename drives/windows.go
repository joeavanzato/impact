package drives

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	kernel32         = windows.NewLazySystemDLL("kernel32.dll")
	getLogicalDrives = kernel32.NewProc("GetLogicalDrives")
	getVolumeInfo    = kernel32.NewProc("GetVolumeInformationW")
	getDiskFreeSpace = kernel32.NewProc("GetDiskFreeSpaceExW")
	getDriveType     = kernel32.NewProc("GetDriveTypeW")

	mpr              = windows.NewLazySystemDLL("mpr.dll")
	wNetOpenEnum     = mpr.NewProc("WNetOpenEnumW")
	wNetEnumResource = mpr.NewProc("WNetEnumResourceW")
	wNetCloseEnum    = mpr.NewProc("WNetCloseEnum")
)

// Constants for Windows drive types
const (
	DRIVE_UNKNOWN     = 0
	DRIVE_NO_ROOT_DIR = 1
	DRIVE_REMOVABLE   = 2
	DRIVE_FIXED       = 3
	DRIVE_REMOTE      = 4
	DRIVE_CDROM       = 5
	DRIVE_RAMDISK     = 6
)

// Constants for WNetOpenEnum
const (
	RESOURCE_CONNECTED        = 0x00000001
	RESOURCE_GLOBALNET        = 0x00000002
	RESOURCETYPE_DISK         = 0x00000001
	RESOURCEDISPLAYTYPE_SHARE = 0x00000003
	RESOURCEUSAGE_CONNECTABLE = 0x00000001
)

func getLocalDrivesImpl() ([]DriveInfo, error) {
	mask, _, _ := getLogicalDrives.Call()

	var drives []DriveInfo

	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}

		driveLetter := string('A' + i)
		rootPath := driveLetter + ":\\"

		// Convert to UTF16 pointer
		rootPathPtr, _ := syscall.UTF16PtrFromString(rootPath)

		// Get drive type
		driveType, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(rootPathPtr)))

		// Skip network drives as they'll be handled by GetNetworkShares
		if driveType == DRIVE_REMOTE {
			continue
		}

		// Prepare buffers for volume information
		var volumeNameBuffer [256]uint16
		var fileSystemNameBuffer [256]uint16
		var serialNumber uint32
		var maxComponentLength uint32
		var fileSystemFlags uint32

		getVolumeInfo.Call(
			uintptr(unsafe.Pointer(rootPathPtr)),
			uintptr(unsafe.Pointer(&volumeNameBuffer[0])),
			uintptr(len(volumeNameBuffer)),
			uintptr(unsafe.Pointer(&serialNumber)),
			uintptr(unsafe.Pointer(&maxComponentLength)),
			uintptr(unsafe.Pointer(&fileSystemFlags)),
			uintptr(unsafe.Pointer(&fileSystemNameBuffer[0])),
			uintptr(len(fileSystemNameBuffer)),
		)

		// Get disk space information
		var freeBytesAvailable int64
		var totalBytes int64
		var totalFreeBytes int64

		getDiskFreeSpace.Call(
			uintptr(unsafe.Pointer(rootPathPtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)),
		)

		drives = append(drives, DriveInfo{
			Name:        driveLetter + ":",
			MountPoint:  rootPath,
			FileSystem:  syscall.UTF16ToString(fileSystemNameBuffer[:]),
			TotalSpace:  uint64(totalBytes),
			FreeSpace:   uint64(totalFreeBytes),
			IsRemovable: driveType == DRIVE_REMOVABLE,
		})
	}

	return drives, nil
}

type NETRESOURCE struct {
	dwScope       uint32
	dwType        uint32
	dwDisplayType uint32
	dwUsage       uint32
	lpLocalName   *uint16
	lpRemoteName  *uint16
	lpComment     *uint16
	lpProvider    *uint16
}

func getNetworkSharesImpl() ([]NetworkShareInfo, error) {
	var shares []NetworkShareInfo
	var handle uintptr

	// Open enumeration
	ret, _, _ := wNetOpenEnum.Call(
		uintptr(RESOURCE_CONNECTED),
		uintptr(RESOURCETYPE_DISK),
		0,
		0,
		uintptr(unsafe.Pointer(&handle)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("WNetOpenEnum failed with error code %d", ret)
	}

	defer wNetCloseEnum.Call(handle)

	// Buffer for enumeration
	const bufferSize = 16384
	buffer := make([]byte, bufferSize)

	for {
		// Variables for enumeration
		var count uint32 = 0xFFFFFFFF
		var bufferSizeBytes uint32 = bufferSize

		// Enumerate resources
		ret, _, _ = wNetEnumResource.Call(
			handle,
			uintptr(unsafe.Pointer(&count)),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&bufferSizeBytes)),
		)

		// Check if we're done
		if ret != 0 {
			if ret == 259 { // ERROR_NO_MORE_ITEMS
				break
			}
			return nil, fmt.Errorf("WNetEnumResource failed with error code %d", ret)
		}

		// Process resources
		for i := uint32(0); i < count; i++ {
			offset := uintptr(unsafe.Pointer(&buffer[0])) + uintptr(i)*unsafe.Sizeof(NETRESOURCE{})
			res := (*NETRESOURCE)(unsafe.Pointer(offset))

			var localName, remoteName, comment string

			if res.lpLocalName != nil {
				localName = windows.UTF16PtrToString(res.lpLocalName)
			}

			if res.lpRemoteName != nil {
				remoteName = windows.UTF16PtrToString(res.lpRemoteName)
			}

			if res.lpComment != nil {
				comment = windows.UTF16PtrToString(res.lpComment)
			}

			shares = append(shares, NetworkShareInfo{
				Name:        localName,
				RemotePath:  remoteName,
				MountPoint:  localName,
				Description: comment,
			})
		}
	}

	return shares, nil
}
