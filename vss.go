package main

import (
	"fmt"
	"github.com/joeavanzato/impact/drives"
	"github.com/mxk/go-vss"
)

func RemoveShadowCopies(isRemoteDevice bool) error {
	if isRemoteDevice {
		// We won't do this remotely, only if running locally
		return nil
	}
	localDrives, err := drives.GetLocalDrives()
	if err != nil {
		return err
	}
	for _, drive := range localDrives {
		if drive.IsRemovable == true {
			continue
		}
		copies, err := vss.List(drive.Name)
		if err != nil {
			continue
		}
		if len(copies) == 0 {
			continue
		}
		for _, c := range copies {
			printFormattedMessage(fmt.Sprintf("Deleting shadow copy: %s", c.ID), INFO)
			err = vss.Remove(c.ID)
			if err != nil {
				printFormattedMessage(fmt.Sprintf("Error deleting shadow copy: %s", err.Error()), ERROR)
			}
		}

	}
	return nil
}
