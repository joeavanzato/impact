package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func printFormattedMessage(msg string, level LogLevel) {
	ts := time.Now().Format("2006-01-02T15:04:05.000Z")
	fmt.Printf("%s|%s| %s\n", ts, level, msg)
}

func generateDecryptInstructions(targetDir string, privateKeyData AsymKeyHandler, cipher string, recurse bool) {
	decryptionCommand := ""
	if privateKeyData.System == "ecc" {
		decryptionCommand = fmt.Sprintf("impact -directory \"%s\" -skipconfirm -ecc_private \"%s\" -cipher %s -decrypt", targetDir, privateKeyData.ECCPrivateKeyFile, cipher)
	} else if privateKeyData.System == "rsa" {
		decryptionCommand = fmt.Sprintf("impact -directory \"%s\" -skipconfirm -rsa_private \"%s\" -cipher %s -decrypt", targetDir, privateKeyData.RSAPrivateKeyFile, cipher)
	}
	if recurse {
		decryptionCommand += " -recursive"
	}
	f, err := os.Create("decryption_command.txt")
	defer f.Close()
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening decryption command file: %s", err.Error()), ERROR)
		return
	}
	f.WriteString(decryptionCommand)
}

func removeLastExtension(filename string) string {
	ext := filepath.Ext(filename)
	if ext != "" {
		return strings.TrimSuffix(filename, ext)
	}
	return filename
}
