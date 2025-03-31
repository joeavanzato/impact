package main

import (
	r "crypto/rand"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// printFormattedMessage - a psuedo-logging mechanism since I didn't want to deploy zerolog for whatever reason
func printFormattedMessage(msg string, level LogLevel) {
	ts := time.Now().Format("2006-01-02T15:04:05.000Z")
	fmt.Printf("%s|%s| %s\n", ts, level, msg)
}

// generateDecryptInstructions - generates 'decryption_command.txt' when performing an encryption directive to assist in reversing the operation
func generateDecryptInstructions(targetDir string, privateKeyData AsymKeyHandler, cipher string, recurse bool) {
	decryptionCommand := ""
	keyFile := ""
	if privateKeyData.System == "ecc" {
		if privateKeyData.ECCPrivateKeyFile == "" {
			keyFile = "ecc_key.ecc"
		} else {
			keyFile = privateKeyData.ECCPrivateKeyFile
		}
	} else if privateKeyData.System == "rsa" {
		if privateKeyData.RSAPrivateKeyFile == "" {
			keyFile = "rsa_key.rsa"
		} else {
			keyFile = privateKeyData.RSAPrivateKeyFile
		}
	}

	if privateKeyData.System == "ecc" {
		decryptionCommand = fmt.Sprintf("impact -directory \"%s\" -skipconfirm -ecc_private \"%s\" -cipher %s -decrypt", targetDir, keyFile, cipher)
	} else if privateKeyData.System == "rsa" {
		decryptionCommand = fmt.Sprintf("impact -directory \"%s\" -skipconfirm -rsa_private \"%s\" -cipher %s -decrypt", targetDir, keyFile, cipher)
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

// removeLastExtension - Removes the last extension from a filepath and returns the filepath without the extension
func removeLastExtension(filename string) string {
	ext := filepath.Ext(filename)
	if ext != "" {
		return strings.TrimSuffix(filename, ext)
	}
	return filename
}

// ReadConfig - Handles reading the embedded configuration file containing ransomware group metadata
func ReadConfig() (Config, error) {
	var tmp Config
	var data []byte
	var readerr error
	data, readerr = configFile.ReadFile("config.yaml")
	if readerr != nil {
		return tmp, readerr
	}
	err := yaml.Unmarshal(data, &tmp)
	if err != nil {
		return tmp, fmt.Errorf("YAML Unmarshal Error: %w", err)
	}
	return tmp, err
}

// doesOSEntryExist - basic wrapper
func doesOSEntryExist(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	return nil
}

// makeDirectory - basic wrapper
func makeDirectory(dir string) error {
	err := os.Mkdir(dir, os.ModeDir)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

// createNote - Used to create the specified ransomware note on disk
func createNote(note string, noteName string, destDir string) {
	f, _ := os.Create(filepath.Join(destDir, noteName))
	f.Write([]byte(note))
	f.Close()
}

// gatherFiles - Only used to identify top-level files in a directory when operating non-recursively
func gatherFiles(fileList []string, recursive bool, targetDir string) ([]string, error) {
	if !recursive {
		files, _ := os.ReadDir(targetDir)
		for _, v := range files {
			if v.IsDir() {
				continue
			}
			fileList = append(fileList, filepath.Join(targetDir, v.Name()))
		}
	} else {
		filepath.Walk(targetDir,
			func(path string, info os.FileInfo, err error) error {
				fileList = append(fileList, path)
				return nil
			})
	}
	return fileList, nil
}

func replaceExtensionVariables(extension string) string {
	var runes = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	for true {
		if strings.Contains(extension, "%R") {
			extension = strings.Replace(extension, "%R", string(runes[rand.Intn(len(runes))]), 1)
		} else {
			break
		}
	}
	return extension
}

// CreateFiles - Handles the creation of dummy data inside the target directory
func CreateFiles(fileCount int, fileSize int, targetdir string) (error, []string) {
	printFormattedMessage(fmt.Sprintf("Creating Dummy Data inside directory: %s", targetdir), INFO)
	printFormattedMessage(fmt.Sprintf("Target Size: %d Megabytes", fileSize), INFO)
	printFormattedMessage(fmt.Sprintf("Target File Count: %d", fileCount), INFO)
	fileList := make([]string, 0)
	// Makes a random number of subdirectories followed by numbers and dates and distributes chunks of files into them
	validDirs := make([]string, 0)
	subdir_count := rand.Intn(20) + 3
	for i := 0; i < subdir_count; i++ {
		tmp := filepath.Join(targetdir, fmt.Sprintf("%s_%d_%d_%d", subdir_names[rand.Intn(len(subdir_names))], time.Now().Year(), rand.Intn(12), rand.Intn(60)))
		err := makeDirectory(tmp)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error Creating Directory: %s", err.Error()), ERROR)
			continue
		}
		validDirs = append(validDirs, tmp)
	}
	// Now we have a set of directories to load files into
	// We will distribute the files as evenly as possible between the directories
	targetFileSizeMegabytes := float64(fileSize) / float64(fileCount)
	targetFileSizeBytes := int(targetFileSizeMegabytes * (1 << 20))
	filesPerDirectory := fileCount / len(validDirs)
	var wg sync.WaitGroup
	for _, v := range validDirs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < filesPerDirectory; i++ {
				tmpFileName := fmt.Sprintf("%s_%s_%d_%d_%d.%s", file_names[rand.Intn(len(file_names))], subFileNames[rand.Intn(len(subFileNames))], rand.Intn(30), time.Now().Year(), rand.Intn(60), dummy_extensions[rand.Intn(len(dummy_extensions))])
				tmpFileFull := filepath.Join(v, tmpFileName)
				f, err := os.Create(tmpFileFull)
				if err != nil {
					printFormattedMessage(fmt.Sprintf("Error Creating File: %s", err.Error()), ERROR)
					continue
				}
				io.Copy(f, io.LimitReader(r.Reader, int64(targetFileSizeBytes)))
				fileList = append(fileList, tmpFileFull)
				f.Close()
			}
		}()
	}
	wg.Wait()
	return nil, fileList
}
