package chefcrypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	// MinimumVersion is the minimum encryption version supported
	MinimumVersion = 1

	// MaximumVersion is the maximum encryption version supported
	MaximumVersion = 3

	// Version1 version 1 encrypted data bag item
	Version1 = 1

	// Version2 version 2 encrypted data bag item
	Version2 = 2

	// Version3 version 3 encrypted data bag item
	Version3 = 3

	// VersionLatest latest version supported currently 3
	VersionLatest = 3

	// standard GCM sizes
	gcmStandardNonceSize = 12
	gcmTagSize           = 16
)

// ErrItemNotValid invalid data bag
var ErrItemNotValid = errors.New("data is not an encrypted data bag item")

// ErrUnsupportedVersion unsupported encryption version
var ErrUnsupportedVersion = errors.New("unsupported encryption version")

// ErrInvalidTarget invalid target pointer
var ErrInvalidTarget = errors.New("target must be a non-nil pointer")

// ErrInvalidSecretKey invalid secret key
var ErrInvalidSecretKey = errors.New("key must be a non-empty byte array")

// ErrDecryptFailed decryption failed
var ErrDecryptFailed = errors.New("failed to decrypt data bag")

// ErrSignatureValidationFailed hmac validation failed
var ErrSignatureValidationFailed = errors.New("signature validation failed, an invalid secret key was most likely used")

// EncryptedDataBagItem item interface
type EncryptedDataBagItem interface {
	Decrypt(key []byte, target interface{}) error
	IsValid() bool
	GetVersion() int
}

// Encrypt encrypts the data using the specified key and encryption version
func Encrypt(key, data []byte, version int) (EncryptedDataBagItem, error) {
	switch version {
	case Version1:
		return EncryptDataBagItemV1(key, data)
	case Version2:
		return EncryptDataBagItemV2(key, data)
	case Version3:
		return EncryptDataBagItemV3(key, data)
	default:
		return nil, ErrUnsupportedVersion
	}
}

// Decrypt decrypts the data bag item with the appropriate encryption version
func Decrypt(key, data []byte, target interface{}) error {
	encrypted, version, err := IsEncryptedDataBagItem(data)
	if err != nil || !encrypted {
		return ErrItemNotValid
	}

	var item EncryptedDataBagItem

	switch version {
	case Version1:
		item = &EncryptedDataBagItemV1{}
	case Version2:
		item = &EncryptedDataBagItemV2{}
	case Version3:
		item = &EncryptedDataBagItemV3{}
	default:
		return ErrUnsupportedVersion
	}

	if err := json.Unmarshal(data, &item); err != nil {
		return err
	}

	return item.Decrypt(key, target)
}

// IsEncryptedDataBagItem determines if the databag is encrypted and if so what version
func IsEncryptedDataBagItem(data []byte) (bool, int, error) {
	// decrypt data bag as a v1 since that contains all the
	// basic fields for a data bag
	var databag EncryptedDataBagItemV1
	if err := json.Unmarshal(data, &databag); err != nil {
		return false, -1, err
	}

	// check if item is a valid databag
	if databag.EncryptedData == "" ||
		databag.IV == "" ||
		databag.Cipher == "" ||
		!isValidVersion(databag.Version) {
		return false, -1, ErrItemNotValid
	}

	// return true with the version and the map
	return true, databag.GetVersion(), nil
}

// NewSecretKey generates a new secret key of specified length
func NewSecretKey(length int) ([]byte, error) {
	if length%128 > 0 {
		return nil, fmt.Errorf("key length must be a multiple of 128")
	}

	key := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	return key, nil
}

// NewSecretKeyBase64 generates a new secret key of specified length
func NewSecretKeyBase64(length int) (*string, error) {
	key, err := NewSecretKey(length)
	if err != nil {
		return nil, err
	}
	b64key := base64.StdEncoding.EncodeToString(key)
	return &b64key, nil
}

// hash the key
func hashKey(key []byte) []byte {
	hash := sha256.New()
	hash.Write(key)
	return hash.Sum(nil)
}

// create a hmac from the encrypted data and key
func encryptedDataHMAC(keyHash, encryptedData []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, keyHash)
	if _, err := mac.Write(encryptedData); err != nil {
		return nil, err
	}
	sum := mac.Sum(nil)
	return sum, nil
}

// pkcs7Pad appends padding.
// from https://github.com/Luzifer/go-openssl/blob/master/openssl.go
func pkcs7Pad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	padlen := 1
	for ((len(data) + padlen) % blocklen) != 0 {
		padlen = padlen + 1
	}

	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(data, pad...), nil
}

// pkcs7Unpad returns slice of the original data without padding.
// from https://github.com/Luzifer/go-openssl/blob/master/openssl.go
func pkcs7Unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen <= 0 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}
	padlen := int(data[len(data)-1])
	if padlen > blocklen || padlen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	pad := data[len(data)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padlen], nil
}

// formats data as base 64 in lines of 60 characters
// with a trailing new line (why 60?)
func formatBase64(data []byte) string {
	b64str := base64.StdEncoding.EncodeToString(data)
	rx := regexp.MustCompile(`.{1,60}`)
	blocks := rx.FindAllString(b64str, -1)
	return fmt.Sprintf("%s\n", strings.Join(blocks, "\n"))
}

// checks if the version is within the valid range
func isValidVersion(version int) bool {
	return version >= MinimumVersion && version <= MaximumVersion
}
