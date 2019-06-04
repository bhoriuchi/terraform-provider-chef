package chefcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

// CipherV1 the v1 cipher used
const CipherV1 = "aes-256-cbc"

// EncryptedDataBagItemV1 version 1 encrypted databag
type EncryptedDataBagItemV1 struct {
	EncryptedData string `json:"encrypted_data"`
	IV            string `json:"iv"`
	Version       int    `json:"version"`
	Cipher        string `json:"cipher"`
}

// IsValid validates the encrypted databag
func (c *EncryptedDataBagItemV1) IsValid() bool {
	return c.EncryptedData != "" &&
		c.IV != "" &&
		c.Version == Version1 &&
		c.Cipher == CipherV1
}

// GetVersion returns the databag version
func (c *EncryptedDataBagItemV1) GetVersion() int {
	return c.Version
}

// Decrypt decrypts the v1 databag
func (c *EncryptedDataBagItemV1) Decrypt(key []byte, target interface{}) error {
	tgtVal := reflect.ValueOf(target)
	if tgtVal.Kind() != reflect.Ptr || tgtVal.IsNil() {
		return ErrInvalidTarget
	} else if len(key) == 0 {
		return ErrInvalidSecretKey
	} else if c.Cipher != CipherV1 {
		return fmt.Errorf("invalid data bag cipher: expected %q, got %q", CipherV1, c.Cipher)
	}

	var res map[string]interface{}
	keyHash := hashKey(key)

	// create a new AES cipher
	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return err
	}

	// decode the encrypted data from base64
	data, err := base64.StdEncoding.DecodeString(c.EncryptedData)
	if err != nil {
		return err
	}

	// decode iv from base64
	iv, err := base64.StdEncoding.DecodeString(c.IV)
	if err != nil {
		return err
	}

	// create a new decryptor
	aescbc := cipher.NewCBCDecrypter(block, iv)
	aescbc.CryptBlocks(data, data)

	// unpad the data
	decrypted, err := pkcs7Unpad(data, aes.BlockSize)
	if err != nil {
		return err
	}

	// unmarshal the json
	err = json.Unmarshal(decrypted, &res)
	if err != nil {
		return err
	}

	// look for the json wrapper
	val, ok := res["json_wrapper"]
	if !ok {
		return ErrDecryptFailed
	}

	// assign the value to the target
	reflect.ValueOf(target).Elem().Set(reflect.ValueOf(&val).Elem())
	return nil
}

// EncryptDataBagItemV1 encrypts a databag with the v1 specification
func EncryptDataBagItemV1(key, jsonData []byte) (*EncryptedDataBagItemV1, error) {
	keyHash := hashKey(key)

	// create a new AES cipher
	block, err := aes.NewCipher(keyHash)
	if err != nil {
		return nil, err
	}

	// wrap the data in json. data should be json formatted
	wrappedData := fmt.Sprintf("{\"json_wrapper\":%s}", jsonData)

	// generate a nonce
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// encrypt the data
	aescbc := cipher.NewCBCEncrypter(block, iv)
	ciphertext, err := pkcs7Pad([]byte(wrappedData), aes.BlockSize)
	if err != nil {
		return nil, err
	}

	aescbc.CryptBlocks(ciphertext, ciphertext)

	// create the databag
	databag := EncryptedDataBagItemV1{
		EncryptedData: formatBase64(ciphertext),
		IV:            formatBase64(iv),
		Version:       Version1,
		Cipher:        CipherV1,
	}

	return &databag, nil
}
