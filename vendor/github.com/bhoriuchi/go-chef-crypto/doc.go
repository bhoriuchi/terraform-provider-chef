/*
Package chefcrypto provides functions for encrypting and decrypting Chef encrypted data bag items.

This package does not fetch data from the Chef server.

When encrypting, data must be encoded in JSON (i.e. for a string "\"foo\"" not just "foo")

Example

	package main

	import (
		"fmt"
		"encoding/json"

		cc "github.com/bhoriuchi/go-chef-crypto"
	)

	func main() {
		// generate a key for encryption
		key, _ := cc.NewSecretKey(512)
		secretData := "foo"


		// Encrypt some data
		databag, _ := cc.Encrypt(key, []byte(secretData), cc.VersionLatest)

		// marshal the data
		databagJSON, _ := json.MarshalIndent(databag, "", "  ")

		// Decrypt the databag
		var value interface{}
		cc.Decrypt(key, []byte(databagJSON), &value)

		// Print the data
		fmt.Printf("Secret: %s", value.(string))
	}
*/
package chefcrypto
