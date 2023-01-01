// Examples for the aesgcmio package go pkg docs.

package goaesgcmio_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	gcm "github.com/dlfoo/go-aes-gcm-io"
)

// This example shows writing cleartext to an io.Writer.
// Note: You can't compare the ciphertext bytes output to the Reader.Read()
// example below, due to the random nonce.
func ExampleNewWriter() {
	// Declare the key we will use to encrypt the cleartext.
	key, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		// TODO: handle error.
	}

	// Decode the cleartext hex of 10 bytes.
	cleartext, err := hex.DecodeString("5d81f3c1b7d7bc599439")
	if err != nil {
		// TODO: handle error.
	}

	cipherTextBuffer := new(bytes.Buffer)

	// Create new GCM writer to encrypt ciphertext buffer. Setting 0 means
	// default chunk size will be used.
	w, err := gcm.NewWriter(cipherTextBuffer, key, 0)
	if err != nil {
		// TODO: handle error.
	}

	// Write the cleartext bytes to the cipherTextWriter.
	_, err = io.Copy(w, bytes.NewBuffer(cleartext))
	if err != nil {
		// TODO: handle error.
	}

	// Be sure to explicitly close the writer to flush any remaining data.
	if err := w.Close(); err != nil {
		// TODO: handle error.
	}

	fmt.Printf("Cleartext: %x\n", cleartext)
	fmt.Printf("Cleartext Size: %d bytes\n", len(cleartext))
	fmt.Printf("Ciphertext: %x\n", cipherTextBuffer.Bytes())
	fmt.Printf("Ciphertext Size: %d bytes\n", cipherTextBuffer.Len())
}

// This example shows reading ciphertext from an io.Reader.
func ExampleNewReader() {
	// Declare the key we will use to decrypt the ciphertext.
	key, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		// TODO: handle error.
	}

	// Decode the cleartext hex of 10 bytes.
	cleartext, err := hex.DecodeString("5d81f3c1b7d7bc599439")
	if err != nil {
		// TODO: handle error.
	}

	// Decode ciphertext hex which is 42 bytes (10 cleartext, 28 aes/gcm, 4 chunkSize.
	ciphertext, err := hex.DecodeString("fc010000f44a6d308c86b3360d2b891dda518dcf3df1aac63ff762e506cb4d0d3495c6d6d41e3eb6d69d")
	if err != nil {
		// TODO: handle error.
	}

	// Create new reader to decrypt ciphertext.
	r, err := gcm.NewReader(bytes.NewBuffer(ciphertext), key)
	if err != nil {
		// TODO: handle error.
	}

	cleartextBuffer := new(bytes.Buffer)

	// Read the cleartext cleartext from the reader.
	_, err = io.Copy(cleartextBuffer, r)
	if err != nil {
		// TODO: handle error.
	}

	fmt.Printf("Cleartext: %x\n", cleartext)
	fmt.Printf("Cleartext Size: %d bytes\n", len(cleartext))
	fmt.Printf("Cleartext: %x\n", cleartextBuffer.Bytes())
	fmt.Printf("Cleartext Size: %d bytes\n", cleartextBuffer.Len())
	fmt.Printf("Equal: %t\n", bytes.Equal(cleartext, cleartextBuffer.Bytes()))
}
