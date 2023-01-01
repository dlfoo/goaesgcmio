// Provides helper functions and consts shared by both reader and writer.

package goaesgcmio

import (
	"crypto/aes"
	"crypto/rand"
	"io"
)

const (
	defaultChunkSize = 512 // Default size of each chunk written to the dest.
	nonceSize        = 12  // Amount of bytes to read for random nonce.
	gcmTagSize       = 16  // Size of generated GCM tag.
)

func defaultNonce() ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// payloadSize ensures the size of the plaintext payload is in multiples
// of aes.Blocksize. Subtract nonceSize and gcm additions as they are already appended
// to the ciphertext bytes output.
func payloadSize(n int) int {
	return ((n - nonceSize - gcmTagSize) / aes.BlockSize) * aes.BlockSize
}

// Determine size of reader chunks.
func readerChunkSize(n, chunkSize int) int {
	size := (n / chunkSize) * chunkSize
	if size <= 0 {
		size = chunkSize // Use chunkSize if n is too small.
	}
	return size
}
