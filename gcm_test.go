// Tests for the aesgcmio package.

package goaesgcmio_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"testing"

	gcm "github.com/dlfoo/goaesgcmio"
)

var (
	key = make([]byte, 32)
)

// random creates a random payload of n bytes.
func random(n int64) ([]byte, error) {
	plaintext := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func init() {
	k, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		log.Fatal(err)
	}
	key = k
}

func TestWriteAndRead(t *testing.T) {

	tests := []struct {
		name          string
		key           []byte
		plaintextSize int64
		chunkSize     int
		equal         bool
		wantErr       bool
	}{
		{
			name:          "regular write and read",
			key:           key,
			plaintextSize: 50,
			chunkSize:     250,
			equal:         true,
		},
		{
			name:          "larger chunk size",
			key:           key,
			plaintextSize: 50,
			chunkSize:     512000,
			equal:         true,
		},
		{
			name:          "regular write and read negative test",
			key:           key,
			plaintextSize: 50,
			chunkSize:     250,
			equal:         false,
			wantErr:       true,
		},
		{
			name:          "larger plaintext size",
			key:           key,
			plaintextSize: 512000,
			chunkSize:     600,
			equal:         true,
		},
	}

	for _, test := range tests {
		p, err := random(test.plaintextSize)
		if err != nil {
			t.Fatalf("could not generate random payload, got err; %v", err)
		}

		// for cleartext input.
		cleartext := bytes.NewBuffer(p)

		// for ciphertext.
		ciphertext := new(bytes.Buffer)

		// for cleartext output.
		got := new(bytes.Buffer)

		// Create new GCM writer to encrypt ciphertext buffer.
		w, err := gcm.NewWriter(ciphertext, test.key, 0)
		if err != nil {
			t.Fatalf("could not create gcm writer, got err; %v", err)
		}

		// Write entire payload.
		_, err = io.Copy(w, cleartext)
		if err != nil {
			t.Fatalf("got err writing cleartext to ciphertext writer; %v", err)
		}

		if err := w.Close(); err != nil {
			t.Fatalf("got err closing ciphertext writer; %v", err)
		}

		// Create new reader to decrypt ciphertext buffer.
		r, err := gcm.NewReader(ciphertext, test.key)
		if err != nil {
			t.Fatalf("could not create gcm reader, got err; %v", err)
		}

		_, err = io.Copy(got, r)
		if err != nil {
			t.Fatalf("got err reading ciphertext from ciphertext reader; %v", err)
		}

		diff := bytes.Compare(p, got.Bytes())
		if test.equal && diff != 0 {
			if !test.wantErr {
				t.Errorf("cleartext decrypted bytes of len %d did not match cleartext input bytes of len %d", got.Len(), len(p))
			}
		}
		if !test.equal && diff == 0 {
			if !test.wantErr {
				t.Errorf("wanted decrypted bytes of len %d not equal to cleartext input bytes of len %d", got.Len(), len(p))
			}
		}
	}
}

func TestIrreggularPatterns(t *testing.T) {
	tests := []struct {
		name          string
		key           []byte
		plaintextSize int64
		chunkSize     int
		firstRead     int64
		lastRead      int64
		firstWrite    int64
		lastWrite     int64
		equal         bool
		wantErr       bool
	}{
		{
			name:          "regular write and read",
			key:           key,
			plaintextSize: 50,
			chunkSize:     250,
			firstWrite:    10,
			lastWrite:     20,
			firstRead:     10,
			lastRead:      30,
			equal:         true,
		},
		{
			name:          "larger chunk size",
			key:           key,
			plaintextSize: 50,
			chunkSize:     512000,
			firstWrite:    10,
			lastWrite:     20,
			firstRead:     10,
			lastRead:      30,
			equal:         true,
		},
		{
			name:          "regular write and read negative test",
			key:           key,
			plaintextSize: 50,
			chunkSize:     250,
			firstWrite:    10,
			lastWrite:     20,
			firstRead:     10,
			lastRead:      30,
			equal:         false,
			wantErr:       true,
		},
		{
			name:          "larger plaintext size",
			key:           key,
			plaintextSize: 512000,
			chunkSize:     600,
			firstWrite:    10,
			lastWrite:     20,
			firstRead:     10,
			lastRead:      30,
			equal:         true,
		},
	}

	for _, test := range tests {
		p, err := random(test.plaintextSize)
		if err != nil {
			t.Fatalf("could not generate random payload, got err; %v", err)
		}

		// for cleartext input.
		cleartext := bytes.NewBuffer(p)

		// for ciphertext.
		ciphertext := new(bytes.Buffer)

		// for cleartext output.
		got := new(bytes.Buffer)

		// Create new GCM writer to encrypt ciphertext buffer.
		w, err := gcm.NewWriter(ciphertext, test.key, 0)
		if err != nil {
			t.Fatalf("could not create gcm writer, got err; %v", err)
		}

		// Write first chunk of payload.
		n, err := io.CopyN(w, cleartext, test.firstWrite)
		if err != nil {
			t.Fatalf("[first chunk] got err writing cleartext to ciphertext writer; %v", err)
		}

		// Write second chunk of payload.
		_, err = io.CopyN(w, cleartext, int64(len(p))-n-test.lastWrite)
		if err != nil {
			t.Fatalf("[second chunk] got err writing cleartext to ciphertext writer; %v", err)
		}

		// Write remaining bytes of payload.
		_, err = io.Copy(w, cleartext)
		if err != nil {
			t.Fatalf("[last chunk] got err writing cleartext to ciphertext writer; %v", err)
		}

		if err := w.Close(); err != nil {
			t.Fatalf("got err closing ciphertext writer; %v", err)
		}

		// Create new reader to decrypt ciphertext buffer.
		r, err := gcm.NewReader(ciphertext, test.key)
		if err != nil {
			t.Fatalf("could not create gcm reader, got err; %v", err)
		}

		// Read first chunk of payload.
		n, err = io.CopyN(got, r, test.firstRead)
		if err != nil {
			t.Fatalf("[first chunk] got err reading ciphertext from ciphertext reader; %v", err)
		}

		// Read second chunk of payload.
		_, err = io.CopyN(got, r, int64(len(p))-n-test.lastRead)
		if err != nil {
			t.Fatalf("[second chunk] got err reading ciphertext from ciphertext reader; %v", err)
		}

		// Read remaining bytes of payload.
		_, err = io.Copy(got, r)
		if err != nil {
			t.Fatalf("[last chunk] got err reading ciphertext from ciphertext reader; %v", err)
		}

		diff := bytes.Compare(p, got.Bytes())
		if test.equal && diff != 0 {
			if !test.wantErr {
				t.Errorf("cleartext decrypted bytes of len %d did not match cleartext input bytes of len %d", got.Len(), len(p))
			}
		}
		if !test.equal && diff == 0 {
			if !test.wantErr {
				t.Errorf("wanted decrypted bytes of len %d not equal to cleartext input bytes of len %d", got.Len(), len(p))
			}
		}
	}
}
