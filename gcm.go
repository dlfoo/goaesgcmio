// Implements the io.Reader and io.Writer interface.

package goaesgcmio

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
)

type Reader struct {
	c         cipher.AEAD
	buf       *bytes.Buffer
	src       io.Reader
	chunkSize int
}

func (g *Reader) Read(p []byte) (int, error) {
	todo := readerChunkSize(len(p), g.chunkSize)
	for {
		if todo < g.chunkSize {
			break
		}

		// Always read gross chunk sizes, and modify if todo is smaller.
		size := g.chunkSize
		if (size - todo) > 0 {
			size = todo
		}

		// Read chunkSize amount of bytes from src reader.
		buf := make([]byte, size)
		n, err := g.src.Read(buf)
		if err != nil {
			if err == io.EOF {
				// Need to return remaining bytes on the buffer back
				// to the caller if EOF is received from src reader.
				if g.buf.Len() > 0 {
					break
				}
			}
			return 0, err
		}

		todo -= n

		// Decrypt cipher text chunk.
		b, err := g.c.Open(nil, buf[:g.c.NonceSize()], buf[g.c.NonceSize():n], nil)
		if err != nil {
			return 0, err
		}

		// Write plaintext bytes to buffer.
		_, err = g.buf.Write(b)
		if err != nil {
			return 0, err
		}
	}

	// Read len(p) bytes from buf and return back to caller upon exit.
	// Note: The buffer will likely have bytes left over, due to chunk size.
	n, err := g.buf.Read(p)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// NewReader returns a reader to read plaintext bytes from the encrypted
// source reader.
func NewReader(r io.Reader, key []byte) (*Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	reader := &Reader{
		c:   aesgcm,
		buf: new(bytes.Buffer),
		src: r,
	}

	sizeBuf := make([]byte, 4)
	if _, err := r.Read(sizeBuf); err != nil {
		return nil, err
	}

	reader.chunkSize = int(binary.LittleEndian.Uint32(sizeBuf))
	return reader, nil

}

type Writer struct {
	c           cipher.AEAD
	dst         io.Writer
	buf         *bytes.Buffer
	chunkSize   int
	payloadSize int
}

func (g *Writer) Write(p []byte) (int, error) {
	// todo represents the amount of bytes left to encrypt
	// and write to the destination writer. Note: There may
	// be bytes left over due to the chunkSize below.
	todo := len(p)

	// Write the supplied data to the buffer initially.
	n, err := g.buf.Write(p)
	if err != nil {
		return 0, err
	}

	// Loop until there's no bytes left to encrypt, or the
	// remaining bytes left in the buffer is less than the
	// pre determined chunk size.
	for {
		if todo <= 0 || g.buf.Len() < g.payloadSize {
			break
		}

		// For every chunk read a new nonce from crypto/rand.
		nonce, err := defaultNonce()
		if err != nil {
			return 0, err
		}

		// Prepare buffer of size and read the chunk of data from the buffer.
		buf := make([]byte, g.payloadSize)
		_, err = g.buf.Read(buf)
		if err != nil {
			return 0, err
		}

		// Encrypt the plaintext and prepend the nonce to the start of the
		// chunk. The nonce is always needed to decrypt the cipher text.
		b := g.c.Seal(nonce, nonce, buf, nil)

		// Write cipher text bytes to the destination writer.
		_, err = g.dst.Write(b)
		if err != nil {
			return 0, err
		}

		// Subtract chunk size from todo.
		todo -= g.payloadSize
	}

	// Always return the amount of bytes read from the supplied p.
	return n, nil
}

func (g *Writer) Close() error {
	// Return quickly if there's no bytes remaining on the buffer, nothing
	// more needs to be done.
	if g.buf.Len() <= 0 {
		return nil
	}

	// Read everything remaining on buffer.
	buf, err := io.ReadAll(g.buf)
	if err != nil {
		return err
	}

	// Create new nonce for last chunk.
	nonce, err := defaultNonce()
	if err != nil {
		return err
	}

	// Encrypt the plaintext and prepend the nonce to the start of the
	// chunk. The nonce is always needed to decrypt the cipher text.
	b := g.c.Seal(nonce, nonce, buf, nil)
	_, err = g.dst.Write(b)
	if err != nil {
		return err
	}
	// Close the destination writer.
	return nil
}

// NewWriter returns a writer to write plaintext payload to, if
// chunkSize is set to 0 then defaultChunkSize will be used.
func NewWriter(w io.Writer, key []byte, chunkSize int) (*Writer, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if chunkSize <= 0 {
		chunkSize = defaultChunkSize
	}

	payloadSize := payloadSize(chunkSize)
	size := payloadSize + nonceSize + gcmTagSize

	// Write chunk size to start of destination writer, the reader can then
	// use this to read that size chunks from the source reader.
	if err := binary.Write(w, binary.LittleEndian, uint32(size)); err != nil {
		panic(err.Error())
	}

	return &Writer{
		c:           aesgcm,
		dst:         w,
		buf:         new(bytes.Buffer),
		chunkSize:   size,
		payloadSize: payloadSize,
	}, nil
}
