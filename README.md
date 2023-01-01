# Golang AES GCM IO Read/Writer

This library implements both the io.WriteCloser and io.Reader interface when you need
to encrypt/decrypt an unknown payload size with AES GCM in Golang.

The writer will take the provided payload bytes buffer then encrypt into specified chunk
sizes. GCM encrypts a payload and provides authentication and integrity, each
chunk is decrypted and verified before being returned to the caller. Often the
amount needed to be read at any one time can be greater than the chunk size,
therefore the whole chunk is read (due to verification and integrity) and kept
in a buffer.

Due to the nature of this writer and the unknown total payload size, the writer
needs to be explicitly closed otherwise the ciphertext will likely be missing
bytes on the end.

You can provide whatever chunk size you like, ofcourse there will be a 16 (gcm)
plus 12 (nonce/iv) byte overhead for each chunk. For uniformity each chunks payload
 will be multiples of aes.BlockSize. So the provided chunkSize is a maximum, it
may not result in exactly the provided chunk size.

For simplicity the chunkSize is written at the start of the payload in clear
text, the reader then reads this 4 byte value from the source reader upon
creation of the reader. It would be pretty easy for an attacker to determine the
chunk size anyway upon close inspection of the encrypted bytes anyway.

Finally a new random nonce/iv is created for every single chunk and prepended to the
ciphertext bytes.

For example:

```sh
# Encrypting a 1096 byte cleartext payload with a provided 512 chunk,
# would result in the following.

512 - 16(gcm) - 12(nonce) = 484
484 / 16(aes.BlockSize) = 30
30 * aes.BlockSize = 480

So 1096 breaks down into three chunks:

480, 480, 136

With the 28 byte overhead plus chunk_size this should equal:

4, 508, 508, 164

Total Encrypted Bytes: 1184 (88 byte overhead)
```

## Important

This library uses the standard crypto/cipher library and the function (https://pkg.go.dev/crypto/cipher#NewGCM), along with the above information you must be comfortable with the following:

1.  Chunk Size integer will be in clear text at the start of each chunk, an attacker would likely be
able to work out the chunk size anyway if they analyze all the bytes/padding.
2.  The order of which the chunks are returned is not verified for integrity, you can
implement your own HMAC hash fairly easily, but this would denote storing the entire decrypted
payload in a buffer and only returning it to the caller once the hash is verified. 
3.  Use a 32 byte key for AES256.
