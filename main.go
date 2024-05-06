package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	key := "my32digitkey12345678901234567890"
	iv := "my16digitIvKey12"

	plainText := "This is a secret message"

	encrypted, err := encrypt(key, iv, plainText)
	if err!= nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Encrypted:", encrypted)

	decrypted, err := decrypt(key, iv, encrypted)
	if err!= nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Decrypted:", decrypted)
}

func encrypt(key, iv, plainText string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err!= nil {
		return "", err
	}

	// Pad the plaintext to a multiple of the block size
	paddedPlainText := pkcs5Pad([]byte(plainText), block.BlockSize())

	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	ciphertext := make([]byte, len(paddedPlainText))
	mode.CryptBlocks(ciphertext, paddedPlainText)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(key, iv, encrypted string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err!= nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err!= nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Unpad the decrypted text
	unpaddedDecrypted := pkcs5Unpad(decrypted)

	// Convert the decrypted byte slice to a string with UTF-8 encoding
	decryptedString := string(unpaddedDecrypted)

	return decryptedString, nil
}

func pkcs5Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padText...)
}

func pkcs5Unpad(src []byte) []byte {
	padding := int(src[len(src)-1])
	return src[:len(src)-padding]
}