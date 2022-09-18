package crudaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"github.com/leyle/crud-crypto/pkg/cryptoutils"
	"io"
)

func GcmEncrypt(key, text []byte) ([]byte, error) {
	key32 := cryptoutils.MakeKeyLength32(key)
	c, err := aes.NewCipher(key32)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())

	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	result := gcm.Seal(nonce, nonce, text, nil)
	return result, nil
}

func GcmDecrypt(key, cipherText []byte) ([]byte, error) {
	key32 := cryptoutils.MakeKeyLength32(key)
	c, err := aes.NewCipher(key32)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("invalid cipherText")
	}

	nonce := cipherText[:nonceSize]

	cipherData := cipherText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
