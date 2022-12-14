package crudaes

import (
	"github.com/leyle/crud-crypto/pkg/crudutils"
	"testing"
)

var key = []byte("v}#0CEYuG%M8#c77HkUp")
var msg = []byte("eventservice")

func encrypt() []byte {
	cipherText, err := GcmEncrypt(key, msg)
	if err != nil {
		panic(err)
	}

	return cipherText
}

func TestGCMEncrypt(t *testing.T) {
	cipherText := encrypt()

	t.Log(cipherText)
	t.Log(string(cipherText))

	t.Log(crudutils.HexEncodeCipherText(cipherText))
}

func TestGcmDecrypt(t *testing.T) {
	cipherText := encrypt()
	t.Log(crudutils.HexEncodeCipherText(cipherText))

	text, err := GcmDecrypt(key, cipherText)
	if err != nil {
		t.Error(err)
	}

	t.Log(text)
	t.Log(string(text))
}

func TestGCMDecryptSRCHex(t *testing.T) {
	// raw := "B2h+HK3at6Yo0pkWbsTgMRx6gy7es9u70v9hVrvqOa/q85pk9jixgA=="
	raw := "8db8c7073975be91bf85801b5aa4711b11f046c7c18e7dc2a9a30ea209569044aec77abdb00ff13e"
	decodeBytes, err := crudutils.HexDecodeCipherString(raw)
	if err != nil {
		t.Error(err)
	}

	text, err := GcmDecrypt(key, decodeBytes)
	if err != nil {
		t.Error(err)
	}
	t.Log(text)
	t.Log(string(text))
}

func TestEncryptAndDecrypt(t *testing.T) {
	cipherText := encrypt()
	b64Str := crudutils.HexEncodeCipherText(cipherText)

	t.Log(b64Str)

	srcCipherText, err := crudutils.HexDecodeCipherString(b64Str)
	if err != nil {
		panic(err)
	}
	text, err := GcmDecrypt(key, srcCipherText)
	if err != nil {
		panic(err)
	}

	t.Log(string(text))
}
