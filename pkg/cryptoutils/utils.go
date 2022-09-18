package cryptoutils

import (
	"crypto/md5"
	"encoding/hex"
)

const keyLength = 32

func MakeKeyLength32(key []byte) []byte {
	if len(key) == keyLength {
		return key
	}
	m := md5.New()
	m.Write(key)
	tmp := hex.EncodeToString(m.Sum(nil))
	return []byte(tmp)
}

func HexEncodeCipherText(cipherText []byte) string {
	return hex.EncodeToString(cipherText)
}

func HexDecodeCipherString(msg string) ([]byte, error) {
	cipherText, err := hex.DecodeString(msg)
	return cipherText, err
}
