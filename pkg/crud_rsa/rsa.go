package crud_rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const (
	PublicKeyPreamble  = "RSA PUBLIC KEY"
	PrivateKeyPreamble = "RSA PRIVATE KEY"
)

const preferBits = 4096

var (
	digestHashFunc = sha256.New()
	cryptoHashFunc = crypto.SHA256
)

type RSAKeyPair struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	PublicKeyPEM  string
	PrivateKeyPEM string
}

type RSASign struct {
	MsgDigest []byte
	Signature []byte
}

func generateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, preferBits)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func NewRSAKeyPair() (*RSAKeyPair, error) {
	// return values are publicKey | privateKey | error
	// publicKey/privateKey are encoded in PEM format
	privateKey, err := generateKey()
	if err != nil {
		return nil, err
	}

	rsaKP := privateKeyToRSAKeyPair(privateKey)
	return rsaKP, nil
}

func privateKeyToRSAKeyPair(key *rsa.PrivateKey) *RSAKeyPair {
	publicPEM := exportPublicKeyToPEM(&key.PublicKey)
	privatePEM := exportPrivateKeyToPEM(key)

	rsaKP := &RSAKeyPair{
		privateKey:    key,
		publicKey:     &key.PublicKey,
		PrivateKeyPEM: privatePEM,
		PublicKeyPEM:  publicPEM,
	}
	return rsaKP
}

func exportPublicKeyToPEM(key *rsa.PublicKey) string {
	pBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  PublicKeyPreamble,
			Bytes: x509.MarshalPKCS1PublicKey(key),
		})

	return string(pBytes)
}

func exportPrivateKeyToPEM(key *rsa.PrivateKey) string {
	pBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  PrivateKeyPreamble,
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		})

	return string(pBytes)
}

func LoadPublicKey(publicPEM []byte) (*RSAKeyPair, error) {
	block, _ := pem.Decode(publicPEM)
	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKP := &RSAKeyPair{
		publicKey:    key,
		PublicKeyPEM: string(publicPEM),
	}
	return rsaKP, err
}

func LoadPrivateKey(privatePEM []byte) (*RSAKeyPair, error) {
	block, _ := pem.Decode(privatePEM)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKP := privateKeyToRSAKeyPair(key)
	return rsaKP, nil
}

func (r *RSAKeyPair) Encrypt(message []byte) ([]byte, error) {
	cipherText, err := rsa.EncryptOAEP(digestHashFunc, rand.Reader, r.publicKey, message, nil)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}

func (r *RSAKeyPair) Decrypt(cipherText []byte) ([]byte, error) {
	msg, err := rsa.DecryptOAEP(digestHashFunc, rand.Reader, r.privateKey, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (r *RSAKeyPair) Sign(message []byte) (*RSASign, error) {
	if r.privateKey == nil {
		return nil, errors.New("no private key")
	}

	msgDigest := hashMsg(message)

	signature, err := rsa.SignPSS(rand.Reader, r.privateKey, cryptoHashFunc, msgDigest, nil)
	if err != nil {
		return nil, err
	}

	rsaSign := &RSASign{
		MsgDigest: msgDigest,
		Signature: signature,
	}

	return rsaSign, nil
}

func (r *RSAKeyPair) Verify(msgDigest, signature []byte) error {
	if r.publicKey == nil {
		return errors.New("no public key")
	}
	return rsa.VerifyPSS(r.publicKey, cryptoHashFunc, msgDigest, signature, nil)
}

func hashMsg(msg []byte) []byte {
	digestHashFunc.Write(msg)
	result := digestHashFunc.Sum(nil)
	return result
}
