package crudrsa

import (
	"github.com/leyle/crud-crypto/pkg/cryptoutils"
	"os"
	"testing"
)

const (
	msg = "hello, world"
)

func readPEMFile(pemFile string) []byte {
	data, err := os.ReadFile(pemFile)
	if err != nil {
		panic(err)
	}

	return data
}

func writePEMFile(name, data string) error {
	return os.WriteFile(name, []byte(data), 0600)
}

func newRSAKPFromFile() *RSAKeyPair {
	pemFile := "/tmp/p1.private"
	pemData := readPEMFile(pemFile)
	rsaKP, err := LoadPrivateKey(pemData)
	if err != nil {
		panic(err)
	}

	return rsaKP
}

func TestCreateNewKeyPair(t *testing.T) {
	rsaKP, err := NewRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("public key\n%s", rsaKP.PublicKeyPEM)
	t.Logf("private key\n%s", rsaKP.PrivateKeyPEM)
}

func TestLoadKeyPair(t *testing.T) {
	rsaKP := newRSAKPFromFile()

	t.Logf("public key\n%s", rsaKP.PublicKeyPEM)
	t.Logf("private key\n%s", rsaKP.PrivateKeyPEM)
}

func TestRSAKeyPair_Encrypt(t *testing.T) {
	rsaKP := newRSAKPFromFile()

	cipherText, err := rsaKP.Encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(cipherText)
}

func TestRSAKeyPair_Decrypt(t *testing.T) {
	rsaKP := newRSAKPFromFile()
	cipherText, err := rsaKP.Encrypt([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cipherText)

	rawMSG, err := rsaKP.Decrypt(cipherText)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(rawMSG))
}

func TestRSAKeyPair_Sign(t *testing.T) {
	rsaKP := newRSAKPFromFile()
	sign, err := rsaKP.Sign([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cryptoutils.HexEncodeCipherText(sign.MsgDigest))
	t.Log(cryptoutils.HexEncodeCipherText(sign.Signature))
}

func TestRSAKeyPair_Verify(t *testing.T) {
	rsaKP := newRSAKPFromFile()
	sign, err := rsaKP.Sign([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cryptoutils.HexEncodeCipherText(sign.MsgDigest))
	t.Log(cryptoutils.HexEncodeCipherText(sign.Signature))

	result := rsaKP.Verify([]byte(msg), sign.Signature)
	t.Log(result)
}

func TestRSAKeyPair_VerifyInvalid(t *testing.T) {
	rsaKP := newRSAKPFromFile()
	sign, err := rsaKP.Sign([]byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cryptoutils.HexEncodeCipherText(sign.MsgDigest))
	t.Log(cryptoutils.HexEncodeCipherText(sign.Signature))

	result := rsaKP.Verify([]byte(msg), []byte("invalid data"))
	t.Log(result)

	result2 := rsaKP.Verify([]byte("invalid data"), sign.Signature)
	t.Log(result2)
}

func TestSignAndVerify2(t *testing.T) {
	// generate key pair, save them, then load from file
	rskKP1, err := NewRSAKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	priv1 := "/tmp/p1.private"
	pub1 := "/tmp/p1.public"

	err = writePEMFile(priv1, rskKP1.PrivateKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	err = writePEMFile(pub1, rskKP1.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	// use p1's private key sign message, then load p1's public key to verify
	rawMSG := []byte("golang is programming language")

	p1PrivData := readPEMFile(priv1)
	s1, err := LoadPrivateKey(p1PrivData)
	if err != nil {
		t.Fatal(err)
	}

	result, err := s1.Sign(rawMSG)
	if err != nil {
		t.Fatal(err)
	}

	p1PubData := readPEMFile(pub1)
	s2, err := LoadPublicKey(p1PubData)
	if err != nil {
		t.Fatal(err)
	}

	ok := s2.Verify(result.MsgDigest, result.Signature)
	t.Log(ok)

}
