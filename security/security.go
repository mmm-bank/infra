package security

import (
	"github.com/golang-module/dongle"
)

func Encrypt(cardNumber, key string) []byte {
	cipher := dongle.NewCipher()
	cipher.SetKey(key)
	cipher.SetMode(dongle.ECB)
	return dongle.Encrypt.FromString(cardNumber).ByAes(cipher).ToHexBytes()
}

func Decrypt(cardNumber []byte, key string) string {
	cipher := dongle.NewCipher()
	cipher.SetKey(key)
	cipher.SetMode(dongle.ECB)
	return dongle.Decrypt.FromHexBytes(cardNumber).ByAes(cipher).ToString()
}
