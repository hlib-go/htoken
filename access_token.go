package htoken

import (
	"bytes"
	"crypto/des"
	"encoding/base64"
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"time"
)

// 密文token

var (
	INVALID_TOKEN = errors.New("99911:无效TOKEN")
)

type Token struct {
	Uid     string    `json:"uid"`
	Mobile  string    `json:"mobile"`
	Second  int64     `json:"second"`  // 有效期秒数
	Expires time.Time `json:"expires"` // 到期时间
}

func (t *Token) Json() string {
	tbytes, _ := json.Marshal(t)
	return string(tbytes)
}

func (t *Token) SetExpires(second int64) *Token {
	t.Expires = time.Now().Add(time.Duration(second) * time.Second)
	return t
}

func (t *Token) Gen(secret string) string {
	token, err := des_ecb_pkcs5_encode(t.Json(), secret)
	if err != nil {
		token = "gen-token-error"
	}
	return token
}

// 生成 Token
func Gen(secret string, t *Token) (tokenVal string) {
	defer func() {
		if e := recover(); e != nil {
			tokenVal = "gen-token-error"
			log.Error(e)
		}
	}()
	tokenVal = t.Gen(secret)
	return
}

// 验证 Token
func Ver(secret, tokenVal string) (t *Token, err error) {
	defer func() {
		if e := recover(); e != nil {
			log.Error("解析TOKEN出错", e)
			err = INVALID_TOKEN
		}
	}()
	src, err := des_ecb_pkcs5_decode(tokenVal, secret)
	if err != nil {
		return
	}
	err = json.Unmarshal([]byte(src), &t)
	if err != nil {
		return
	}
	// 验证是否超时
	if time.Now().After(t.Expires) {
		err = INVALID_TOKEN
		return
	}
	if t.Uid == "" {
		err = INVALID_TOKEN
		return
	}
	return
}

// des_ecb_pkcs5_encode
func des_ecb_pkcs5_encode(src, key string) (v string, err error) {
	if len(key) != 8 {
		err = errors.New("Token密钥长度错误")
		return
	}
	data := []byte(src)
	keyByte := []byte(key)
	block, err := des.NewCipher(keyByte)
	if err != nil {
		return
	}
	bs := block.BlockSize()
	//对明文数据进行补码
	data = pkCS5Padding(data, bs)
	if len(data)%bs != 0 {
		err = errors.New("Need a multiple of the blocksize")
		return
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Encrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	v = base64.RawURLEncoding.EncodeToString(out)
	return
}

// des_ecb_pkcs5_decode
func des_ecb_pkcs5_decode(src, key string) (v string, err error) {
	if len(key) != 8 {
		err = errors.New("Token密钥长度错误")
		return
	}
	data, err := base64.RawURLEncoding.DecodeString(src)
	if err != nil {
		return
	}
	keyByte := []byte(key)
	block, err := des.NewCipher(keyByte)
	if err != nil {
		return
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		err = errors.New("crypto/cipher: input not full blocks")
		return
	}
	out := make([]byte, len(data))
	dst := out
	for len(data) > 0 {
		block.Decrypt(dst, data[:bs])
		data = data[bs:]
		dst = dst[bs:]
	}
	out = pkCS5UnPadding(out)
	v = string(out)
	return
}

func pkCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// Token验证
/*func VerifyToken(request *http.Request) *Token {
	t, err := Ver(_options.TokenSecret, request.Header.Get("token"))
	if err != nil {
		panic(err)
	}
	return t
}
*/
