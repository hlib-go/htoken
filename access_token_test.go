package htoken

import (
	"fmt"
	"testing"
)

func TestToken(t *testing.T) {
	secret := "12345678"

	tokenVal := Gen(secret, (&Token{
		Uid:    "111111111111",
		Mobile: "1",
		Second: 10,
	}).SetExpires(100))

	fmt.Println(tokenVal)
	token, err := Ver(secret, tokenVal)
	if err != nil {
		t.Log(err)
		return
	}
	t.Log(token.Uid)
}
