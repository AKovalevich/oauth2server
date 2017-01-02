package oauth2server

import (
	"encoding/base64"
	"errors"
	"github.com/kataras/iris"
	"strings"
)

// GetBasicAuthentication get username and password from Authorization header
func GetBasicAuthentication(ctx *iris.Context) (username, password string, err error) {
	if header := ctx.Request.Header.Get("Authorization"); header != "" {
		if strings.ToLower(header[:6]) == "basic " {
			// decode header value
			value, err := base64.StdEncoding.DecodeString(header[6:])
			if err != nil {
				return "", "", err
			}
			strValue := string(value)
			if ind := strings.Index(strValue, ":"); ind > 0 {
				return strValue[:ind], strValue[ind+1:], nil
			}
		}
	}
	return "", "", nil
}

// CheckBasicAuthentication header credentials
func CheckBasicAuthentication(username, password string, ctx *iris.Context) error {
	u, p, err := GetBasicAuthentication(ctx)
	if err != nil {
		return err
	}
	if u != "" && p != "" {
		if u != username && p != password {
			return errors.New("Invalid credentials")
		}
	}
	return nil
}
