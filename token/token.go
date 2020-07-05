package token

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/khangjig/middleware-pkg/model"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"time"
)

type Token struct {
}

func (t *Token) Decode(token string, key string) (*model.DataClaims, error) {
	tokenType, err := jwt.ParseWithClaims(token, &model.DataClaims{}, func(_ *jwt.Token) (interface{}, error) {
		return []byte(key), nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "parsing token has failed!")
	}

	if claims, ok := tokenType.Claims.(*model.DataClaims); ok && tokenType.Valid {
		return claims, nil
	} else {
		return nil, errors.New("decoding token has failed!")
	}
}

func (t *Token) Encode(user model.UserClaims, key string, expireTime time.Time) (string, error) {
	claims := model.DataClaims{
		user,
		jwt.StandardClaims{
			ExpiresAt: expireTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return "", errors.Wrap(err, "encoding has failed!")
	}

	return tokenString, nil
}

func GetClaim(c echo.Context, secretKey string) (*model.DataClaims, error) {
	headerToken := c.Request().Header.Get("Authorization")
	tokenService := &Token{}

	claims, err := tokenService.Decode(headerToken, secretKey)
	if err != nil {
		return nil, errors.Wrap(err, "decoding claims has failed!")
	}

	return claims, nil
}
