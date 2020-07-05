package model

import "github.com/dgrijalva/jwt-go"

const DataClaim = "DataClaim"

type AllowedRoute struct {
	Method string
	Path   string
}

type DataResponse struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

type DataClaims struct {
	UserClaims
	jwt.StandardClaims
}

type UserClaims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
}
