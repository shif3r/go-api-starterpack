package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"time"

	"../include"

	"github.com/dgrijalva/jwt-go"
	"github.com/jackc/pgx/pgxpool"
)

var n int32
var db *pgxpool.Pool
var err error

var loginCheck = regexp.MustCompile(`^[A-Za-z0-9]{4,19}$`)
var emailCheck = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// MaxSessionCount максимально допустимое кол-во открытых сессий
const maxSessionCount = 5

var AccessExpiresIn = include.GetJwtExpiresIn()
var RefreshExpiresIn = include.GetRefreshExpiresIn()

// RegistrationForm структура для приёма json
// объекта от клиента при регистрации
type RegistrationForm struct {
	Login         string `json:"Login"`
	Email         string `json:"Email"`
	EncryptedPass string `json:"EncryptedPass"`
}

// LoginForm структура для приёма json
// объекта от клиента при аутентификации
type LoginForm struct {
	LoginOrEmail  string `json:"LoginOrEmail"`
	EncryptedPass string `json:"EncryptedPass"`
	FingerPrint   string `json:"FingerPrint"`
}

// Claims реализуют структуру сохранённых в jwt данных
type Claims struct {
	Login string `json:"Login"`
	jwt.StandardClaims
}

type refreshKeys struct {
	RefreshToken string `json:"RefreshToken"`
	FingerPrint  string `json:"FingerPrint"`
}

type UserSession struct {
	UserAgent string
	IP        string
	UpdatedAt time.Time
}

type Session struct {
	UserSession
	UserID       string
	RefreshToken string
	FingerPrint  string
	ExpiresIn    int64
	CreatedAt    time.Time
}

// rsaKeygen returns private and public rsa-keys
func rsaKeygen(bitSize int) (string, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		panic(err)
	}
	publicKey := &privateKey.PublicKey
	pubkeypem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(publicKey)}))
	privatekeypem := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
	return privatekeypem, pubkeypem
}

func accessKeyGen(login string) (string, error) {
	claims := &Claims{
		Login: login,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(AccessExpiresIn).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(include.GetJwtKey())
}

func getLoginJwt(jwtstr string) string {
	tkn, _ := jwt.ParseWithClaims(jwtstr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return include.GetJwtKey(), nil
	})
	claims := tkn.Claims.(*Claims)
	return claims.Login
}
