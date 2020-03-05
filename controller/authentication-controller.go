package controller

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"time"

	"../include"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx"
	jsoniter "github.com/json-iterator/go"
)

var db *pgx.Conn
var err error

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
}

// rsaKeygen returns private and public rsakeys
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

// Register создаёт запись нового пользователя в базе данных
// принимает json с login, email, encryptedPass
// если передан только login, программа проверит его наличие в бд,
// если !login, то создаст первичную запись, сгенерирует пару rsa ключей
// и вернёт publickey клиенту. Если переданы все поля, то сначала проверим login
// и email, затем дешифровка зашифрованного хеша encryptedPass
// и обновление данных пользователя. В случае успеха вернёт {"Error":0}
func Register(c *gin.Context) {
	db = include.InitDB()
	var regform RegistrationForm
	decoder := jsoniter.NewDecoder(c.Request.Body)
	// преобразуем json запрос в структуру
	err := decoder.Decode(&regform)
	if err != nil {
		c.JSON(400, gin.H{"Error": 1}) // ошибка при декодировани json объекта
		return
	}
	if regform.Login == "" {
		c.JSON(400, gin.H{"Error": 2}) // логин пустой
		return
	}
	regexLogin, err := regexp.Match(regform.Login, []byte(`^(?=.*[A-Za-z0-9]$)[A-Za-z][A-Za-z\d.-]{4,19}$`))
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 3}) // ошибка при regex на логине
		return
	}
	if regexLogin == false {
		c.JSON(400, gin.H{"Error": 4}) // regex не пройден, логин не валидный
		return
	}
	if regform.Email == "" {
		if regform.EncryptedPass == "" {
			err = db.QueryRow(context.Background(),
				"select \"Login\" from public.\"Users\" where \"Login\"=$1", regform.Login).Scan(&regform.Login)
			if err != nil {
				fmt.Println(err)
				c.JSON(400, gin.H{"Error": 5}) // ошибка при запросе в бд на проверку пользователя
				return
			}
			if len(regform.Login) > 3 {
				c.JSON(400, gin.H{"Error": 6}) // пользователь уже существует
				return
			}
			privateKey, publicKey := rsaKeygen(1024)
			_, err = db.Query(c.Request.Context(), "INSERT INTO public.\"Users\" (\"Login\", \"PrivateKey\") VALUES ($1, $2)", regform.Login, privateKey)
			if err != nil {
				fmt.Println(err)
				c.JSON(400, gin.H{"Error": 7}) // ошибка при запросе в бд на добавление логина \ privatekey
				return
			}
			c.JSON(200, gin.H{"PublicKey": publicKey})
			return
		}
		c.JSON(400, gin.H{"Error": 8}) // переданы только логин и пароль
		return
	}
	if regform.EncryptedPass == "" {
		c.JSON(400, gin.H{"Error": 9}) // логин, мыло пришло, но нет пароля
		return
	}
	regexEmail, err := regexp.Match(regform.Email, []byte(`(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)`))
	if err != nil {
		c.JSON(400, gin.H{"Error": 10}) // ошибка при regex на мыле
		return
	}
	if regexEmail == false {
		c.JSON(400, gin.H{"Error": 11}) // regex не пройден, мыло не валидное
		return
	}
	err = db.QueryRow(context.Background(),
		"select \"Login\" from public.\"Users\" where \"Login\"=$1", regform.Login).Scan(&regform.Login)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 5}) // ошибка при запросе в бд на проверку пользователя
		return
	}
	if regform.Login == "" {
		c.JSON(400, gin.H{"Error": 13}) // пользователь не прошёл первичную идентификацию (не существует в бд)
		return
	}
	var privateKey string
	err = db.QueryRow(c.Request.Context(), "SELECT \"PrivateKey\" FROM public.\"Users\" where \"Login\"=$1", regform.Login).Scan(&privateKey)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 14}) // ошибка при запросе в бд на получение приватного ключа
		return
	}
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		fmt.Println(block)
		c.JSON(400, gin.H{"Error": 15}) // ошибка при декодировке приватного ключа из бд
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(priv)
		c.JSON(400, gin.H{"Error": 16}) // ошибка при парсинге приватного ключа из бд после декодировки в программу
		return
	}
	encr, err := hex.DecodeString(regform.EncryptedPass)
	passwordHash, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encr, nil)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 17}) // ошибка при дешифровке пароля
		return
	}
	commandTag, err := db.Exec(c.Request.Context(), "UPDATE public.\"Users\" SET \"Email\"=$1, \"Password_hash\"=$2 WHERE \"Login\"=$3", regform.Email, passwordHash, regform.Login)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 18}) // ошибка при запросе в бд на обновление данных пользователя (мыла и пароля)
		return
	}
	if commandTag.RowsAffected() != 1 {
		c.JSON(400, gin.H{"Error": 19}) // ошибка: ни один пользователь при запросе на обновление данных не затронут
		return
	}
	c.JSON(200, gin.H{"Error": 0})
}

// Signin проверяет введёный пароль с тем, что храниться в бд
// для этого сначала должна быть отправлена структура {"Login":""}
// чтобы сгенерировать и занести в бд rsa ключ и unixtime для соли
// publickey+unixtime отправляется клиенту, где введённый пароль шифруется
// в формате md5(md5(pass+salt).tostring()+unixtime) и отправляется на сервер
// вместе с логином. Если проверка будет успешной клиенту отправятся
// Access и Refresh - токены
func Signin(c *gin.Context) {
	db = include.InitDB()
	var logform LoginForm
	decoder := jsoniter.NewDecoder(c.Request.Body)
	// преобразуем json запрос в структуру
	err := decoder.Decode(&logform)
	if err != nil {
		c.JSON(400, gin.H{"Error": 1}) // ошибка при декодировани json объекта
		return
	}
	if logform.LoginOrEmail == "" {
		c.JSON(400, gin.H{"Error": 2}) // логин пустой
		return
	}
	loginCheck, err := regexp.Match(logform.LoginOrEmail, []byte(`^(?=.*[A-Za-z0-9]$)[A-Za-z][A-Za-z\d.-]{4,19}$`))
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 3}) // ошибка при regex на логине
		return
	}
	if loginCheck == false {
		emailCheck, err := regexp.Match(logform.LoginOrEmail, []byte(`^[a-zA-Z0-9.!#$%&'*+/=?^_\x60{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`))
		if err != nil {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 3}) // ошибка при regex на логине
			return
		}
		if emailCheck == false {
			c.JSON(400, gin.H{"Error": 4}) // введённый логин \ мыло не прошло проверку regexp
			return
		}
	}
	if logform.EncryptedPass == "" {
		err = db.QueryRow(context.Background(),
			"select \"Login\" from public.\"Users\" where \"Login\"=$1 or \"Email\"=$1", logform.LoginOrEmail).Scan(&logform.LoginOrEmail)
		if err != nil {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 5}) // ошибка при запросе в бд на проверку пользователя
			return
		}
		if len(logform.LoginOrEmail) > 3 {
			c.JSON(400, gin.H{"Error": 6}) // пользователя не существует
			return
		}
		unixTime := time.Now().Unix()
		privateKey, publicKey := rsaKeygen(1024)
		commandTag, err := db.Exec(c.Request.Context(),
			"UPDATE public.\"Users\" SET \"UnixTime\"=$1, \"PrivateKey\"=$2 WHERE \"Login\"=$3 or \"Email\"=$3",
			unixTime, privateKey, logform.LoginOrEmail)
		if err != nil {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 7}) // ошибка при запросе в бд на обновление данных пользователя (время и privatekey)
			return
		}
		if commandTag.RowsAffected() != 1 {
			c.JSON(400, gin.H{"Error": 8}) // ошибка при работе с бд: ни один пользователь при запросе на обновление данных не затронут
			return
		}
		c.JSON(200, gin.H{"PublicKey": publicKey, "UnixTime": unixTime})
		return
	}
	var privateKey, passwordHash string
	var unixTime int64
	err = db.QueryRow(c.Request.Context(), "SELECT \"PrivateKey\", \"Password_hash\", \"UnixTime\" FROM public.\"Users\" where \"Login\"=$1 or \"Email\"", logform.LoginOrEmail).Scan(&privateKey, &passwordHash, &unixTime)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 9}) // ошибка при запросе в бд на получение приватного ключа
		return
	}
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		fmt.Println(block)
		c.JSON(400, gin.H{"Error": 10}) // ошибка при декодировании приватного ключа из бд
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(priv)
		c.JSON(400, gin.H{"Error": 11}) // ошибка при парсинге приватного ключа из бд после декодирования в программу
		return
	}
	encr, err := hex.DecodeString(logform.EncryptedPass)
	decodedHash, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encr, nil)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 12}) // ошибка при расшифровки пароля
		return
	}
	hasher := md5.New()
	hasher.Write([]byte(string(passwordHash) + string(unixTime)))
	pass := hex.EncodeToString(hasher.Sum(nil))
	if pass == string(decodedHash) {
		c.JSON(200, gin.H{"Error": 0}) // отдать токены
		return
	}
	c.JSON(200, gin.H{"Error": 13}) // пароль не верен
}
