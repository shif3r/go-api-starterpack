package controller

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx"

	"../include"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Register создаёт запись нового пользователя в базе данных
// принимает json с login, email, encryptedPass
// если передан только login, программа проверит его наличие в бд,
// если !login, то создаст первичную запись, сгенерирует пару rsa ключей
// и вернёт publickey клиенту. Если переданы все поля, то сначала проверим login
// и email, затем дешифровка зашифрованного хеша encryptedPass
// и обновление данных пользователя. В случае успеха вернёт {"Error":0}
func Register(c *gin.Context) {
	db = include.GetDB()
	var regform RegistrationForm
	err = json.NewDecoder(c.Request.Body).Decode(&regform)
	if err != nil {
		c.JSON(400, gin.H{"Error": 1})
		return
	}
	if regform.Login == "" {
		c.JSON(400, gin.H{"Error": 2})
		return
	}
	if loginCheck.MatchString(regform.Login) == false {
		c.JSON(400, gin.H{"Error": 3})
		return
	}
	if regform.Email == "" {
		if regform.EncryptedPass == "" {
			var loginFromDB string
			err = db.QueryRow(c.Request.Context(), "select \"Login\" from public.\"Users\" where \"Login\"=$1", regform.Login).Scan(&loginFromDB)
			if err != nil {
				if err != pgx.ErrNoRows {
					fmt.Println(err)
					c.JSON(400, gin.H{"Error": 4})
					return
				}
			}
			if len(loginFromDB) > 3 {
				c.JSON(400, gin.H{"Error": 5})
				return
			}
			privateKey, publicKey := rsaKeygen(1024)
			_, err = db.Exec(c.Request.Context(), "INSERT INTO public.\"Users\" (\"Login\", \"PrivateKey\") VALUES ($1, $2)", regform.Login, privateKey)
			if err != nil {
				fmt.Println(err)
				c.JSON(400, gin.H{"Error": 6})
				return
			}
			c.JSON(200, gin.H{"PublicKey": publicKey})
			return
		}
		c.JSON(400, gin.H{"Error": 7})
		return
	}
	if regform.EncryptedPass == "" {
		c.JSON(400, gin.H{"Error": 8})
		return
	}
	if emailCheck.MatchString(regform.Email) == false {
		c.JSON(400, gin.H{"Error": 9})
		return
	}
	err = db.QueryRow(c.Request.Context(), "select \"Login\" from public.\"Users\" where \"Login\"=$1", regform.Login).Scan(&regform.Login)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 10})
		return
	}
	if regform.Login == "" {
		c.JSON(400, gin.H{"Error": 11})
		return
	}
	var privateKey string
	err = db.QueryRow(c.Request.Context(), "SELECT \"PrivateKey\" FROM public.\"Users\" where \"Login\"=$1", regform.Login).Scan(&privateKey)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 12})
		return
	}
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		fmt.Println(block)
		c.JSON(400, gin.H{"Error": 13})
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(priv)
		c.JSON(400, gin.H{"Error": 14})
		return
	}
	encr, err := hex.DecodeString(regform.EncryptedPass)
	passwordHash, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encr, nil)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 15})
		return
	}
	commandTag, err := db.Exec(c.Request.Context(), "UPDATE public.\"Users\" SET \"Email\"=$1, \"Password_hash\"=$2 WHERE \"Login\"=$3", regform.Email, passwordHash, regform.Login)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 16})
		return
	}
	if commandTag.RowsAffected() != 1 {
		c.JSON(400, gin.H{"Error": 17})
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
	db = include.GetDB()
	var logform LoginForm
	err = json.NewDecoder(c.Request.Body).Decode(&logform)
	if err != nil {
		c.JSON(400, gin.H{"Error": 1, "Msg": "ошибка при декодировании json-объекта"})
		return
	}
	if logform.LoginOrEmail == "" {
		c.JSON(400, gin.H{"Error": 2, "Msg": "логин пустой"})
		return
	}
	if loginCheck.MatchString(logform.LoginOrEmail) == false {
		if emailCheck.MatchString(logform.LoginOrEmail) == false {
			c.JSON(400, gin.H{"Error": 3, "Msg": "введённый логин / мыло не прошло проверку regexp"})
			return
		}
	}
	err = db.QueryRow(c.Request.Context(), "select \"Login\" from public.\"Users\" where \"Login\"=$1 or \"Email\"=$1", logform.LoginOrEmail).Scan(&logform.LoginOrEmail)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 4, "Msg": "ошибка при запросе в бд на получение логина"})
		return
	}
	if len(logform.LoginOrEmail) < 3 {
		c.JSON(400, gin.H{"Error": 5, "Msg": "пользователя не существует"})
		return
	}
	if logform.EncryptedPass == "" {
		unixTime := time.Now().Unix()
		privateKey, publicKey := rsaKeygen(1024)
		commandTag, err := db.Exec(c.Request.Context(), "UPDATE public.\"Users\" SET \"UnixTime\"=$1, \"PrivateKey\"=$2 WHERE \"Login\"=$3 or \"Email\"=$3", unixTime, privateKey, logform.LoginOrEmail)
		if err != nil {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 6, "Msg": "ошибка при запросе в бд на обновление данных пользователя (время и privatekey)"})
			return
		}
		if commandTag.RowsAffected() != 1 {
			c.JSON(400, gin.H{"Error": 7, "Msg": "ни один пользователь при запросе на обновление данных не затронут"})
			return
		}
		c.JSON(200, gin.H{"PublicKey": publicKey, "UnixTime": unixTime})
		return
	}
	var privateKey, passwordHash string
	var unixTime int64
	err = db.QueryRow(c.Request.Context(), "SELECT \"PrivateKey\", \"Password_hash\", \"UnixTime\" FROM public.\"Users\" where \"Login\"=$1 or \"Email\"=$1", logform.LoginOrEmail).Scan(&privateKey, &passwordHash, &unixTime)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 8, "Msg": "при запросе на получение прив ключа из бд"})
		return
	}
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		fmt.Println(block)
		c.JSON(400, gin.H{"Error": 9, "Msg": "ошибка при декодировании приватного ключа из бд"})
		return
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(priv)
		c.JSON(400, gin.H{"Error": 10, "Msg": "ошибка при парсинге приватного ключа из бд после декодирования в программу"})
		return
	}
	encr, err := hex.DecodeString(logform.EncryptedPass)
	decodedHash, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encr, nil)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 11, "Msg": "ошибка расшифровки пароля"})
		return
	}
	hasher := md5.New()
	hasher.Reset()
	hasher.Write([]byte(passwordHash + strconv.FormatInt(unixTime, 10)))
	str := string(decodedHash)
	if hex.EncodeToString(hasher.Sum(nil)) == str {
		rows, err := db.Query(c.Request.Context(), "SELECT * FROM public.\"Sessions\" where \"UserId\"=$1", logform.LoginOrEmail)
		if err != nil {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 12, "Msg": "при запросе на получение активных сессий пользователя"})
			return
		}
		n = 0
		for rows.Next() {
			n++
		}
		if n > maxSessionCount {
			_, err = db.Exec(c.Request.Context(), "DELETE FROM public.\"Sessions\" where \"UserId\"=$1", logform.LoginOrEmail)
			if err != nil {
				fmt.Println(err)
				c.JSON(400, gin.H{"Error": 13, "Msg": "при запросе на удаление активных сессий пользователя"})
				return
			}
		}
		if logform.FingerPrint == "" {
			c.JSON(200, gin.H{"Error": 14, "Msg": "fingerprint не получен"})
			return
		}
		ua := c.GetHeader("XX-User-Agent")
		if ua == "" {
			c.JSON(400, gin.H{"Error": 15, "Msg": "не был передан user-agent (header)"})
			return
		}
		refreshToken, err := uuid.NewRandom()
		if err != nil {
			fmt.Println(err)
			c.JSON(200, gin.H{"Error": 16, "Msg": "невозможно создать refresh-токен"})
			return
		}
		timeNow := time.Now()
		expiresIn := timeNow.Add(RefreshExpiresIn).Unix()
		_, err = db.Exec(c.Request.Context(),
			"INSERT INTO public.\"Sessions\" (\"UserId\", \"RefreshToken\", \"UserAgent\", \"FingerPrint\", \"IP\", \"ExpiresIn\", \"СreatedAt\", \"UpdatedAt\") VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
			logform.LoginOrEmail,
			refreshToken,
			ua,
			logform.FingerPrint,
			c.ClientIP(),
			expiresIn,
			timeNow,
			timeNow)
		if err != nil {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 17, "Msg": "ошибка при добавлении сессии в бд"})
			return
		}
		accessToken, err := accessKeyGen(logform.LoginOrEmail)
		if err != nil {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 18, "Msg": "ошибка при создании access токена"})
			return
		}
		c.JSON(200, gin.H{"AccessToken": accessToken, "RefreshToken": refreshToken})
		return
	}
	c.JSON(400, gin.H{"Error": 19, "Msg": "пароль не верен"})
}

// SignOut функция logout принимает на вход RefreshToken и fingerprint
// проверка входных данных
// получение сессии по refreshToken-у
// сравнение fingerprint клиента из бд и из полученных данных
// удаление сессии по refreshToken-у
func SignOut(c *gin.Context) {
	db = include.GetDB()
	var refreshKeysForm refreshKeys
	err = json.NewDecoder(c.Request.Body).Decode(&refreshKeysForm)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 1, "Msg": "ошибка при декодировани json объекта"})
		return
	}
	if refreshKeysForm.RefreshToken == "" {
		c.JSON(400, gin.H{"Error": 2, "Msg": "RefreshToken пустой"})
		return
	}
	if refreshKeysForm.FingerPrint == "" {
		c.JSON(400, gin.H{"Error": 3, "Msg": "FingerPrint токен пустой"})
		return
	}
	uuidStr, err := uuid.Parse(refreshKeysForm.RefreshToken)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 4, "Msg": "RefreshToken не прошёл верификацию uuid"})
		return
	}
	var fingerPrint, refreshToken string
	err = db.QueryRow(c.Request.Context(), "SELECT \"RefreshToken\", \"FingerPrint\" FROM public.\"Sessions\" where \"RefreshToken\"=$1", uuidStr).Scan(
		&refreshToken,
		&fingerPrint,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(400, gin.H{"Error": 5, "Msg": "сессия не найдена"})
			return
		}
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 6, "Msg": "при запросе на получение сессии по рефрешу"})
		return
	}
	if fingerPrint != refreshKeysForm.FingerPrint {
		c.JSON(400, gin.H{"Error": 7, "Msg": "FingerPrint запроса не соответствует сохранённому в бд"})
		return
	}
	_, err = db.Exec(c.Request.Context(), "DELETE FROM public.\"Sessions\" where \"RefreshToken\"=$1", uuidStr)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 8, "Msg": "при запросе на удаление сессии по рефрешу"})
		return
	}
}
