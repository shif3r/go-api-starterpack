package controller

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx"

	"../include"
	"github.com/gin-gonic/gin"
)

// Refresh функция для обновления access и refresh токенов
func Refresh(c *gin.Context) {
	//jwtKey := config.GetJwtKey()
	db = include.GetDB()
	var refreshKeysForm refreshKeys
	err = json.NewDecoder(c.Request.Body).Decode(&refreshKeysForm)
	if err != nil {
		c.JSON(400, gin.H{"Error": 1, "Msg": "ошибка при декодировани json объекта"})
		return
	}
	if refreshKeysForm.RefreshToken == "" {
		c.JSON(400, gin.H{"Error": 2, "Msg": "RefreshToken пустой"})
		return
	}
	if refreshKeysForm.FingerPrint == "" {
		c.JSON(400, gin.H{"Error": 3, "Msg": "FingerPrint пустой"})
		return
	}
	uuidStr, err := uuid.Parse(refreshKeysForm.RefreshToken)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 4, "Msg": "RefreshToken не прошёл верификацию uuid"})
		return
	}
	var session Session
	err = db.QueryRow(c.Request.Context(), "SELECT * FROM public.\"Sessions\" where \"RefreshToken\"=$1", uuidStr).Scan(
		&session.UserID,
		&session.RefreshToken,
		&session.UserAgent,
		&session.FingerPrint,
		&session.IP,
		&session.ExpiresIn,
		&session.CreatedAt,
		&session.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(400, gin.H{"Error": 5, "Msg": "сессия не найдена"})
			return
		}
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 6, "Msg": "при запросе на получение сессии по рефрешу"})
		return
	}
	_, err = db.Exec(c.Request.Context(), "DELETE FROM public.\"Sessions\" where \"RefreshToken\"=$1", uuidStr)
	if time.Now().Unix() > session.ExpiresIn {
		c.JSON(400, gin.H{"Error": 7, "Msg": "RefreshKey истёк срок годности"})
		return
	}
	if session.FingerPrint != refreshKeysForm.FingerPrint {
		c.JSON(400, gin.H{"Error": 8, "Msg": "FingerPrint запроса не соответствует сохранённому в бд"})
		return
	}
	accessToken, err := accessKeyGen(session.UserID)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 9, "Msg": "ошибка при создании access токена"})
		return
	}
	refreshToken, err := uuid.NewRandom()
	if err != nil {
		fmt.Println(err)
		c.JSON(200, gin.H{"Error": 10, "Msg": "невозможно создать refresh-токен"})
		return
	}
	timeNow := time.Now()
	expiresIn := timeNow.Add(RefreshExpiresIn).Unix()
	_, err = db.Exec(c.Request.Context(),
		"INSERT INTO public.\"Sessions\" (\"UserId\", \"RefreshToken\", \"UserAgent\", \"FingerPrint\", \"IP\", \"ExpiresIn\", \"СreatedAt\", \"UpdatedAt\") VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		session.UserID,
		refreshToken,
		session.UserAgent,
		refreshKeysForm.FingerPrint,
		c.ClientIP(),
		expiresIn,
		session.CreatedAt,
		timeNow)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 11, "Msg": "ошибка при добавлении сессии в бд"})
		return
	}
	c.JSON(200, gin.H{"AccessToken": accessToken, "RefreshToken": refreshToken})
	return
}
