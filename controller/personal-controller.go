package controller

import (
	"encoding/json"
	"fmt"
	"time"

	"../include"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx"
)

func GetAccountInfo(c *gin.Context) {
	db := include.GetDB()
	accessToken := c.Request.Header.Get("Access-token")
	loginFromToken := getLoginJwt(accessToken)
	var email string
	err := db.QueryRow(c.Request.Context(), "select \"Email\" from public.\"Users\" where \"Login\"=$1", loginFromToken).Scan(&email)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 4, "Msg": "запрос на логин"})
		return
	}
	var str []gin.H
	err = db.QueryRow(c.Request.Context(), "SELECT array_to_json(array_agg(row_to_json(t))) FROM (SELECT \"UserAgent\", \"IP\", \"UpdatedAt\" FROM public.\"Sessions\" where \"UserId\"=$1) t", loginFromToken).Scan(&str)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Err": 5, "Msg": "запрос на сессии"})
		return
	}
	for _, s := range str {
		m, _ := json.Marshal(s)
		var a interface{}
		json.Unmarshal(m, &a)
		b := a.(map[string]interface{})
		b["Browser"] = b["UserAgent"]
		delete(b, "UserAgent")
		b["Last seen"] = b["UpdatedAt"]
		delete(b, "UpdatedAt")
		s = b
	}
	c.JSON(200, gin.H{"Email": email, "Sessions": str})
}

func DeleteUserSessions(c *gin.Context) {
	db = include.GetDB()
	var deleteSessionsForm refreshKeys
	accessToken := c.Request.Header.Get("Access-token")
	userID := getLoginJwt(accessToken)
	err = json.NewDecoder(c.Request.Body).Decode(&deleteSessionsForm)
	if err != nil {
		c.JSON(400, gin.H{"Error": 4, "Msg": "ошибка при декодировани json объекта"})
		return
	}
	if deleteSessionsForm.RefreshToken == "" {
		c.JSON(400, gin.H{"Error": 5, "Msg": "RefreshToken пустой"})
		return
	}
	if deleteSessionsForm.FingerPrint == "" {
		c.JSON(400, gin.H{"Error": 6, "Msg": "FingerPrint пустой"})
		return
	}
	uuidStr, err := uuid.Parse(deleteSessionsForm.RefreshToken)
	if err != nil {
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 7, "Msg": "RefreshToken не прошёл верификацию uuid"})
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
			c.JSON(400, gin.H{"Error": 8, "Msg": "сессия не найдена"})
			return
		}
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 9, "Msg": "при запросе на получение сессии по рефрешу"})
		return
	}
	if session.FingerPrint != deleteSessionsForm.FingerPrint {
		c.JSON(400, gin.H{"Error": 10, "Msg": "FingerPrint запроса не соответствует сохранённому в бд"})
		return
	}
	if userID != session.UserID {
		c.JSON(400, gin.H{"Error": 11, "Msg": "не совпадают значения login из токена доступа и бд"})
		return
	}
	if time.Now().Unix() > session.ExpiresIn {
		c.JSON(400, gin.H{"Error": 12, "Msg": "RefreshKey истёк срок годности"})
		return
	}
	rows, err := db.Exec(c.Request.Context(), "DELETE FROM public.\"Sessions\" WHERE \"RefreshToken\" <> $1", uuidStr)
	if err != nil {
		if err != pgx.ErrNoRows {
			fmt.Println(err)
			c.JSON(400, gin.H{"Error": 13, "Msg": "RefreshKey истёк срок годности"})
			return
		}
		fmt.Println(err)
		c.JSON(400, gin.H{"Error": 14, "Msg": "при запросе на получение сессии по рефрешу"})
		return
	}
	c.JSON(200, gin.H{"Deleted": rows.RowsAffected()})
}
