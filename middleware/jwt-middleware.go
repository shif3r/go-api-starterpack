package middleware

import (
	"fmt"
	"net/http"

	"../controller"
	"../include"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// JwtAuthentication проверяет токен доступа на срок годности
// и его сигнатуру (подпись). Если что то не так возвращает ошибку
func JwtAuthentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		a := c.Copy()
		accessToken := a.Request.Header.Get("Access-token")
		if accessToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"Error": 1, "Msg": "Нет токена"})
			c.Abort()
			return
		}
		tkn, err := jwt.ParseWithClaims(accessToken, &controller.Claims{}, func(token *jwt.Token) (interface{}, error) {
			return include.GetJwtKey(), nil
		})
		if err != nil {
			fmt.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"Error": 2, "Msg": "токен кал"})
			c.Abort()
			return
		}
		if !tkn.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"Error": 3, "Msg": "Токен не валиден"})
			c.Abort()
			return
		}
		c.Next()
	}
}
