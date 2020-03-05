package main

import (
	"context"

	"./config"
	"./controller"
	"./include"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx"
)

var db *pgx.Conn
var err error

func main() {
	config := config.InitConfig()

	db = include.InitDB()
	defer db.Close(context.Background())

	router := gin.Default()
	router.Use(cors.Default())

	store := memstore.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))
	// Non-protected routes
	api := router.Group("/api")
	{
		checkPassword := api.Group("/checkPassword")
		{
			checkPassword.POST("/signup", controller.Register)
			checkPassword.POST("/signin", controller.Signin)
		}
	}

	router.GET("/incr", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Options(sessions.Options{
			Path:     "/",
			MaxAge:   5400, //секунды (полтора часа)
			HttpOnly: true,
		})
		var count int
		v := session.Get("count")
		if v == nil {
			count = 0
		} else {
			count = v.(int)
			count++
		}
		session.Set("count", count)
		session.Save()
		c.JSON(200, gin.H{"count": count})
	})

	router.Run(":" + config.Server.Port)
}
