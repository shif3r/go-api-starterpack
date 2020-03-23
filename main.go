package main

import (
	"net/http"
	"time"

	"./config"
	"./controller"
	"./include"
	"./middleware"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx"
	"github.com/jackc/pgx/pgxpool"
)

func setupRouter() (*gin.Engine, config.Configuration, *pgxpool.Pool) {
	initConfig := config.InitConfig()
	db := include.InitDB()
	router := gin.Default()
	//router.Use(cors.Default())
	router.Use(cors.New(cors.Config{
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "XX-User-Agent", "Access-token"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
		AllowAllOrigins:  true,
	}))
	router.POST("/signup", controller.Register)
	router.POST("/signin", controller.Signin)
	router.POST("/refresh", controller.Refresh)
	router.POST("/signout", controller.SignOut)
	router.GET("/getSint", func(c *gin.Context) {
		rows, err := db.Query(c.Request.Context(), "SELECT * FROM public.\"Sessions\"")
		defer rows.Close()
		if err != nil {
			c.JSON(400, gin.H{"Err": err.Error})
			return
		}
		i := 0
		for rows.Next() {
			i++
		}
		if rows.Err() != nil {
			c.JSON(400, gin.H{"Err": err.Error})
			return
		}
		c.JSON(200, gin.H{"Sessions": i})
	})
	router.GET("/delS", func(c *gin.Context) {
		rows, err := db.Exec(c.Request.Context(), "DELETE FROM public.\"Sessions\"")
		if err != nil {
			if err == pgx.ErrNoRows {
				return
			}
			c.JSON(400, gin.H{"Err": err.Error()})
			return
		}
		c.JSON(200, gin.H{"Deleted": rows.RowsAffected()})
	})
	api := router.Group("/api")
	{
		api.Use(middleware.JwtAuthentication())
		api.GET("/hello", func(c *gin.Context) {
			c.JSON(200, gin.H{"Msg": "hello"})
		})
		api.GET("/getinfo", controller.GetAccountInfo)
		api.POST("/delSessions", controller.DeleteUserSessions)
	}
	return router, initConfig, db
}

func main() {
	router, initConfig, db := setupRouter()
	defer db.Close()
	s := &http.Server{
		Addr:           ":" + initConfig.Server.Port,
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.ListenAndServe()
}
