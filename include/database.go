package include

import (
	"context"
	"fmt"

	"../config"
	"github.com/jackc/pgx/pgxpool"
)

// DB database handler
var DB *pgxpool.Pool
var err error

// InitDB opens a database and saves the reference to `Database` struct.
func InitDB() *pgxpool.Pool {
	var db = DB

	configuration := config.InitConfig()

	database := configuration.Database.Dbname
	username := configuration.Database.Username
	password := configuration.Database.Password
	host := configuration.Database.Host
	port := configuration.Database.Port

	db, err = pgxpool.Connect(context.Background(), "host="+host+" port="+port+" user="+username+" dbname="+database+" sslmode=disable password="+password)
	if err != nil {
		fmt.Println("db err: ", err)
	}

	DB = db
	return DB
}

// GetDB helps you to get a connection
func GetDB() *pgxpool.Pool {
	return DB
}
