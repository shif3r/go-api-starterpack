package include

import (
	"context"
	"fmt"

	"../config"

	"github.com/jackc/pgx"
)

// Database handler
type Database struct {
	*pgx.Conn
}

// DB database handler
var DB *pgx.Conn
var err error

// InitDB opens a database and saves the reference to `Database` struct.
func InitDB() *pgx.Conn {
	var db = DB

	config := config.InitConfig()

	database := config.Database.Dbname
	username := config.Database.Username
	password := config.Database.Password
	host := config.Database.Host
	port := config.Database.Port

	db, err = pgx.Connect(context.Background(), "host="+host+" port="+port+" user="+username+" dbname="+database+" sslmode=disable password="+password)
	if err != nil {
		fmt.Println("db err: ", err)
	}
	DB = db
	return DB
}

// GetDB helps you to get a connection
func GetDB() *pgx.Conn {
	return DB
}
