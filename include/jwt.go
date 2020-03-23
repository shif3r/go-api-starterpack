package include

import (
	"time"

	"../config"
)

func GetJwtKey() []byte {
	configuration := config.InitConfig()
	return []byte(configuration.Jwt.JwtKey)
}

func GetJwtExpiresIn() time.Duration {
	configuration := config.InitConfig()
	n, err := time.ParseDuration(configuration.Jwt.AccessExpiresIn)
	if err != nil {
		panic(err)
	}
	return n
}

func GetRefreshExpiresIn() time.Duration {
	configuration := config.InitConfig()
	n, err := time.ParseDuration(configuration.Jwt.RefreshExpiresIn)
	if err != nil {
		panic(err)
	}
	return n
}
