package config

import (
	"log"

	"github.com/spf13/viper"
)

// Configuration used to store configuration of server and database connection
type Configuration struct {
	Server   ServerConfiguration
	Database DatabaseConfiguration
}

// InitConfig creating configuration struct for server and database connection
func InitConfig() Configuration {
	var configuration Configuration

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}

	err := viper.Unmarshal(&configuration)
	if err != nil {
		log.Fatalf("Unable to decode into struct, %v", err)
	}

	return configuration
}
