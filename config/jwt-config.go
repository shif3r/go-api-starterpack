package config

// ServerConfiguration used to store server configuration
type JwtConfiguration struct {
	JwtKey           string
	AccessExpiresIn  string
	RefreshExpiresIn string
}
