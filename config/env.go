package config

import (
	"os"

	"github.com/joho/godotenv"
)

var Env *env

type env struct {
	Port string
}

func LoadEnv() *env {
	if err := godotenv.Load(); err != nil {
		panic("Error loading .env file")
	}

	Env = &env{
		Port: EnvKey("PORT", "8080"),
	}

	return Env
}

func EnvKey(key string, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}
