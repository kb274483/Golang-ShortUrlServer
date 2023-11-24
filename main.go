package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
)

var redisClient *redis.Client

func main() {
	// 初始化 Gin 引擎
	r := gin.Default()
	// 定義路由
	r.GET("/backend/api", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})
	// r.POST("/shorten", shortenURL)
	// r.GET("/:shortURL", redirectURL)
	if err := godotenv.Load(); err != nil {
		fmt.Println("無法載入 .env 文件")
		return
	}
	initRedisConnection()
	// 測試
	pong, err := redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Fatal("Error connecting to Redis:", err)
	}
	fmt.Println("Connected to Redis:", pong)
	// 啟動服務
	port := ":8080"
	log.Fatal(r.Run(port))
}

func initRedisConnection() {
	redisHost := os.Getenv("REDIS_HOST")
	redisPassword := os.Getenv("REDIS_PASSWORD")
	// 初始化 Redis 客戶端
	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisHost,
		Password: redisPassword,
	})
}
