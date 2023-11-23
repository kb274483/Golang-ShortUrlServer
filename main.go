package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	// "github.com/go-redis/redis/v8"
)

// var redisClient *redis.Client

func init() {
	// 初始化 Redis 客戶端
	// redisClient = redis.NewClient(&redis.Options{
	// 	// 替換為您的 ElastiCache（Redis）伺服器地址
	// 	Addr:     "clustercfg.royshorturlredis.3evrc8.memorydb.ap-northeast-1.amazonaws.com:6379",
	// 	Password: "", // 如果有密碼，請填寫密碼
	// 	DB:       0,
	// })
}

func main() {
	// 初始化 Gin 引擎
	r := gin.Default()

	// 定義路由
	r.GET("/backend/api", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})
	// r.POST("/shorten", shortenURL)
	// r.GET("/:shortURL", redirectURL)

	// 測試
	// pong, err := redisClient.Ping(context.Background()).Result()
	// if err != nil {
	// 	log.Fatal("Error connecting to Redis:", err)
	// }
	// fmt.Println("Connected to Redis:", pong)
	// 啟動服務
	port := ":8080"
	log.Fatal(r.Run(port))
}

// shortenURL 處理縮短網址的請求
// func shortenURL(c *gin.Context) {
// 	var req struct {
// 		URL string `json:"url" binding:"required"`
// 	}

// 	if err := c.BindJSON(&req); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}

// 	// 生成短網址
// 	shortURL := generateShortURL()

// 	// 將原始網址存入 Redis，以短網址作為鍵，原始網址作為值
// 	err := redisClient.Set(context.Background(), shortURL, req.URL, 0).Err()
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store URL"})
// 		return
// 	}

// 	// 回傳短網址
// 	c.JSON(http.StatusOK, gin.H{"shortURL": shortURL})
// }

// // redirectURL 處理短網址重導向
// func redirectURL(c *gin.Context) {
// 	shortURL := c.Param("shortURL")

// 	// 從 Redis 中取得原始網址
// 	url, err := redisClient.Get(context.Background(), shortURL).Result()
// 	if err == redis.Nil {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "Short URL not found"})
// 		return
// 	} else if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
// 		return
// 	}

// 	// 重導向至原始網址
// 	c.Redirect(http.StatusTemporaryRedirect, url)
// }

// func generateShortURL() string {
// 	return fmt.Sprintf("%d", time.Now().UnixNano())
// }
