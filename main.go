package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// 定義送出的資料結構
type RequestItem struct {
	ID   string
	Url  string
	Date string
}

func main() {
	// 初始化 Gin 引擎
	r := gin.Default()
	// 載入環境變數
	if err := godotenv.Load(); err != nil {
		fmt.Println("無法載入 .env 文件")
		return
	}
	awsRegion := os.Getenv("AWS_REGION")
	accessKey := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	// 與DynamoDB建立連線
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
		Credentials: credentials.NewStaticCredentials(
			accessKey,
			secretKey,
			""),
	})
	if err != nil {
		log.Fatal(err)
	}
	svc := dynamodb.New(sess)
	r.Use(CORSMiddleware())
	// 定義路由
	r.GET("/url_api/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})
	r.GET("/url_api/:key", func(c *gin.Context) {
		key := c.Param("key")
		result, error := GetItem(key, svc)
		if error != nil {
			c.JSON(http.StatusOK, gin.H{"error": error.Error()})
			return
		}
		c.Redirect(http.StatusMovedPermanently, result)
	})
	r.POST("/url_api/generate_short_url", func(c *gin.Context) {
		c.Set("dynamodb", svc)
		generateShortURLHandler(c)
	})

	println(svc)
	// 啟動服務
	port := ":8080"
	log.Fatal(r.Run(port))
}

// 短網址Handler
func generateShortURLHandler(c *gin.Context) {
	// 接收POST參數
	var request struct {
		URL string `json:"url" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	svc, exists := c.Get("dynamodb")
	if !exists {
		c.JSON(500, gin.H{"error": "DynamoDB service not available"})
		return
	}
	dynamoDBService, ok := svc.(*dynamodb.DynamoDB)
	if !ok {
		c.JSON(500, gin.H{"error": "Failed to get DynamoDB service"})
		return
	}
	// fmt.Println(request.URL)
	shortURL := "http://13.115.250.182/url_api/" + generateShortURL(request.URL, dynamoDBService)
	c.JSON(http.StatusOK, gin.H{"short_url": shortURL})
}
func generateShortURL(originalURL string, svc *dynamodb.DynamoDB) string {
	// 記錄時間
	currentTime := time.Now()
	formattedDate := currentTime.Format("2006/01/02")
	// 透過哈希函數，產生短網址
	hasher := sha256.New()
	hasher.Write([]byte(originalURL))
	hash := hasher.Sum(nil)
	hashString := hex.EncodeToString(hash)
	shortURLCode := hashString[:6]
	// 儲存結果到 DynamoDB
	SaveItem(shortURLCode, originalURL, formattedDate, svc)
	return shortURLCode
}

// 根據傳入的參數搜尋 DynamoDB
func GetItem(key string, svc *dynamodb.DynamoDB) (string, error) {
	search := &dynamodb.GetItemInput{
		TableName: aws.String("shorturl_service"),
		Key: map[string]*dynamodb.AttributeValue{
			"ID": {
				S: aws.String(key),
			},
		},
	}
	// 使用 GetItem 方法取得項目
	result, err := svc.GetItem(search)
	if err != nil {
		log.Fatal(err)
	}
	item, ok := result.Item["Url"]
	if !ok {
		return "", errors.New("item not found in dynamodb result")
	}
	originalURL := aws.StringValue(item.S)
	return originalURL, nil
}

// DynamoDB資料儲存
func SaveItem(key string, url string, date string, svc *dynamodb.DynamoDB) string {
	item := RequestItem{
		ID:   key,
		Url:  url,
		Date: date,
	}
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		fmt.Println("Error", err.Error())
		os.Exit(1)
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String("shorturl_service"),
	}
	_, err = svc.PutItem(input)
	if err != nil {
		fmt.Println("Error", err.Error())
		os.Exit(1)
	}
	return "Success"
}

// 本地端跨域處理
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
