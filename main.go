package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

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
	// 定義路由
	r.GET("/backend/api", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})
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
	println(svc)
	// 啟動服務
	port := ":8080"
	log.Fatal(r.Run(port))
}

// 根據傳入的參數搜尋 DynamoDB
func GetItem(key string, svc *dynamodb.DynamoDB) map[string]*dynamodb.AttributeValue {
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
	return result.Item
}

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
