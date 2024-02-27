package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

// 定義送出的資料結構
type RequestUrlItem struct {
	ID   string
	Url  string
	Date string
	User string
}

// 定義登入資訊
type LoginData struct {
	Account  string `json:"account"`
	Password string `json:"password"`
}

// 建立會員資訊
type CreateMember struct {
	Account  string
	Password string
}

// 取得會員歷史紀錄
type memberHistoryReq struct {
	Account string `json:"user"`
}

// 產生JWT隨機密鑰
func generateSecretKey(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// 驗證JWT憑證是否正確有效
func validateToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		splitArr := strings.Split(auth, " ")
		tokenString := ""
		if len(splitArr) >= 2 {
			tokenString = splitArr[1]
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.NewValidationError("unexpected signing method", jwt.ValidationErrorSignatureInvalid)
			}
			return JWTKey, nil
		})

		if err != nil || !token.Valid {
			c.Set("tokenValid", false)
		} else {
			c.Set("tokenValid", true)
		}

		c.Next()
	}
}

// 產生JWT隨機密鑰
var JWTKey []byte

func init() {
	var err error
	JWTKey, err = generateSecretKey(32)
	if err != nil {
		log.Fatalf("Failed to generate JWT secret key: %v", err)
	}
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

	r.Use(CORSMiddleware()) // 關閉跨域
	// 定義路由
	// 測試用
	r.GET("/url_api/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})
	// 轉址
	r.GET("/url_api/:key", func(c *gin.Context) {
		key := c.Param("key")
		result, error := GetUrlItem(key, svc)
		if error != nil {
			c.JSON(http.StatusOK, gin.H{"error": error.Error()})
			return
		}
		c.Redirect(http.StatusMovedPermanently, result)
	})
	// 產生短網址
	r.POST("/url_api/generate_short_url", validateToken(), func(c *gin.Context) {
		c.Set("dynamodb", svc)
		auth := c.GetHeader("Authorization")
		splitArr := strings.Split(auth, " ")
		token := ""
		if len(splitArr) >= 2 {
			token = splitArr[1]
		}
		generateShortURLHandler(c, token)
	})
	// 登入
	r.POST("/url_api/login", func(c *gin.Context) {
		c.Set("dynamodb", svc)
		loginHandler(c)
	})
	// 建立會員
	r.POST("/url_api/create_member", func(c *gin.Context) {
		c.Set("dynamodb", svc)
		createMember(c)
	})
	// 取得會員歷史紀錄
	r.POST("/url_api/member_history", validateToken(), func(c *gin.Context) {
		c.Set("dynamodb", svc)
		queryMemberHistory(c)
	})
	// 啟動服務
	port := ":8080"
	log.Fatal(r.Run(port))
}

// 短網址Handler
func generateShortURLHandler(c *gin.Context, token string) {
	// 接收POST參數
	var request struct {
		URL  string `json:"url" binding:"required"`
		User string `json:"user"`
	}
	value, exists := c.Get("tokenValid")
	if !exists {
		return
	}
	isLogin, ok := value.(bool)
	if !ok {
		return
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
	shortURL := "https://brief-url.link/url_api/" + generateShortURL(request.URL, request.User, dynamoDBService, token, isLogin)
	c.JSON(http.StatusOK, gin.H{"short_url": shortURL})
}
func generateShortURL(originalURL string, user string, svc *dynamodb.DynamoDB, token string, loginStatus bool) string {
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
	SaveItem(shortURLCode, originalURL, formattedDate, user, loginStatus, svc)
	return shortURLCode
}

// 根據傳入的短網址參數搜尋 DynamoDB
func GetUrlItem(key string, svc *dynamodb.DynamoDB) (string, error) {
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
func SaveItem(key string, url string, date string, user string, loginStatus bool, svc *dynamodb.DynamoDB) string {
	item := RequestUrlItem{
		ID:   key,
		Url:  url,
		Date: date,
		User: user,
	}
	if !loginStatus {
		item.User = "guest"
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

// 登入handler
func loginHandler(c *gin.Context) {
	// 接收登入的POST參數
	var userLogin LoginData
	if err := c.BindJSON(&userLogin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	Account := userLogin.Account
	Password := userLogin.Password
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
	checkPassword, error := getUserDataList(Account, dynamoDBService)
	if error != nil {
		c.JSON(http.StatusOK, gin.H{"error": error.Error()})
		return
	}
	if checkPassword == "does not exist" {
		c.JSON(401, gin.H{"error": "login fail"})
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(checkPassword), []byte(Password))
	if err != nil {
		c.JSON(401, gin.H{"error": "login fail"})
		return
	} else {
		token, err := GenerateJWT(Account)
		if err != nil {
			c.JSON(500, gin.H{"error": "something wrong"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"msg":       "login success",
			"user_name": Account,
			"token":     token,
		})
		return
	}
}

// 產生JWT
func GenerateJWT(userName string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["authorized"] = true
	claims["user"] = userName
	claims["exp"] = time.Now().Add(time.Minute * 60).Unix()

	tokenString, err := token.SignedString(JWTKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// 取得User資料表
func getUserDataList(Account string, svc *dynamodb.DynamoDB) (string, error) {
	// 透過帳號去搜尋是否有符合的項目
	search := &dynamodb.GetItemInput{
		TableName: aws.String("user_data"),
		Key: map[string]*dynamodb.AttributeValue{
			"Account": {
				S: aws.String(Account),
			},
		},
	}
	result, err := svc.GetItem(search)
	if err != nil {
		log.Fatal(err)
	}
	item, ok := result.Item["Password"]
	if !ok {
		return "does not exist", nil
	}
	password := aws.StringValue(item.S)
	return password, nil
}

// 建立新會員
func createMember(c *gin.Context) {
	// 接收會員POST參數
	var userLogin LoginData
	if err := c.BindJSON(&userLogin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	Account := userLogin.Account
	Password := userLogin.Password
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
	// 確認帳號是否存在
	checkAccount, error := getUserDataList(Account, dynamoDBService)
	if error != nil {
		c.JSON(500, gin.H{"error": error.Error()})
		return
	}
	// 帳號不存在 則為密碼作加密
	if checkAccount == "does not exist" {
		encrypted := []byte(Password)
		hashedPassword, err := bcrypt.GenerateFromPassword(encrypted, bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, gin.H{"error": error.Error()})
			return
		}
		saveStatus := saveMemberData(Account, string(hashedPassword), dynamoDBService)
		if saveStatus == "Success" {
			c.JSON(http.StatusOK, gin.H{"msg": "member create success"})
			return
		}
	} else {
		c.JSON(403, gin.H{"error": "this account already exist"})
		return
	}
}

// 取得會員歷史紀錄
func queryMemberHistory(c *gin.Context) {
	var memberHistoryReq struct {
		Account string `json:"user"`
	}
	value, exists := c.Get("tokenValid")
	if !exists {
		return
	}
	isLogin, ok := value.(bool)
	if !ok {
		return
	}
	if !isLogin {
		c.JSON(401, gin.H{"error": "Not logged in or your certificate has expired, please log in again"})
		return
	}
	if err := c.ShouldBindJSON(&memberHistoryReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
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
	searchKey := expression.Key("User").Equal(expression.Value(memberHistoryReq.Account))
	expr, err := expression.NewBuilder().WithKeyCondition(searchKey).Build()
	if err != nil {
		fmt.Println("Got error building expression:", err)
		return
	}
	queryInput := &dynamodb.QueryInput{
		TableName:                 aws.String("shorturl_service"),
		IndexName:                 aws.String("User-Date-index"),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
	}

	result, err := dynamoDBService.Query(queryInput)
	if err != nil {
		fmt.Println("Query API call failed:", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

// 儲存新建的會員資料進資料庫
func saveMemberData(account string, password string, svc *dynamodb.DynamoDB) string {
	item := CreateMember{
		Account:  account,
		Password: password,
	}
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		fmt.Println("Error", err.Error())
		os.Exit(1)
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String("user_data"),
	}
	_, err = svc.PutItem(input)
	if err != nil {
		fmt.Println("SaveError", err.Error())
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
