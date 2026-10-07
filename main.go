package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // Keep named time zones available in minimal container images.

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	googleOauthConfig *oauth2.Config
)

// VAPID鑰匙
var (
	vapidPublicKey  string
	vapidPrivateKey string
)

// 產生隨機字串
func generateRandomString(length int) (string, error) {
	randomBytes := make([]byte, length)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	randomString := base64.URLEncoding.EncodeToString(randomBytes)
	return randomString[:length], nil
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

// 短網址Handler
func generateShortURLHandler(c *gin.Context, token string, store shortURLWriter) {
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
	shortURLCode, err := generateShortURL(request.URL, request.User, store, token, isLogin)
	if err != nil {
		log.Printf("create short URL: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create short URL"})
		return
	}
	shortURL := appConfig.PublicBaseURL + "/url_api/" + shortURLCode
	c.JSON(http.StatusOK, gin.H{"short_url": shortURL})
}
func generateShortURL(originalURL string, user string, svc shortURLWriter, token string, loginStatus bool) (string, error) {
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
	if err := SaveItem(shortURLCode, originalURL, formattedDate, user, loginStatus, svc); err != nil {
		return "", err
	}
	return shortURLCode, nil
}

// 根據傳入的短網址參數搜尋 DynamoDB
func GetUrlItem(key string, svc shortURLReader) (string, error) {
	search := &dynamodb.GetItemInput{
		TableName: aws.String(appConfig.Tables.ShortURLs),
		Key: map[string]*dynamodb.AttributeValue{
			"ID": {
				S: aws.String(key),
			},
		},
	}
	// 使用 GetItem 方法取得項目
	result, err := svc.GetItem(search)
	if err != nil {
		return "", fmt.Errorf("get short URL %q: %w", key, err)
	}
	if result == nil {
		return "", ErrShortURLNotFound
	}
	item, ok := result.Item["Url"]
	if !ok || item == nil || item.S == nil {
		return "", ErrShortURLNotFound
	}
	originalURL := aws.StringValue(item.S)
	return originalURL, nil
}

func resolveShortURLHandler(store shortURLReader) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.Param("key")
		destination, err := GetUrlItem(key, store)
		if errors.Is(err, ErrShortURLNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "short URL not found"})
			return
		}
		if err != nil {
			log.Printf("resolve short URL %q: %v", key, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve short URL"})
			return
		}
		c.Redirect(http.StatusMovedPermanently, destination)
	}
}

// DynamoDB資料儲存
func SaveItem(key string, url string, date string, user string, loginStatus bool, svc shortURLWriter) error {
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
		return fmt.Errorf("marshal short URL item: %w", err)
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(appConfig.Tables.ShortURLs),
	}
	_, err = svc.PutItem(input)
	if err != nil {
		return fmt.Errorf("save short URL item: %w", err)
	}
	return nil
}

// 登入handler
func loginHandler(c *gin.Context, store userDataReader) {
	// 接收登入的POST參數
	var userLogin LoginData
	if err := c.BindJSON(&userLogin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	Account := userLogin.Account
	Password := userLogin.Password
	checkPassword, err := getUserDataList(Account, store)
	if err != nil {
		log.Printf("look up login account %q: %v", Account, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to log in"})
		return
	}
	if checkPassword == "does not exist" {
		c.JSON(401, gin.H{"error": "login fail"})
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(checkPassword), []byte(Password))
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

// google 回調
func handlerGoogleCallBack(c *gin.Context) map[string]interface{} {
	if err := validateGoogleState(c); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid OAuth state"})
		return nil
	}
	clearGoogleStateCookie(c)
	// 得到google回應的授權碼
	code := c.Query("code")
	// 使用授權碼向google取得token
	ctx := context.WithValue(c.Request.Context(), oauth2.HTTPClient, &http.Client{Timeout: appConfig.HTTPTimeout})
	token, err := googleOauthConfig.Exchange(ctx, code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token get fail"})
		return nil
	}
	// 再使用token去跟google的資源伺服器取得用戶資訊
	googleUserData, err := getGoogleUserData(ctx, token)
	if err != nil {
		c.JSON(500, gin.H{"error": "something wrong"})
		return nil
	}
	return googleUserData
}

func getGoogleUserData(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	client := googleOauthConfig.Client(ctx, token)
	response, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google userinfo returned HTTP %d", response.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
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
func getUserDataList(Account string, svc userDataReader) (string, error) {
	// 透過帳號去搜尋是否有符合的項目
	search := &dynamodb.GetItemInput{
		TableName: aws.String(appConfig.Tables.Users),
		Key: map[string]*dynamodb.AttributeValue{
			"Account": {
				S: aws.String(Account),
			},
		},
	}
	result, err := svc.GetItem(search)
	if err != nil {
		return "", fmt.Errorf("get user data for %q: %w", Account, err)
	}
	if result == nil {
		return "does not exist", nil
	}
	item, ok := result.Item["Password"]
	if !ok || item == nil || item.S == nil {
		return "does not exist", nil
	}
	password := aws.StringValue(item.S)
	return password, nil
}

// 建立新會員
func createMember(c *gin.Context, reader userDataReader, writer userDataWriter) {
	// 接收會員POST參數
	var userLogin LoginData
	if err := c.BindJSON(&userLogin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	Account := userLogin.Account
	Password := userLogin.Password
	// 確認帳號是否存在
	checkAccount, err := getUserDataList(Account, reader)
	if err != nil {
		log.Printf("look up member account %q: %v", Account, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create member"})
		return
	}
	// 帳號不存在 則為密碼作加密
	if checkAccount == "does not exist" {
		encrypted := []byte(Password)
		hashedPassword, err := bcrypt.GenerateFromPassword(encrypted, bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		if err := saveMemberData(Account, string(hashedPassword), writer); err != nil {
			log.Printf("save member account %q: %v", Account, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create member"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"msg": "member create success"})
		return
	} else {
		c.JSON(403, gin.H{"error": "this account already exist"})
		return
	}
}

// 取得會員歷史紀錄
func queryMemberHistory(c *gin.Context) {
	var memberHistoryReq MemberHistoryReq
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
		log.Println("Got error building expression:", err)
		return
	}
	queryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(appConfig.Tables.ShortURLs),
		IndexName:                 aws.String("User-Date-index"),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
	}

	result, err := dynamoDBService.Query(queryInput)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"data": nil})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

// 儲存新建的會員資料進資料庫
func saveMemberData(account string, password string, svc userDataWriter) error {
	item := CreateMember{
		Account:  account,
		Password: password,
	}
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal member item: %w", err)
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(appConfig.Tables.Users),
	}
	_, err = svc.PutItem(input)
	if err != nil {
		return fmt.Errorf("save member item: %w", err)
	}
	return nil
}

// 建立新行程
func addItinerary(c *gin.Context, store itineraryWriter) {
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
	var newEvent itineraryData
	if err := c.BindJSON(&newEvent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// 接收前端傳來的變數
	Timestamp := newEvent.Timestamp
	Account := newEvent.Account
	Title := newEvent.Title
	Content := newEvent.Content
	Date := newEvent.Date
	Time := newEvent.Time
	Status := newEvent.Status

	if err := saveItineraryToDB(Timestamp, Account, Title, Content, Date, Time, Status, store); err != nil {
		log.Printf("save itinerary for account %q: %v", Account, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create itinerary"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "Itinerary create success"})
}

// 將行程存入資料庫
func saveItineraryToDB(timestamp int, account string, title string, content string, date string, time string, status bool, svc itineraryWriter) error {
	item := saveItineraryData{
		Timestamp: timestamp,
		Account:   account,
		Title:     title,
		Content:   content,
		Date:      date,
		Time:      time,
		Status:    status,
	}
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		return fmt.Errorf("marshal itinerary item: %w", err)
	}
	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(appConfig.Tables.Itineraries),
	}
	_, err = svc.PutItem(input)
	if err != nil {
		return fmt.Errorf("save itinerary item: %w", err)
	}
	return nil
}

// 取得當天行程
func getItinerary(c *gin.Context) {
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
	var itineraryReqData itineraryReq
	if err := c.ShouldBindJSON(&itineraryReqData); err != nil {
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
	searchKey := expression.Key("Account").Equal(expression.Value(itineraryReqData.Account)).And(expression.Key("Date").Equal(expression.Value(itineraryReqData.Date)))
	expr, err := expression.NewBuilder().WithKeyCondition(searchKey).Build()
	if err != nil {
		log.Println("Got error building expression:", err)
		return
	}
	queryInput := &dynamodb.QueryInput{
		TableName:                 aws.String(appConfig.Tables.Itineraries),
		IndexName:                 aws.String("Account-Date-index"),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
	}

	result, err := dynamoDBService.Query(queryInput)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"data": nil})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": result})
}

// 更新行程
func updeateItinerary(c *gin.Context) {
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
	var updateEvent itineraryData
	if err := c.BindJSON(&updateEvent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	key := map[string]*dynamodb.AttributeValue{
		"Timestamp": {
			N: aws.String(strconv.Itoa(updateEvent.Timestamp)),
		},
	}
	updateExpr := "SET #title = :newTitle, #content = :newContent ,#time = :newTime ,#status = :newStatus "
	exprAttrNames := map[string]*string{
		"#title":   aws.String("Title"),
		"#content": aws.String("Content"),
		"#time":    aws.String("Time"),
		"#status":  aws.String("Status"),
	}

	exprAttrValues := map[string]*dynamodb.AttributeValue{
		":newTitle": {
			S: aws.String(updateEvent.Title),
		},
		":newContent": {
			S: aws.String(updateEvent.Content),
		},
		":newTime": {
			S: aws.String(updateEvent.Time),
		},
		":newStatus": {
			BOOL: aws.Bool(updateEvent.Status),
		},
	}

	input := &dynamodb.UpdateItemInput{
		TableName:                 aws.String(appConfig.Tables.Itineraries),
		Key:                       key,
		UpdateExpression:          aws.String(updateExpr),
		ExpressionAttributeNames:  exprAttrNames,
		ExpressionAttributeValues: exprAttrValues,
		ReturnValues:              aws.String("UPDATED_NEW"),
	}
	result, err := dynamoDBService.UpdateItem(input)
	if err != nil {
		c.JSON(500, gin.H{"error": "Something wrong!"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// 刪除行程
func deleteItinerary(c *gin.Context) {
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
	var deleteEvent itineraryData
	if err := c.BindJSON(&deleteEvent); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	key := map[string]*dynamodb.AttributeValue{
		"Timestamp": {
			N: aws.String(strconv.Itoa(deleteEvent.Timestamp)),
		},
	}

	input := &dynamodb.DeleteItemInput{
		TableName: aws.String(appConfig.Tables.Itineraries),
		Key:       key,
	}
	_, err := dynamoDBService.DeleteItem(input)
	if err != nil {
		c.JSON(500, gin.H{"error": "Something wrong!"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "Delete Successfully"})
}

// 訂閱
func subscribeNotification(c *gin.Context, store subscriptionWriter) {
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
	var subscription SubscriptionData
	if err := c.BindJSON(&subscription); err != nil {
		c.JSON(400, gin.H{"error": "Invalid subscription format"})
		return
	}
	item := SaveSubscriptionData{
		Account: subscription.Account,
		Subscription: struct {
			Endpoint string
			Keys     struct {
				P256dh string
				Auth   string
			}
		}(subscription.Subscription),
	}
	av, err := dynamodbattribute.MarshalMap(item)
	if err != nil {
		log.Printf("marshal subscription for account %q: %v", subscription.Account, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save subscription"})
		return
	}

	input := &dynamodb.PutItemInput{
		Item:      av,
		TableName: aws.String(appConfig.Tables.Subscriptions),
	}
	_, err = store.PutItem(input)
	if err != nil {
		log.Printf("save subscription for account %q: %v", subscription.Account, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save subscription"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "Subscribe Successfully"})
}
