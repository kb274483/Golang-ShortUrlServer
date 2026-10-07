package main

import (
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gin-gonic/gin"
)

func newRouter(svc *dynamodb.DynamoDB) *gin.Engine {
	r := gin.New()
	r.Use(requestLogging(appLogger, appConfig), recoverRequests(appLogger))

	registerHealthRoutes(r)
	registerShortURLRoutes(r, svc)
	registerAuthRoutes(r, svc)
	registerItineraryRoutes(r, svc)
	registerNotificationRoutes(r, svc)

	return r
}

func registerHealthRoutes(r *gin.Engine) {
	r.GET("/url_api/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
}

func registerShortURLRoutes(r *gin.Engine, svc *dynamodb.DynamoDB) {
	// 測試用
	r.GET("/url_api/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, World!"})
	})
	// 轉址
	r.GET("/url_api/:key", resolveShortURLHandler(svc))
	// 產生短網址
	r.POST("/url_api/generate_short_url", validateToken(), func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		splitArr := strings.Split(auth, " ")
		token := ""
		if len(splitArr) >= 2 {
			token = splitArr[1]
		}
		generateShortURLHandler(c, token, svc)
	})
}

func registerAuthRoutes(r *gin.Engine, svc *dynamodb.DynamoDB) {
	// 登入
	r.POST("/url_api/login", func(c *gin.Context) {
		loginHandler(c, svc)
	})
	// 第三方登入
	r.GET("/url_api/google_login", func(c *gin.Context) {
		if googleOauthConfig == nil || googleOauthConfig.ClientID == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Google login is not configured"})
			return
		}
		state, err := issueGoogleState(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start Google login"})
			return
		}
		url := googleOauthConfig.AuthCodeURL(state)
		c.JSON(http.StatusOK, gin.H{"redirectUrl": url})
	})
	// Google 回調
	r.GET("/url_api/google_call_back", func(c *gin.Context) {
		if googleOauthConfig == nil || googleOauthConfig.ClientID == "" {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Google login is not configured"})
			return
		}
		userData := handlerGoogleCallBack(c)
		if userData != nil {
			userEmail, emailExist := userData["email"].(string)
			if !emailExist {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Email not found in userData"})
				return
			}
			splitEmail := strings.Split(userEmail, "@")
			if len(splitEmail) > 0 {
				account := splitEmail[0]
				token, err := GenerateJWT(account)
				if err != nil {
					c.JSON(500, gin.H{"error": "something wrong"})
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"msg":       "login success",
					"user_name": account,
					"token":     token,
				})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Email split error"})
			}
		}
	})
	// 建立會員
	r.POST("/url_api/create_member", func(c *gin.Context) {
		createMember(c, svc, svc)
	})
	// 取得會員歷史紀錄
	r.POST("/url_api/member_history", validateToken(), func(c *gin.Context) {
		c.Set("dynamodb", svc)
		queryMemberHistory(c)
	})
}

func registerItineraryRoutes(r *gin.Engine, svc *dynamodb.DynamoDB) {
	// 建立行程事件
	r.POST("/url_api/add_itinerary", validateToken(), func(c *gin.Context) {
		addItinerary(c, svc)
	})
	// 取得當天行程
	r.POST("/url_api/get_itinerary", validateToken(), func(c *gin.Context) {
		c.Set("dynamodb", svc)
		getItinerary(c)
	})
	// 更新事件
	r.POST("/url_api/update_itinerary", validateToken(), func(c *gin.Context) {
		c.Set("dynamodb", svc)
		updeateItinerary(c)
	})
	// 刪除事件
	r.POST("/url_api/delete_itinerary", validateToken(), func(c *gin.Context) {
		c.Set("dynamodb", svc)
		deleteItinerary(c)
	})
}

func registerNotificationRoutes(r *gin.Engine, svc *dynamodb.DynamoDB) {
	// 取得VAPID KEY
	r.GET("/url_api/get_vapid_key", validateToken(), func(c *gin.Context) {
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
		c.JSON(http.StatusOK, gin.H{"publicKey": vapidPublicKey})
	})
	// 訂閱
	r.POST("/url_api/subscribe", validateToken(), func(c *gin.Context) {
		subscribeNotification(c, svc)
	})
}
