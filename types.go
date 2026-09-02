package main

import (
	"errors"

	"github.com/aws/aws-sdk-go/service/dynamodb"
)

// 定義送出的資料結構
type RequestUrlItem struct {
	ID   string
	Url  string
	Date string
	User string
}

var ErrShortURLNotFound = errors.New("short URL not found")

type shortURLReader interface {
	GetItem(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
}

type shortURLWriter interface {
	PutItem(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
}

type userDataReader interface {
	GetItem(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
}

type userDataWriter interface {
	PutItem(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
}

type itineraryWriter interface {
	PutItem(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
}

type subscriptionWriter interface {
	PutItem(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
}

type itineraryReminderStore interface {
	Query(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error)
	GetItem(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
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
type MemberHistoryReq struct {
	Account string `json:"user"`
}

// 定義前端傳來的行程資訊
type itineraryData struct {
	Timestamp int    `json:"timestamp"`
	Account   string `json:"account"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Date      string `json:"date"`
	Time      string `json:"time"`
	Status    bool   `json:"status"`
}

// 定義要存入資料庫的行程
type saveItineraryData struct {
	Timestamp int
	Account   string
	Title     string
	Content   string
	Date      string
	Time      string
	Status    bool
}

// 定義前端取行程資料的條件
type itineraryReq struct {
	Account string `json:"account"`
	Date    string `json:"date"`
}

// 訂閱資訊
type SubscriptionData struct {
	Account      string `json:"account"`
	Subscription struct {
		Endpoint string `json:"endpoint"`
		Keys     struct {
			P256dh string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
	} `json:"subscription"`
}

// 存入資料庫的訂閱結構
type SaveSubscriptionData struct {
	Account      string
	Subscription struct {
		Endpoint string
		Keys     struct {
			P256dh string
			Auth   string
		}
	}
}

type sendSub struct {
	Subscription struct {
		Endpoint string
		Keys     struct {
			P256dh string
			Auth   string
		}
	}
}

// 要傳送的訊息
type NotiPayload struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	Icon  string `json:"icon"`
}
