package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/gin-gonic/gin"
)

func TestHealthz(t *testing.T) {
	router := newRouter(nil)

	request := httptest.NewRequest(http.MethodGet, "/url_api/healthz", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("health check status = %d, want %d", response.Code, http.StatusOK)
	}

	if response.Body.String() != `{"status":"ok"}` {
		t.Fatalf("health check body = %q, want %q", response.Body.String(), `{"status":"ok"}`)
	}
}

type fakeShortURLStore struct {
	getItem func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	putItem func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
}

func (store fakeShortURLStore) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	return store.getItem(input)
}

func (store fakeShortURLStore) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	return store.putItem(input)
}

func TestResolveShortURL(t *testing.T) {
	tests := []struct {
		name         string
		store        fakeShortURLStore
		wantStatus   int
		wantLocation string
		wantBody     string
	}{
		{
			name: "short URL does not exist",
			store: fakeShortURLStore{
				getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					return &dynamodb.GetItemOutput{}, nil
				},
			},
			wantStatus: http.StatusNotFound,
			wantBody:   `{"error":"short URL not found"}`,
		},
		{
			name: "DynamoDB read fails",
			store: fakeShortURLStore{
				getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					return nil, errors.New("DynamoDB unavailable")
				},
			},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"failed to resolve short URL"}`,
		},
		{
			name: "short URL redirects to destination",
			store: fakeShortURLStore{
				getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
					return &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
						"Url": {S: aws.String("https://example.com")},
					}}, nil
				},
			},
			wantStatus:   http.StatusMovedPermanently,
			wantLocation: "https://example.com",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/url_api/:key", resolveShortURLHandler(test.store))

			request := httptest.NewRequest(http.MethodGet, "/url_api/abc123", nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}

			if location := response.Header().Get("Location"); location != test.wantLocation {
				t.Fatalf("Location = %q, want %q", location, test.wantLocation)
			}

			if test.wantBody != "" && response.Body.String() != test.wantBody {
				t.Fatalf("body = %q, want %q", response.Body.String(), test.wantBody)
			}
		})
	}
}

func TestSaveItemReturnsDynamoDBWriteError(t *testing.T) {
	wantErr := errors.New("DynamoDB unavailable")
	store := fakeShortURLStore{
		putItem: func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			return nil, wantErr
		},
	}

	err := SaveItem("abc123", "https://example.com", "2026/09/02", "roy", true, store)
	if !errors.Is(err, wantErr) {
		t.Fatalf("SaveItem error = %v, want %v", err, wantErr)
	}
}

func TestGenerateShortURLReturnsInternalServerErrorWhenWriteFails(t *testing.T) {
	store := fakeShortURLStore{
		putItem: func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			return nil, errors.New("DynamoDB unavailable")
		},
	}
	router := gin.New()
	router.POST("/url_api/generate_short_url", func(c *gin.Context) {
		c.Set("tokenValid", true)
		generateShortURLHandler(c, "test-token", store)
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"/url_api/generate_short_url",
		strings.NewReader(`{"url":"https://example.com","user":"roy"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}

	if response.Body.String() != `{"error":"failed to create short URL"}` {
		t.Fatalf("body = %q, want %q", response.Body.String(), `{"error":"failed to create short URL"}`)
	}
}
