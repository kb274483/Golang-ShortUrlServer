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

type fakeItineraryReminderStore struct {
	query   func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error)
	getItem func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
}

func (store *fakeItineraryReminderStore) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	return store.query(input)
}

func (store *fakeItineraryReminderStore) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	return store.getItem(input)
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

func TestLoginReturnsInternalServerErrorWhenUserLookupFails(t *testing.T) {
	store := fakeShortURLStore{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return nil, errors.New("DynamoDB unavailable")
		},
	}
	router := gin.New()
	router.POST("/url_api/login", func(c *gin.Context) {
		loginHandler(c, store)
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"/url_api/login",
		strings.NewReader(`{"account":"roy","password":"secret"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}

	if response.Body.String() != `{"error":"failed to log in"}` {
		t.Fatalf("body = %q, want %q", response.Body.String(), `{"error":"failed to log in"}`)
	}
}

func TestCreateMemberReturnsInternalServerErrorWhenSaveFails(t *testing.T) {
	store := fakeShortURLStore{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{}, nil
		},
		putItem: func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			return nil, errors.New("DynamoDB unavailable")
		},
	}
	router := gin.New()
	router.POST("/url_api/create_member", func(c *gin.Context) {
		createMember(c, store, store)
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"/url_api/create_member",
		strings.NewReader(`{"account":"roy","password":"secret"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}

	if response.Body.String() != `{"error":"failed to create member"}` {
		t.Fatalf("body = %q, want %q", response.Body.String(), `{"error":"failed to create member"}`)
	}
}

func TestCreateMemberReturnsInternalServerErrorWhenUserLookupFails(t *testing.T) {
	store := fakeShortURLStore{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return nil, errors.New("DynamoDB unavailable")
		},
	}
	router := gin.New()
	router.POST("/url_api/create_member", func(c *gin.Context) {
		createMember(c, store, store)
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"/url_api/create_member",
		strings.NewReader(`{"account":"roy","password":"secret"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}

	if response.Body.String() != `{"error":"failed to create member"}` {
		t.Fatalf("body = %q, want %q", response.Body.String(), `{"error":"failed to create member"}`)
	}
}

func TestAddItineraryReturnsInternalServerErrorWhenSaveFails(t *testing.T) {
	store := fakeShortURLStore{
		putItem: func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			return nil, errors.New("DynamoDB unavailable")
		},
	}
	router := gin.New()
	router.POST("/url_api/add_itinerary", func(c *gin.Context) {
		c.Set("tokenValid", true)
		addItinerary(c, store)
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"/url_api/add_itinerary",
		strings.NewReader(`{"timestamp":1,"account":"roy","title":"test","content":"test","date":"2026/09/02","time":"12:00","status":false}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}

	if response.Body.String() != `{"error":"failed to create itinerary"}` {
		t.Fatalf("body = %q, want %q", response.Body.String(), `{"error":"failed to create itinerary"}`)
	}
}

func TestSubscribeNotificationReturnsInternalServerErrorWhenSaveFails(t *testing.T) {
	store := fakeShortURLStore{
		putItem: func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
			return nil, errors.New("DynamoDB unavailable")
		},
	}
	router := gin.New()
	router.POST("/url_api/subscribe", func(c *gin.Context) {
		c.Set("tokenValid", true)
		subscribeNotification(c, store)
	})

	request := httptest.NewRequest(
		http.MethodPost,
		"/url_api/subscribe",
		strings.NewReader(`{"account":"roy","subscription":{"endpoint":"https://example.com","keys":{"p256dh":"key","auth":"auth"}}}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}

	if response.Body.String() != `{"error":"failed to save subscription"}` {
		t.Fatalf("body = %q, want %q", response.Body.String(), `{"error":"failed to save subscription"}`)
	}
}

func TestCheckItineraryContinuesWhenSubscriptionLookupFails(t *testing.T) {
	lookupCount := 0
	store := &fakeItineraryReminderStore{
		query: func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
			return &dynamodb.QueryOutput{Items: []map[string]*dynamodb.AttributeValue{
				{"Account": {S: aws.String("first")}},
				{"Account": {S: aws.String("second")}},
			}}, nil
		},
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			lookupCount++
			if lookupCount == 1 {
				return nil, errors.New("DynamoDB unavailable")
			}
			return &dynamodb.GetItemOutput{Item: map[string]*dynamodb.AttributeValue{
				"Subscription": {M: map[string]*dynamodb.AttributeValue{
					"Endpoint": nil,
					"Keys":     nil,
				}},
			}}, nil
		},
	}

	checkItinerary(store)

	if lookupCount != 2 {
		t.Fatalf("subscription lookups = %d, want 2", lookupCount)
	}
}
