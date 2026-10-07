package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
)

type contextReminderStore struct {
	ctx context.Context
	svc *dynamodb.DynamoDB
}

func (store contextReminderStore) Query(input *dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
	return store.svc.QueryWithContext(store.ctx, input)
}

func (store contextReminderStore) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	return store.svc.GetItemWithContext(store.ctx, input)
}

type notificationSender func(sendSub, []byte) error

func runReminderWorker(ctx context.Context, store itineraryReminderStore, tables tableNames, now time.Time, send notificationSender) error {
	if store == nil {
		return errors.New("notification store is nil")
	}
	if send == nil {
		return errors.New("notification sender is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := json.Marshal(NotiPayload{
		Title: "Trip reminder", Body: "Are you ready to start?",
		Icon: "https://cdn-icons-png.flaticon.com/512/4906/4906333.png",
	})
	if err != nil {
		return fmt.Errorf("encode notification: %w", err)
	}
	location, err := time.LoadLocation("Asia/Taipei")
	if err != nil {
		return err
	}
	now = now.In(location)
	// Query each date separately when the next 30 minutes crosses midnight.
	now = now.Truncate(time.Minute)
	end := now.Add(30*time.Minute - time.Minute)
	type window struct{ date, start, end string }
	windows := []window{{now.Format("2006/01/02"), now.Format("15:04"), end.Format("15:04")}}
	if now.Format("2006/01/02") != end.Format("2006/01/02") {
		windows = []window{{now.Format("2006/01/02"), now.Format("15:04"), "23:59"}, {end.Format("2006/01/02"), "00:00", end.Format("15:04")}}
	}
	accounts := make(map[string]bool)
	var failures []error
	for _, interval := range windows {
		condition := expression.Key("Date").Equal(expression.Value(interval.date)).And(expression.Key("Time").Between(expression.Value(interval.start), expression.Value(interval.end)))
		expr, err := expression.NewBuilder().WithKeyCondition(condition).Build()
		if err != nil {
			return err
		}
		input := &dynamodb.QueryInput{
			TableName: aws.String(tables.Itineraries), IndexName: aws.String("Date-Time-index"),
			ExpressionAttributeNames: expr.Names(), ExpressionAttributeValues: expr.Values(), KeyConditionExpression: expr.KeyCondition(),
		}
		for {
			if err := ctx.Err(); err != nil {
				return errors.Join(append(failures, err)...)
			}
			result, err := store.Query(input)
			if err != nil {
				return errors.Join(append(failures, fmt.Errorf("query upcoming itineraries: %w", err))...)
			}
			if result == nil {
				return errors.Join(append(failures, errors.New("query upcoming itineraries returned no result"))...)
			}
			for _, item := range result.Items {
				if item["Account"] == nil {
					continue
				}
				account := aws.StringValue(item["Account"].S)
				if account == "" || accounts[account] {
					continue
				}
				accounts[account] = true
				if err := ctx.Err(); err != nil {
					return errors.Join(append(failures, err)...)
				}
				subscription, err := store.GetItem(&dynamodb.GetItemInput{
					TableName: aws.String(tables.Subscriptions),
					Key:       map[string]*dynamodb.AttributeValue{"Account": {S: aws.String(account)}},
				})
				if err != nil {
					failures = append(failures, errors.New("subscription lookup failed"))
					continue
				}
				if subscription == nil {
					continue
				}
				sub, ok := decodeSubscription(subscription.Item)
				if !ok {
					continue
				}
				if err := send(sub, payload); err != nil {
					failures = append(failures, fmt.Errorf("send notification: %w", err))
				}
			}
			if len(result.LastEvaluatedKey) == 0 {
				break
			}
			input.ExclusiveStartKey = result.LastEvaluatedKey
		}
	}
	return errors.Join(failures...)
}

func decodeSubscription(item map[string]*dynamodb.AttributeValue) (sendSub, bool) {
	var subscription sendSub
	attribute := item["Subscription"]
	if attribute == nil || attribute.M == nil {
		return subscription, false
	}
	endpoint, keys := attribute.M["Endpoint"], attribute.M["Keys"]
	if endpoint == nil || keys == nil || keys.M == nil || keys.M["Auth"] == nil || keys.M["P256dh"] == nil {
		return subscription, false
	}
	subscription.Subscription.Endpoint = aws.StringValue(endpoint.S)
	subscription.Subscription.Keys.Auth = aws.StringValue(keys.M["Auth"].S)
	subscription.Subscription.Keys.P256dh = aws.StringValue(keys.M["P256dh"].S)
	return subscription, subscription.Subscription.Endpoint != "" && subscription.Subscription.Keys.Auth != "" && subscription.Subscription.Keys.P256dh != ""
}

func sendNotificationWithContext(ctx context.Context, subscription sendSub, payload []byte) error {
	sub := &webpush.Subscription{Endpoint: subscription.Subscription.Endpoint, Keys: webpush.Keys{P256dh: subscription.Subscription.Keys.P256dh, Auth: subscription.Subscription.Keys.Auth}}
	response, err := webpush.SendNotificationWithContext(ctx, payload, sub, &webpush.Options{
		Subscriber: "kb274483@gmail.com", VAPIDPublicKey: vapidPublicKey, VAPIDPrivateKey: vapidPrivateKey, TTL: 60,
		HTTPClient: &http.Client{Timeout: appConfig.HTTPTimeout},
	})
	if err != nil {
		return errors.New("Web Push delivery failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("Web Push returned HTTP %d", response.StatusCode)
	}
	appLogger.event("info", "notification_sent", map[string]interface{}{"status": response.StatusCode})
	return nil
}
