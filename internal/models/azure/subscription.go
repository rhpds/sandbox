package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type subscription struct {
	SubscriptionId   string
	SubscriptionFQID string
	DisplayName      string
}

// Retrieves the subscription details for the given subscription name.
// It uses the Microsoft OAuth2 client to request the subscription details. Returns
// the Subscription details or an error if the subscription was not found.
func (g *managementClient) getSubscription(name string) (*subscription, error) {
	err := g.refreshToken()
	if err != nil {
		return nil, err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"GET",
		"https://management.azure.com/subscriptions?api-version=2022-12-01",
		nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)

	response, err := restClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	// Base on the Azure REST API reference, the only response code possible is 200
	subscriptions := struct {
		Value []struct {
			Id             string `json:"id"`
			SubscriptionId string `json:"subscriptionId"`
			DisplayName    string `json:"displayName"`
		} `json:"value"`
	}{}
	err = json.Unmarshal(responseData, &subscriptions)
	if err != nil {
		return nil, err
	}

	for _, sub := range subscriptions.Value {
		if sub.DisplayName == name {
			return &subscription{
				SubscriptionId:   sub.SubscriptionId,
				SubscriptionFQID: sub.Id,
				DisplayName:      sub.DisplayName,
			}, nil
		}
	}

	return nil, fmt.Errorf("subscription %s not found", name)
}
