package azure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type servicePrincipal struct {
	id string
}

func (g *graphClient) createServicePrincipal(appID string) (*servicePrincipal, error) {
	err := g.refreshToken()
	if err != nil {
		return nil, err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	requestBody := struct {
		AppID string `json:"appId"`
	}{
		AppID: appID,
	}

	payloadBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"POST",
		"https://graph.microsoft.com/v1.0/servicePrincipals",
		bytes.NewBuffer(payloadBytes),
	)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)
	req.Header.Add("Content-type", "application/json")
	response, err := restClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusCreated {
		// Graph API reference has no information about error codes
		// returned by this endpoint.
		return nil, fmt.Errorf("failed to create service principal: %s", response.Status)
	}

	responseBody := struct {
		ID string `json:"id"`
	}{}
	err = json.Unmarshal(responseData, &responseBody)
	if err != nil {
		return nil, err
	}
	return &servicePrincipal{
		id: responseBody.ID,
	}, nil
}
