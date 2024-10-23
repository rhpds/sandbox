package azure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type dnsZoneParameters struct {
	Tags              map[string]string
	SubscriptionID    string
	ResourceGroupName string
	ZoneName          string
	Location          string
}

type dnsZone struct {
	Id       string
	Name     string
	Type     string
	Location string
}

// createDNSZone creates a new DNS zone in the specified resource group.
func (g *managementClient) createDNSZone(param dnsZoneParameters) (*dnsZone, error) {
	err := g.refreshToken()
	if err != nil {
		return nil, err
	}

	restEndpoint := fmt.Sprintf(
		"https://management.azure.com/"+
			"subscriptions/%s/"+
			"resourceGroups/%s/"+
			"providers/Microsoft.Network/dnsZones/%s"+
			"?api-version=2018-05-01",
		param.SubscriptionID,
		param.ResourceGroupName,
		param.ZoneName,
	)

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	payloadBytes, err := json.Marshal(
		struct {
			Tags     map[string]string `json:"tags,omitempty"`
			Location string            `json:"location"`
		}{
			Location: param.Location,
			Tags:     param.Tags,
		},
	)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", restEndpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)
	req.Header.Add("Content-Type", "application/json")

	response, err := restClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated:
		zoneInfo := struct {
			Id       string `json:"id"`
			Name     string `json:"name"`
			Type     string `json:"type"`
			Location string `json:"location"`
		}{}
		err = json.Unmarshal(responseData, &zoneInfo)
		if err != nil {
			return nil, err
		}

		return &dnsZone{
			Id:       zoneInfo.Id,
			Name:     zoneInfo.Name,
			Type:     zoneInfo.Type,
			Location: zoneInfo.Location,
		}, nil

	default:
		errorResponse := struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}{}
		err = json.Unmarshal(responseData, &errorResponse)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf(
			"error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message,
		)
	}
}
