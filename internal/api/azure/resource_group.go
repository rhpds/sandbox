package azure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type resourceGroupParameters struct {
	Tags              map[string]string
	SubscriptionId    string
	ResourceGroupName string
	Location          string
}

type resourceGroup struct {
	Id                string
	Name              string
	Location          string
	ProvisioningState string
}

// createResourceGroup creates a new Resource Group.
func (g *managementClient) createResourceGroup(param resourceGroupParameters) (*resourceGroup, error) {
	err := g.refreshToken()
	if err != nil {
		return nil, err
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

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"PUT",
		fmt.Sprintf(
			"https://management.azure.com/subscriptions/%s/resourcegroups/%s?api-version=2021-04-01",
			strings.Trim(param.SubscriptionId, "/"),
			strings.Trim(param.ResourceGroupName, "/"),
		),
		bytes.NewReader(payloadBytes))
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
		groupInfo := struct {
			Id         string `json:"id"`
			Name       string `json:"name"`
			Location   string `json:"location"`
			Properties struct {
				ProvisioningState string `json:"provisioningState"`
			} `json:"properties"`
		}{}
		err = json.Unmarshal(responseData, &groupInfo)
		if err != nil {
			return nil, err
		}

		return &resourceGroup{
			Id:                groupInfo.Id,
			Name:              groupInfo.Name,
			Location:          groupInfo.Location,
			ProvisioningState: groupInfo.Properties.ProvisioningState,
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

		return nil, fmt.Errorf("error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message)
	}
}

// listResourceGroups returns a list of Resource Groups for the Subscription.
func (g *managementClient) listResourceGroups(subscriptionId string) ([]resourceGroup, error) {
	err := g.refreshToken()
	if err != nil {
		return nil, err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf(
			"https://management.azure.com/subscriptions/%s/resourcegroups?api-version=2021-04-01",
			subscriptionId),
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

	switch response.StatusCode {
	case http.StatusOK:
		groupInfo := struct {
			Value []struct {
				Id         string `json:"id"`
				Name       string `json:"name"`
				Location   string `json:"location"`
				Properties struct {
					ProvisioningState string `json:"provisioningState"`
				} `json:"properties"`
			} `json:"value"`
		}{}
		err = json.Unmarshal(responseData, &groupInfo)
		if err != nil {
			return nil, err
		}

		var groups []resourceGroup

		for _, rg := range groupInfo.Value {
			groups = append(groups, resourceGroup{
				Id:                rg.Id,
				Name:              rg.Name,
				Location:          rg.Location,
				ProvisioningState: rg.Properties.ProvisioningState,
			})
		}

		return groups, nil

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

		return nil, fmt.Errorf("error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message)
	}
}

// deleteResourceGroup deletes a resource group.
func (g *managementClient) deleteResourceGroup(resourceGroupID string) error {
	err := g.refreshToken()
	if err != nil {
		return err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"DELETE",
		fmt.Sprintf(
			"https://management.azure.com/%s?api-version=2021-04-01",
			resourceGroupID),
		nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)

	response, err := restClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		return nil
	default:
		responseData, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}

		errorResponse := struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}{}
		err = json.Unmarshal(responseData, &errorResponse)
		if err != nil {
			return err
		}

		return fmt.Errorf("error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message)
	}
}
