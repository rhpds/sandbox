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

// setTags sets the tags for the specified scope.
func (g *managementClient) setTags(scope string, tags map[string]string) error {
	err := g.refreshToken()
	if err != nil {
		return err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	requestBody := struct {
		Properties struct {
			Tags map[string]string `json:"tags"`
		} `json:"properties"`
	}{}
	requestBody.Properties.Tags = tags
	payloadBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"PUT",
		fmt.Sprintf(
			"https://management.azure.com/%s/providers/Microsoft.Resources/tags/default?api-version=2021-04-01",
			strings.Trim(scope, "/")),
		bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)
	req.Header.Add("Content-Type", "application/json")

	response, err := restClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
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

	return nil
}

// updateTags updates (or delete) the tags for the specified scope.
func (g *managementClient) updateTags(scope string, tags map[string]string, operation string) error {
	err := g.refreshToken()
	if err != nil {
		return err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	requestBody := struct {
		Properties struct {
			Tags map[string]string `json:"tags"`
		} `json:"properties"`
		Operation string `json:"operation"`
	}{}
	requestBody.Operation = operation
	requestBody.Properties.Tags = tags
	payloadBytes, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(
		"PATCH",
		fmt.Sprintf(
			"https://management.azure.com/%s/providers/Microsoft.Resources/tags/default?api-version=2021-04-01",
			strings.Trim(scope, "/")),
		bytes.NewReader(payloadBytes))
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)
	req.Header.Add("Content-Type", "application/json")

	response, err := restClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
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

	return nil
}
