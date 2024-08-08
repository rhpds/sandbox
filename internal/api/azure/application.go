package azure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type application struct {
	AppID       string
	DisplayName string
	Password    string
}

// createApplication creates a new application and generate random password.
func (g *graphClient) createApplication(name string) (*application, error) {
	err := g.refreshToken()
	if err != nil {
		return nil, err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	requestBody := struct {
		DisplayName         string `json:"displayName"`
		PasswordCredentials []struct {
			DisplayName string `json:"displayName"`
		} `json:"passwordCredentials"`
	}{
		DisplayName: name,
		PasswordCredentials: []struct {
			DisplayName string `json:"displayName"`
		}{
			{DisplayName: "rbac"},
		},
	}
	payloadBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"POST",
		"https://graph.microsoft.com/v1.0/applications",
		bytes.NewBuffer(payloadBytes),
	)
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

	if response.StatusCode != http.StatusCreated {
		// Graph API reference tells nothing about possible errors or the
		// error response format.
		return nil,
			fmt.Errorf("failed to create the application: %s, server response: %s",
				name, string(responseData))
	}

	responseBody := struct {
		AppID               string `json:"appId"`
		DisplayName         string `json:"displayName"`
		PasswordCredentials []struct {
			DisplayName string `json:"displayName"`
			SecretText  string `json:"secretText"`
		} `json:"passwordCredentials"`
	}{}
	err = json.Unmarshal(responseData, &responseBody)
	if err != nil {
		return nil, err
	}

	// Only first password is used, so ignore the rest. This is a simplification
	// and may not be correct in all cases.
	return &application{
		AppID:       responseBody.AppID,
		DisplayName: responseBody.DisplayName,
		Password:    responseBody.PasswordCredentials[0].SecretText,
	}, nil
}

// getApplicationObjectIDs returns the object IDs of the applications with the
// given name.
func (g *graphClient) getApplicationObjectIDs(name string) ([]string, error) {
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
			"https://graph.microsoft.com/v1.0/applications"+
				"?$search=\"displayName:%s\"&$count=true&$select=Id",
			name,
		),
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Add("ConsistencyLevel", "eventual")
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

	if response.StatusCode != http.StatusOK {
		// Graph API reference tells nothing about possible errors or the
		// error response format.
		return nil,
			fmt.Errorf("failed to get the application object IDs, server response: %s",
				string(responseData))
	}

	responseBody := struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}{}
	err = json.Unmarshal(responseData, &responseBody)
	if err != nil {
		return nil, err
	}

	objectIDs := make([]string, 0, len(responseBody.Value))
	for _, app := range responseBody.Value {
		objectIDs = append(objectIDs, app.ID)
	}

	return objectIDs, nil
}

// deleteApplication deletes the application with the given object ID.
func (g *graphClient) deleteApplication(objectID string) error {
	err := g.refreshToken()
	if err != nil {
		return err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"DELETE",
		"https://graph.microsoft.com/v1.0/applications/"+objectID,
		nil,
	)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)

	response, err := restClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		// Graph API reference tells nothing about possible errors or the
		// error response format.
		return fmt.Errorf("failed to delete the application with ID: %s", objectID)
	}

	return nil
}

// permanentDeleteApplication deletes the application with the given object ID
// permanently. This operation cannot be undone.
func (g *graphClient) permanentDeleteApplication(objectID string) error {
	err := g.refreshToken()
	if err != nil {
		return err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"DELETE",
		"https://graph.microsoft.com/v1.0/directory/deletedItems/"+objectID,
		nil,
	)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)

	response, err := restClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		// Graph API reference tells nothing about possible errors or the
		// error response format.
		return fmt.Errorf("failed to permanently delete the application with ID: %s", objectID)
	}

	return nil
}
