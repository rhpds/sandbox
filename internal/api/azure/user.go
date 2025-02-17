package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type user struct {
	DisplayName       string
	UserPrincipalName string
	Id                string
}

// getUser retrieves user information.
func (g *graphClient) getUser(spName string) (*user, error) {
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
			"https://graph.microsoft.com/v1.0/users('%s')?$select=displayName,userPrincipalName,id",
			spName),
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
		userDetails := struct {
			DisplayName       string `json:"displayName"`
			UserPrincipalName string `json:"userPrincipalName"`
			Id                string `json:"id"`
		}{}
		err = json.Unmarshal(responseData, &userDetails)
		if err != nil {
			return nil, err
		}

		return &user{
			DisplayName:       userDetails.DisplayName,
			UserPrincipalName: userDetails.UserPrincipalName,
			Id:                userDetails.Id,
		}, nil

	case http.StatusAccepted:
		// It's not clear what to do in this case. Graph API documentation
		// does not provide much information about this status code. So just
		// return nil and an error.
		return nil, fmt.Errorf(
			"request was accepted by the Azure Graph API but no data"+
				"was returned for ServicePrincipal %s", spName)

	default:
		errorResponse := struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}{}
		err = json.Unmarshal(responseData, &errorResponse)
		if err != nil {
			panic(err)
		}

		return nil, fmt.Errorf("error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message)
	}
}
