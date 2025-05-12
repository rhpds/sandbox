package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rhpds/sandbox/internal/log"
)

type user struct {
	DisplayName       string
	UserPrincipalName string
	Id                string
}

// getUser retrieves user information.
func (g *graphClient) getUser(spName string) (*user, error) {
  log.Logger.Info("Entering getUser", "email", spName)
	err := g.refreshToken()
	if err != nil {
		log.Logger.Error("Error refreshToken", "email", spName)
		return nil, err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

  log.Logger.Info("Entering getUser2", "email", spName)
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf(
			"https://graph.microsoft.com/v1.0/users/%s?$select=displayName,userPrincipalName,id",
			spName),
		nil)
	if err != nil {
		log.Logger.Error("Error NewRequest.getUser", "email", spName)
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)
  log.Logger.Info("Entering getUser3", "email", spName)

	response, err := restClient.Do(req)
	if err != nil {
		log.Logger.Error("Error getUser", "respnonse", response)
		return nil, err
	}
	defer response.Body.Close()

  log.Logger.Info("Entering getUser4", "email", spName)
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		log.Logger.Error("Error getUser", "respnonse", responseData)
		return nil, err
	}

  log.Logger.Info("Entering getUser5", "email", spName)
	switch response.StatusCode {
	case http.StatusNotFound:
		log.Logger.Info("Entering getUser6", "responseData", responseData)
		return nil,nil
	case http.StatusOK:
		log.Logger.Info("Entering getUser6a", "responseData", responseData)
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
		log.Logger.Info("Entering getUser6b", "responseData", responseData)
		return nil, fmt.Errorf(
			"request was accepted by the Azure Graph API but no data"+
				"was returned for ServicePrincipal %s", spName)

	default:
		log.Logger.Info("Entering getUser6c", "responseData", responseData, "response", fmt.Sprintf("%v", response))
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
