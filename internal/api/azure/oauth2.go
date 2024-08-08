package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type oauth2Token struct {
	TokenType   string
	Expires     time.Time
	AccessToken string
}

type oauth2Client struct {
	tenantId string
	clientId string
	secret   string
}

// oauthInit initializes a new OAuth2 client with the given tenantId, clientId,
// and secret.
func oauthInit(tenantId string, clientId string, secret string) *oauth2Client {
	return &oauth2Client{
		tenantId: tenantId,
		clientId: clientId,
		secret:   secret,
	}
}

// requestToken retrieves OAuth2 token for the specified scope.
func (o *oauth2Client) requestToken(scope string) (*oauth2Token, error) {
	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	v := url.Values{}
	v.Add("client_id", o.clientId)
	v.Add("scope", scope+"/.default")
	v.Add("client_secret", o.secret)
	v.Add("grant_type", "client_credentials")

	response, err := restClient.PostForm(
		fmt.Sprintf(
			"https://login.microsoftonline.com/%s/oauth2/v2.0/token",
			o.tenantId),
		v,
	)
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
		oauthToken := struct {
			TokenType   string `json:"token_type"`
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}{}
		err = json.Unmarshal(responseData, &oauthToken)
		if err != nil {
			return nil, err
		}

		return &oauth2Token{
			TokenType:   oauthToken.TokenType,
			Expires:     time.Now().Add(time.Duration(oauthToken.ExpiresIn) * time.Second).UTC(),
			AccessToken: oauthToken.AccessToken,
		}, nil

	case http.StatusBadRequest, http.StatusUnauthorized:
		error := struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
			Timestamp        string `json:"timestamp"`
			TraceID          string `json:"trace_id"`
			CorrelationID    string `json:"correlation_id"`
			ErrorCodes       []int  `json:"error_codes"`
		}{}
		err = json.Unmarshal(responseData, &error)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("can't get token: %s", error.ErrorDescription)
	default:
		return nil, fmt.Errorf("unexpected status code: %d", response.StatusCode)
	}
}
