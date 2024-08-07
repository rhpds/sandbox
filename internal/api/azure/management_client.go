package azure

import (
	"time"
)

type managementClient struct {
	oauth *oauth2Client
	token *oauth2Token
}

// initManagementClient initializes a new Azure API client (ResourceManagement scope)\
// with the given tenantId, clientId, and secret.
func initManagementClient(tenantId string, clientId string, secret string) *managementClient {
	token := &oauth2Token{
		Expires: time.Unix(0, 0).UTC(),
	}

	return &managementClient{
		token: token,
		oauth: oauthInit(tenantId, clientId, secret),
	}
}

// refreshToken checks if the current access token is about (~ 5 minutes) to
// expire and requests a new token if necessary.
func (g *managementClient) refreshToken() error {
	difference := time.Until(g.token.Expires)
	if difference <= (5 * time.Minute) {
		token, err := g.oauth.requestToken("https://management.azure.com")
		if err != nil {
			return err
		}

		g.token = token
	}

	return nil
}
