package azure

import (
	"time"
)

type graphClient struct {
	oauth *oauth2Client
	token *oauth2Token
}

// initGraphClient initializes a new MS Graph API client with the given
// tenantId, clientId, and secret.
func initGraphClient(tenantId string, clientId string, secret string) *graphClient {
	token := &oauth2Token{
		Expires: time.Unix(0, 0).UTC(),
	}

	return &graphClient{
		token: token,
		oauth: oauthInit(tenantId, clientId, secret),
	}
}

// refreshToken checks if the current access token is about (~ 5 minutes) to
// expire and requests a new token if necessary.
func (g *graphClient) refreshToken() error {
	difference := time.Until(g.token.Expires)
	if difference <= (5 * time.Minute) {
		token, err := g.oauth.requestToken("https://graph.microsoft.com")
		if err != nil {
			return err
		}

		g.token = token
	}

	return nil
}
