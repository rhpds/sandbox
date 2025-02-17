package azure

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

type poolClient struct {
	projectTag    string
	poolID        string
	poolAPISecret string
}

// initPoolClient initializes a new Subscription Pool management API client.
func InitPoolClient(projectTag string, poolId string, poolAPISecret string) *poolClient {
	return &poolClient{
		projectTag:    projectTag,
		poolID:        poolId,
		poolAPISecret: poolAPISecret,
	}
}

// allocatePool requests a new Subscription from the pool.
func (pc *poolClient) AllocatePool() (string, error) {
	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf(
			"https://rhpdspoolhandler.azurewebsites.net/api/get/%s/%s?code=%s",
			pc.projectTag,
			pc.poolID,
			pc.poolAPISecret),
		nil)
	if err != nil {
		return "", err
	}

	response, err := restClient.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	return string(responseData), nil
}

// releasePool releases allocated Subscription back to pool.
func (pc *poolClient) ReleasePool() error {
	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf(
			"https://rhpdspoolhandler.azurewebsites.net/api/release/%s/%s?code=%s",
			pc.projectTag,
			pc.poolID,
			pc.poolAPISecret),
		nil)
	if err != nil {
		return err
	}

	response, err := restClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	_, err = io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	return nil
}
