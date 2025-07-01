package netbox

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
)

func RequestIP(apiURL, token, description string) (string, error) {
	prefixID, err := SelectPrefixID(apiURL, token)
	if err != nil {
		return "", fmt.Errorf("Error RequestIP: %s", err)
	}
	address, err := RequestAvailableIP(apiURL, token, prefixID, description)
	if err != nil {
		return "", fmt.Errorf("Error RequestAvailableIP: %s", err)
	}
	return address, nil
}
func RequestAvailableIP(apiURL string, token string, prefixID int, description string) (string, error) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	http.DefaultClient = client
	body := []byte(fmt.Sprintf(`{"status": "reserved", "description":"%s"}`, description))
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/ipam/prefixes/%d/available-ips/?format=json", apiURL, prefixID), bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("Error: %s", err)
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error RequestAvailableIP: %s", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("RequestAvailableIP Return code error: %s", resp.Status)
	}
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("Error RequestAvailableIP: %s", err)
	}
	return data["address"].(string), nil
}

func SelectPrefixID(apiURL, token string) (int, error) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/ipam/prefixes/?format=json&status=active", apiURL), nil)
	if err != nil {
		return -1, fmt.Errorf("Error: %s", err)
	}
	req.Header.Set("Authorization", "Token 2ee2e6b1235b028686f2547f3c8571999aed0ae3")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("Error: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("SelectPrefixID Return code error: %s", resp.Status)
	}
	var prefixIDs []int
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return -1, fmt.Errorf("Error SelectPrefixID: %s data: %v", err, resp)
	}
	defer resp.Body.Close()
	results, ok := data["results"]
	if ok {
		for _, result := range results.([]interface{}) {
			id := int(result.(map[string]interface{})["id"].(float64))
			prefixIDs = append(prefixIDs, id)
		}
		for _, prefixID := range prefixIDs {
			_, err := GetAvailableIP(apiURL, token, prefixID)
			if err != nil {
				continue
			} else {
				return prefixID, nil
			}
		}
	}
	return 0, fmt.Errorf("no active prefixes found")
}
func GetAvailableIP(apiURL, token string, prefixID int) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/ipam/prefixes/%d/available-ips/?format=json&limit=1", apiURL, prefixID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GetAvailableIP Return code error: %s", resp.Status)
	}
	defer resp.Body.Close()
	var data []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("no available IP for prefix ID %d", prefixID)
	}
	return data[0]["address"].(string), nil
}
func ReleaseIP(apiURL, token string, ip string) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/ipam/ip-addresses/?address=%s", apiURL, ip), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ReleaseIP search IP return code error: %s", resp.Status)
	}
	var data map[string]interface{}
	var ipID float64
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}
	defer resp.Body.Close()
	results := data["results"].([]interface{})
	if len(results) == 0 {
		return fmt.Errorf("IP %s was not reserved before", ip)
	} else {
		ipID = results[0].(map[string]interface{})["id"].(float64)
	}

	client = &http.Client{}
	req, err = http.NewRequest("DELETE", fmt.Sprintf("%s/api/ipam/ip-addresses/%d/", apiURL, int(ipID)), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("ReleaseIP Return code error: %s", resp.Status)
	}
	defer resp.Body.Close()
	return nil
}
