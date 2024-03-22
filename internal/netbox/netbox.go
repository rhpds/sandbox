package netbox

import (
	"encoding/json"
	"fmt"
	"net/http"
  "crypto/tls"
  "strings"
  "bytes"
)

func RequestIP(apiURL, token, description string)(string, error) {
  prefixID,err := SelectPrefixID(apiURL, token)
	if err != nil {
    return "", fmt.Errorf("Error: %s", err)
	}
  address, err := RequestAvailableIP(apiURL, token, prefixID, description)
  return address,nil
} 
func RequestAvailableIP(apiURL string, token string, prefixID int, description string) (string, error) {
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    client := &http.Client{}
    body := []byte(fmt.Sprintf(`{"description":"%s"}`, description))
    req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/ipam/prefixes/%d/available-ips/", apiURL, prefixID), bytes.NewBuffer(body))
    if err != nil {
      return "", fmt.Errorf("Error: %s", err)
    }
    req.Header.Set("Authorization", "Token "+token)
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Content-Type", "application/json")
    resp, err := client.Do(req)
    if err != nil {
      return "", fmt.Errorf("Error: %s", err)
    }
    defer resp.Body.Close()
    var data map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
      return "", fmt.Errorf("Error: %s", err)
    }
    return strings.Split(data["address"].(string),"/")[0], nil
  }

func SelectPrefixID(apiURL, token string) (int, error) {
  http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/ipam/prefixes/?status=active", apiURL), nil)
	if err != nil {
		return -1, fmt.Errorf("Error: %s", err)
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return -1, fmt.Errorf("Error: %s", err)
	}
	defer resp.Body.Close()
	var prefixIDs []int
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return -1, fmt.Errorf("Error: %s", err)
	}
	results := data["results"].([]interface{})
	for _, result := range results {
		id := int(result.(map[string]interface{})["id"].(float64))
		prefixIDs = append(prefixIDs, id)
	}
	for _, prefixID := range prefixIDs {
		_, err := GetAvailableIP(apiURL, token, prefixID)
		if err != nil {
			continue
		} else {
      return prefixID,nil
   }
	}
  return 0,fmt.Errorf("no active prefixes found")
}
func GetAvailableIP(apiURL, token string, prefixID int) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/ipam/prefixes/%d/available-ips/?limit=1", apiURL, prefixID), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
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
