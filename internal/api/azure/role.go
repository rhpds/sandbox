package azure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type roleDefinition struct {
	ID   string
	Type string
	Name string
}

type roleAssignment struct {
	ID   string
	Type string
	Name string
}

// getRoleDefinition searches for the roleName at the specified scope.
func (g *managementClient) getRoleDefinition(scope string, roleName string) (*roleDefinition, error) {
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
			"https://management.azure.com/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01",
			strings.Trim(scope, "")),
		nil,
	)
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
		roleDefinitions := struct {
			Value []struct {
				Properties struct {
					RoleName    string `json:"roleName"`
					Type        string `json:"type"`
					Description string `json:"description"`
				} `json:"properties"`
				ID   string `json:"id"`
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"value"`
		}{}
		err = json.Unmarshal(responseData, &roleDefinitions)
		if err != nil {
			return nil, err
		}

		for _, role := range roleDefinitions.Value {
			if role.Properties.RoleName == roleName {
				return &roleDefinition{
					ID:   role.ID,
					Type: role.Type,
					Name: role.Name,
				}, nil
			}
		}

		return nil, fmt.Errorf("role definition for \"%s\" role not found", roleName)
	default:
		errorResponse := struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}{}

		err = json.Unmarshal(responseData, &errorResponse)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message)
	}
}

// createRoleAssignment creates a new role assignment at the specified scope. If
// the role assignment already exists, it returns details about the existing role
// assignment.
func (g *managementClient) createRoleAssignment(
	scope string,
	roleDefinitionId string,
	principalId string,
	principalType string,
) (*roleAssignment, error) {
	err := g.refreshToken()
	if err != nil {
		return nil, err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	requestBody := struct {
		Properties struct {
			RoleDefinitionID string `json:"roleDefinitionId"`
			PrincipalID      string `json:"principalId"`
			PrincipalType    string `json:"principalType"`
		} `json:"properties"`
	}{}
	requestBody.Properties.RoleDefinitionID = roleDefinitionId
	requestBody.Properties.PrincipalID = principalId
	requestBody.Properties.PrincipalType = principalType
	payloadBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(
		"PUT",
		fmt.Sprintf(
			"https://management.azure.com/%s/providers/Microsoft.Authorization/roleAssignments/%s?api-version=2022-04-01",
			strings.Trim(scope, "/"),
			uuid.New(),
		),
		bytes.NewReader(payloadBytes),
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

	switch response.StatusCode {
	case http.StatusOK, http.StatusCreated:
		assignment := struct {
			Properties struct {
				RoleDefinitionID string `json:"roleDefinitionId"`
				PrincipalID      string `json:"principalId"`
				PrincipalType    string `json:"principalType"`
				Scope            string `json:"scope"`
			} `json:"properties"`
			Id   string `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
		}{}
		err = json.Unmarshal(responseData, &assignment)
		if err != nil {
			return nil, err
		}

		return &roleAssignment{
			ID:   assignment.Id,
			Type: assignment.Type,
			Name: assignment.Name,
		}, nil

	default:
		errorResponse := struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}{}
		err = json.Unmarshal(responseData, &errorResponse)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message)

	}
}

// getRoleAssignments search for the role assignments at the specified scope and
// role definition ID.
func (g *managementClient) getRoleAssignments(
	scope string,
	roleDefinitionId string,
) ([]roleAssignment, error) {
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
			"https://management.azure.com/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
			strings.Trim(scope, "")),
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
		roleAssignments := struct {
			Value []struct {
				Properties struct {
					RoleDefinitionID string `json:"roleDefinitionId"`
					PrincipalID      string `json:"principalId"`
				} `json:"properties"`
				Id   string `json:"id"`
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"value"`
		}{}
		err = json.Unmarshal(responseData, &roleAssignments)
		if err != nil {
			return nil, err
		}

		var assignments []roleAssignment
		for _, assignment := range roleAssignments.Value {
			if assignment.Properties.RoleDefinitionID == roleDefinitionId {
				assignments = append(assignments, roleAssignment{
					ID:   assignment.Id,
					Type: assignment.Type,
					Name: assignment.Name,
				})
			}
		}

		return assignments, nil

	default:
		errorResponse := struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}{}
		err = json.Unmarshal(responseData, &errorResponse)
		if err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("error: %s, %s",
			errorResponse.Error.Code,
			errorResponse.Error.Message)
	}
}

// deleteRoleAssignment deletes the role assignment.
func (g *managementClient) deleteRoleAssignment(
	roleAssignmentId string,
) error {
	err := g.refreshToken()
	if err != nil {
		return err
	}

	restClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest(
		"DELETE",
		fmt.Sprintf(
			"https://management.azure.com/%s?api-version=2022-04-01",
			strings.Trim(roleAssignmentId, "")),
		nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+g.token.AccessToken)

	response, err := restClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	switch response.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return nil

	default:
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
}
