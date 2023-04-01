package models

type Model struct {
	ID         int `json:"id"`
	CreatedAt  int `json:"created_at"`
	UpdatedAt int `json:"updated_at"`
}

type Resource struct {
	ResourceType string `json:"resource_type"`

	ServiceUuid string `json:"service_uuid"`
	Available   bool   `json:"available"`
	ToCleanup 	bool   `json:"to_cleanup"`

	Model
	Account // Resourcetype == "aws"
}

type ResourceWithCreds struct {
	ResourceType string `json:"resource_type"`

	Model
	AccountWithCreds // ResourceType == "aws"
}


type Account struct {
	AccountType string `json:"account_type"`

	AwsAccount // AccountType == "aws"
}

type AccountWithCreds struct {
	AccountType string `json:"account_type"`

	AwsAccountWithCreds // AccountType == "aws"
}

type Credential struct {
	CredentialType string `json:"credential_type"`

	AwsCredential // CredentialType == "aws"
}
