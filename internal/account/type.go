package account

type Account struct {
	Name               string  `json:"name"`
	Available          bool    `json:"available"`
	Guid               string  `json:"guid"`
	Envtype            string  `json:"envtype"`
	AccountID          string  `json:"account_id"`
	Owner              string  `json:"owner"`
	OwnerEmail         string  `json:"owner_email"`
	Zone               string  `json:"zone"`
	HostedZoneID       string  `json:"hosted_zone_id"`
	UpdateTime         float64 `json:"aws:rep:updatetime"`
	Comment            string  `json:"comment"`
	AwsAccessKeyID     string  `json:"aws_access_key_id"`
	AwsSecretAccessKey string  `json:"aws_secret_access_key"`
	// Conan
	ToCleanup          bool    `json:"to_cleanup"`
	ConanStatus        string  `json:"conan_status"`
	ConanTimestamp     string  `json:"conan_timestamp"`
	ConanHostname      string  `json:"conan_hostname"`
}
