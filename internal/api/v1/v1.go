package v1

type Error struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}

type HealthCheckResult struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}
