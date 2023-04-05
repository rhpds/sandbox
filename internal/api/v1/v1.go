package v1

type Error struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}

type HealthCheckResult struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}

type PlacementRequest struct {
	ServiceUuid string            `json:"service_uuid"`
	Request     []ResourceRequest `json:"request"`
	Annotations map[string]string `json:"annotations"`
}

type ResourceRequest struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}
