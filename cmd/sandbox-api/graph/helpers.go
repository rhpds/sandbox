package graph

import (
	"github.com/rhpds/sandbox/cmd/sandbox-api/graph/model"
	"github.com/rhpds/sandbox/internal/models"
)

// toGraphQLPlacement converts internal Placement model to GraphQL model
func toGraphQLPlacement(p *models.Placement) *model.Placement {
	// Convert map[string]string to map[string]any for GraphQL
	annotations := make(map[string]any)
	for k, v := range p.Annotations {
		annotations[k] = v
	}

	return &model.Placement{
		ID:          p.ID,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
		ServiceUUID: p.ServiceUuid,
		Status:      p.Status,
		ToCleanup:   p.ToCleanup,
		Annotations: annotations,
		Request:     p.Request,
	}
}
