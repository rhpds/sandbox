package graph

import (
	"html/template"
	"net/http"
)

// PlaygroundHandler returns a handler that serves the GraphQL Playground with custom examples
func PlaygroundHandler(title, endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		playgroundTemplate.Execute(w, map[string]string{
			"title":    title,
			"endpoint": endpoint,
		})
	}
}

var playgroundTemplate = template.Must(template.New("playground").Parse(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{{.title}}</title>
  <link rel="stylesheet" href="https://unpkg.com/graphiql@3.0.10/graphiql.min.css" />
</head>
<body style="margin: 0;">
  <div id="graphiql" style="height: 100vh;"></div>
  <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
  <script crossorigin src="https://unpkg.com/graphiql@3.0.10/graphiql.min.js"></script>
  <script>
    const fetcher = GraphiQL.createFetcher({ url: '{{.endpoint}}' });
    const defaultQuery = ` + "`" + `# Sandbox API - GraphQL Placements
#
# Example queries (copy and run):
#
# Basic query:
{ placements(limit: 5) { id serviceUuid status } }

# All fields:
# {
#   placements(limit: 5) {
#     id
#     createdAt
#     updatedAt
#     serviceUuid
#     status
#     toCleanup
#     annotations
#     request
#     resources
#   }
# }

# Filter by status:
# { placements(status: "success", limit: 10) { id serviceUuid annotations } }

# Filter by annotations (JSONB contains):
# { placements(annotations: {guid: "test-001"}) { id serviceUuid annotations } }
# { placements(annotations: {env_type: "ocp4-cluster"}) { id serviceUuid status } }

# Get placements pending cleanup:
# { placements(toCleanup: true) { id serviceUuid status } }

# Get by UUID:
# { placementByServiceUuid(serviceUuid: "your-uuid") { id status resources } }

# Pagination:
# { placements(limit: 10, offset: 0) { id serviceUuid status } }
` + "`" + `;
    ReactDOM.createRoot(document.getElementById('graphiql')).render(
      React.createElement(GraphiQL, {
        fetcher: fetcher,
        defaultQuery: defaultQuery,
        defaultHeaders: JSON.stringify({ "Authorization": "Bearer YOUR_ADMIN_TOKEN" }, null, 2),
      }),
    );
  </script>
</body>
</html>`))
