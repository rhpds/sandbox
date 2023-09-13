GET http://{{host}}/api/v1/login
Authorization: Bearer {{login_token}}
HTTP 200
[Captures]
access_token: jsonpath "$.access_token"

DELETE http://{{host}}/api/v1/placements/{{uuid}}
Authorization: Bearer {{access_token}}
[Options]
retry: 40
HTTP 404
