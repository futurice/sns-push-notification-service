IAM configuration
=================

[Example policy file](iam-example-policy.json). You need to add your application endpoints and topics before this file actually works.

Permissions (actions) explained:

- "SNS:CreatePlatformEndpoint" - this is required to register an endpoint (`POST /device`)
- "SNS:DeleteEndpoint" - required for `DELETE /device/<device_id>`
- "SNS:GetEndpointAttributes" - required for `GET /device/<device_id>`
- "SNS:SetEndpointAttributes" - required for updating/re-enabling devices when registering (`POST /device`)
- "SNS:Subscribe" - required for subscribing to topics (`POST /subscription/...` and `POST /device`)
- "SNS:Unsubscribe" - required for unsubscribing from topics (`DELETE /subscription/...`)
- "SNS:DeleteTopic" - `DELETE /topic/<topic_id>` (admin only)
- "SNS:CreateTopic" - `POST /topics` (admin only)
- "SNS:Publish" - `POST /publish/...` (admin only)
- "SNS:ListTopics" - `GET /topics`
