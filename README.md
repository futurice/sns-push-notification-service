
API
---

    POST /device
    DELETE /device/<endpoint_arn>  # base64 encoded endpoint_arn

TBD:

    GET /topics
    GET /
    POST /publish/device/<endpoint_arn>  # base64 encoded endpoint_arn
    POST /publish/topic/<topic_id>  # base64 encoded topic_id


Registering a device
--------------------

    POST /device

JSON body:

    {
      "platform": "ios",
      "endpoint_arn": "optional, must be added if this device has been registered earlier",
      "notification_token": "token from apns/gcm/..."
    }

Deregistering a device
----------------------

    DELETE /device/<endpoint_arn>

Configuration
-------------

- `AWS_ACCESS_KEY`
- `AWS_SECRET_KEY`
- `AWS_REGION`
- `AUTOSUBSCRIBE_TOPICS` - optional. Comma-separated list of topics each device will be subscribed when registering
- `WNS_PLATFORM_APPLICATION`
- `APNS_PLATFORM_APPLICATION`
- `GCM_PLATFORM_APPLICATION`
- `EMAIL_PLATFORM_APPLICATION`
