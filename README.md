About this fork
------------

This fork provides additional capability for associating SNS endpoints with application specific user identifiers. This service is expected to be hosted using elastic beanstalk preconfigured python docker container and requires access to DynamoDB.

SNS push service
================

This service provides a simple API for registering devices to SNS.

What this is and what this is not?
----------------------------------

- There *is* a simple API for basic operations
- There *is* a simple token authentication with two tokens (admin/user)
- This *is not* full management service for SNS
- There *is no* functionality for managing platform applications or permissions. Do these through SNS console.
- There *is no* support for email/SMS/SQS/HTTP/... subscriptions. This service is designed for mobile apps, and not to be a generic all-purpose push service.
- There *is no* configurable authorization logic, or multiple authentication schemes. There is only admin token for all operations and restricted consumer token.

Push requests for functionality listed with "no" will probably be rejected - even though those features would be useful for some people, not everything is worth added complexity.

Installation
------------

1. Sign up to AWS
2. Configure SNS (create topics and platform applications).
3. Configure [IAM](https://aws.amazon.com/documentation/iam/) for SNS access. [IAM configuration explained](iam_configuration.md). Add your topics and platform applications to `Resource` array.
4. Configure [IAM](http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/authentication-and-access-control.html) for DynamoDB access.
5. Set up SNS credentials and other settings as environment variables.
6. In local environment, create and activate new python virtual environment (`pyvenv push-service-env; source push-service-env/bin/activate`) and install dependencies (`pip install -r requirements.txt`).


Configuration
-------------

- `ADMIN_AUTH_TOKEN` - authentication token for admin access (publishing, deleting topics etc.). Optional, but if missing, admin access is disabled.
- `AUTH_TOKEN` - authentication token. Optional, but if missing, random one will be generated on each start.
- `DEBUG` - if set to "true", Flask debug and debug logging will be enabled. Optional.
- `AWS_ACCESS_KEY` - access key from Amazon. Avoid using your full-access credentials here - configure restricted account with IAM. Mandatory.
- `AWS_SECRET_KEY` - secret access key. Mandatory.
- `AWS_REGION` - AWS region name for configured SNS (i.e., `eu-west-1`). Mandatory.
- `AUTOSUBSCRIBE_TOPICS` - optional. Comma-separated list of topics each device will be subscribed automatically during registration.
- `PATH_PREFIX` - optional. A prefix added to the URL path (without the leading `/`). eg. with a value of `push-service` the `topics` endpoint would be under `/push-service/topics`
- `DYNAMODB_TABLE_NAME` - table name in DynamoDB for storing user to endpoint mapping.

Configuring platform applications: create platform applications in SNS first. In this service, you need to invent aliases for each platform application. For example, if you have platform application with identifier `arn:aws:sns:eu-west-1:133752156591:app/WNS/your-app-name-here`, you can add environment variable

    APP_NAME_PLATFORM_APPLICATION="arn:aws:sns:eu-west-1:133752156591:app/WNS/your-app-name-here"

This way, your Windows Phone (WNS) application will use `"platform": "app_name"` in registration requests.

If you have only a single application per upstream platform (one for GCM, one for APNS and so on), it is recommended to use

    GCM_PLATFORM_APPLICATION="sns_identifier"
    APNS_PLATFORM_APPLICATION="sns_identifier"

and so on, so that Android mobile application can then use `"platform": "gcm"`, and iOS applications will use `"platform": "apns"`

For example,

    DEBUG="false"
    AWS_ACCESS_KEY="UIIAJTGMIZEQLRYNBDPA"
    AWS_SECRET_KEY="OAiGHMHv31lp48li0Q23CnFS4iodLmk9GO5J1A0K"
    AWS_REGION="eu-west-1"
    GCM_PLATFORM_APPLICATION="arn:aws:sns:eu-west-1:018561567490:app/GCM/your-app-identifier-here"
    GCM_MOBILE_PLATFORM_APPLICATION="arn:aws:sns:eu-west-1:018561567490:app/GCM/another-app-identifier-here"
    GCM_TABLET_PLATFORM_APPLICATION="arn:aws:sns:eu-west-1:018561567490:app/GCM/yet-another-app-identifier-here"
    AUTOSUBSCRIBE_TOPICS="arn:aws:sns:eu-west-1:038762057900:all-items-topic"
    DYNAMODB_TABLE_NAME="user-to-endpoint-mapping"

With this configuration, all new endpoints will be subscribed to "all-items-topic". Apps can use `gcm`, `gcm_mobile` and `gcm_tablet` as platform identifier. Each identifier will be registered to a different SNS platform application.

Authorization
-------------

Send authentication token (configured with `AUTH_TOKEN` environment variable. If not configured, see startup logs for random token) as `Auth-Token` (case-insensitive) HTTP header. I.e.,

    GET /topics
    Host: your-server-hostname.example.com
    Auth-Token: HQD2PAKBNKSEVXCFJ6LCLE32FPRKN47MO5Y0RYWPPCLMH3Z0AA

See your HTTP client's documentation for API to send custom headers.

Admin token (configured with `ADMIN_AUTH_TOKEN` environment variable) uses the same header. Admin token is required for all admin endpoints. Do not include admin token in any public client applications, as it allows sending push notifications and deleting topics.

API
---

    POST /device
    DELETE /device/<endpoint_id>  # base64 encoded endpoint_id
    GET /status
    GET /stats
    GET /topics
    GET /topic/<topic_id>  # base64 encoded topic_id
    POST /subscription/topic/<topic_id>/target/<endpoint_id>  # base64 encoded topic_id and endpoint_id.
    DELETE /subscription/topic/<topic_id>/target/<subscription_id>  # base64 encoded topic_id and subscription_id.

Admin endpoints:

    POST /topics
    DELETE /topic/<topic_id>  # base64 encoded topic_id
    POST /publish/endpoint/<endpoint_id>  # base64 encoded endpoint_id
    POST /publish/topic/<topic_id>  # base64 encoded topic_id
    POST /publish/user/<user_id>  # base64 encoded user_id


Registering an endpoint
-----------------------

    POST /device

JSON body:

    {
      "platform": "ios",
      "endpoint_id": "optional, must be added if this device has been registered earlier",
      "notification_token": "token from apns/gcm/...",
      "auto_subscribe": true,
      "user_ids": ["user1"]
    }

`auto_subscribe` is true by default. Optional field. If set to false, device is not automatically subscribed to `AUTOSUBSCRIBE_TOPICS`. There is no separate endpoint for just subscribing to default topics. If you want to do that, send a new registration request without `auto_subscribe: false`, and the server will handle subscriptions.

1. Send POST request to `/device`. If there is `endpoint_id` stored on the device, include it.
2. Check that the return code is 200 OK.
3. Store `endpoint_id` from the response. This is needed for other requests.

`endpoint_id` in POST request is *not* encoded.

If client loses `endpoint_id`, it can just re-register. If the notification token did not change, SNS will return the same `endpoint_id`. If the notification token changed, new `endpoint_id` will be assigned. In this case SNS will keep the old endpoint registration, but it will be disabled when the token expires from APNS/GCM/... Unfortunately, there may be timeframe when both tokens are valid, and user will receive duplicate push notifications. This can be avoided by always including `endpoint_id` when registering the device.

Deregistering a device
----------------------

    DELETE /device/<endpoint_id>

    JSON body:

        {
          "user_ids": ["user1"]
        }

`endpoint_id` must be base64 encoded. For example, deleting endpoint with device_id `arn:aws:sns:eu-west-1:1234567890123:endpoint/GCM/your-application-identifier/1b386cbc-7390-303a-8507-174309a94f4b` would become `DELETE /device/YXJuOmF3czpzbnM6ZXUtd2VzdC0xOjEyMzQ1Njc4OTAxMjM6ZW5kcG9pbnQvR0NNL3lvdXItYXBwbGljYXRpb24taWRlbnRpZmllci8xYjM4NmNiYy03MzkwLTMwM2EtODUwNy0xNzQzMDlhOTRmNGI=`. Padding (trailing `=` characters) must be included.

Publishing to endpoint/topic/user
----------------------------

    POST /publish/endpoint/<endpoint_arn>  # base64 encoded endpoint_arn
    POST /publish/topic/<topic_id>  # base64 encoded topic_id
    POST /publish/user/<user_id> # base64 encoded user_id

JSON body:

    {
      "default": "Default message",
      "APNS": {
        "aps": {
          "alert": "Push notification message",
          "url": "http://www.futurice.com/"
        }
      },
      "GCM": {
        "data": {
          "custom-message": "Push notification message",
          "your-custom-data": "Data for your application"
        },
        "time_to_live": 3600,
        "collapse_key": "promotions"
      },
      "WNS": {
        ...
      }
    }

Main-level attributes are optional, except `default`, which must be included. In other words, if you don't have any Windows Phone devices, there's no reason to include `WNS` dictionary.

See upstream provider's reference for field names and descriptions. [GCM](https://developers.google.com/cloud-messaging/http-server-ref#send-downstream), [APNS](https://developer.apple.com/library/ios/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/Chapters/TheNotificationPayload.html)

Creating a new topic
--------------------

    POST /topics

JSON body:

    {
      "name": "topic-name-including_numbers_123"
    }

"name" must conform to `[A-Za-z0-9-_]{1,256}`

Returns `{"topic_id": "<id_from_amazon>"}`

Subscribing and unsubscribing to/from topics
--------------------------------------------

    POST /subscription/topic/<topic_id>/target/<endpoint_id>  # base64 encoded topic_id and endpoint_id.

Empty body. Returns

    {
      "subscription_id": "<subscription_id_string>"
    }

Client needs to store `subscription_id` if it ever wants to unsubscribe from the topic. Deregistering the device (`DELETE /device/<device_id>`) will remove all subscriptions.

Unsubscribing from topic is not possible without subscription ID:

    DELETE /subscription/topic/<topic_id>/target/<subscription_id>  # base64 encoded topic_id and subscription_id.


License
-------

BSD 3-clause. See [LICENSE.txt](LICENSE.txt) for full license text.
