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
- There *is no* state on the server side, i.e., all client information, subscriptions and so on are stored in SNS, not on this service. This means client devices (mobile apps) must keep their device IDs and subscription IDs stored somewhere.

Push requests for functionality listed with "no" will probably be rejected - even though those features would be useful for some people, not everything is worth added complexity.

Installation
------------

1. Sign up to AWS
2. Configure SNS (create topics and platform applications).
3. Configure [IAM](https://aws.amazon.com/documentation/iam/) for SNS access. [Example policy](iam-example-policy.json). Add your topics and platform applications to `Resource` array.
4. Set up SNS credentials and other settings as environment variables ([config variables in Heroku](https://devcenter.heroku.com/articles/config-vars)).
5. In local environment, create and activate new python virtual environment (`pyvenv push-service-env; source push-service-env/bin/activate`) and install dependencies (`pip install -r requirements.txt`). For Heroku, push to heroku remote (`git push heroku master`).

Configuration
-------------

- `ADMIN_AUTH_TOKEN` - authentication token for admin access (publishing, deleting topics etc.). Optional, but if missing, admin access is disabled.
- `AUTH_TOKEN` - authentication token. Optional, but if missing, random one will be generated on each start.
- `DEBUG` - if set to "true", Flask debug and debug logging will be enabled. Optional.
- `AWS_ACCESS_KEY` - access key from Amazon. Avoid using your full-access credentials here - configure restricted account with IAM. Mandatory.
- `AWS_SECRET_KEY` - secret access key. Mandatory.
- `AWS_REGION` - AWS region name for configured SNS (i.e., `eu-west-1`). Mandatory.
- `AUTOSUBSCRIBE_TOPICS` - optional. Comma-separated list of topics each device will be subscribed when registering an endpoint.

Configuring platform applications: create platform applications in SNS first. In this service, you need to invent aliases for each platform application.

For example, if you have platform application with identifier `arn:aws:sns:eu-west-1:133752156591:app/WNS/your-app-name-here`, you can add environment variable

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

With this configuration, all new endpoints will be subscribed to "all-items-topic". Endpoints can use `gcm`, `gcm_mobile` and `gcm_tablet` as platform identifier. Each identifier will be registered to different SNS platform application.

Authorization
-------------

Send authentication token (configured with `AUTH_TOKEN` environment variable. If not configured, see startup logs for random token) as `Auth-Token` (case-insensitive) HTTP header. I.e.,

    GET /topics
    Host: your-server-hostname.example.com
    Auth-Token: HQD2PAKBNKSEVXCFJ6LCLE32FPRKN47MO5Y0RYWPPCLMH3Z0AA

See your HTTP client's documentation for API to send custom headers.

API
---

    POST /device
    DELETE /device/<endpoint_id>  # base64 encoded endpoint_id
    GET /status
    GET /topics
    POST /publish/endpoint/<endpoint_id>  # base64 encoded endpoint_id
    POST /publish/topic/<topic_id>  # base64 encoded topic_id


Registering an endpoint
-----------------------

    POST /device

JSON body:

    {
      "platform": "ios",
      "endpoint_id": "optional, must be added if this device has been registered earlier",
      "notification_token": "token from apns/gcm/..."
    }

1. Send POST request to `/device`. If there is `endpoint_id` stored on the device, include it.
2. Check that the return code is 200 OK.
3. Store `endpoint_id` from the response.

`endpoint_id` in POST request is *not* encoded.

Deregistering a device
----------------------

    DELETE /device/<endpoint_id>

`endpoint_id` must be base64 encoded. For example, deleting endpoint with device_id `arn:aws:sns:eu-west-1:1234567890123:endpoint/GCM/your-application-identifier/1b386cbc-7390-303a-8507-174309a94f4b` would become `DELETE /device/YXJuOmF3czpzbnM6ZXUtd2VzdC0xOjEyMzQ1Njc4OTAxMjM6ZW5kcG9pbnQvR0NNL3lvdXItYXBwbGljYXRpb24taWRlbnRpZmllci8xYjM4NmNiYy03MzkwLTMwM2EtODUwNy0xNzQzMDlhOTRmNGI=`. Padding (trailing `=` characters) must be included.

Publishing to endpoint/topic
----------------------------

    POST /publish/endpoint/<endpoint_arn>  # base64 encoded endpoint_arn
    POST /publish/topic/<topic_id>  # base64 encoded topic_id

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


License
-------

BSD 3-clause. See [LICENSE.txt](LICENSE.txt) for full license text.
