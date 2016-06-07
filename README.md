SNS push service
================

This service provides a simple API for registering devices to SNS.

Installation
------------

1. Sign up to AWS
2. Configure SNS (create topics and platform applications).
3. Configure [IAM](https://aws.amazon.com/documentation/iam/) for SNS access. [Example policy](iam-example-policy.json). Add your topics and platform applications to `Resource` array.
4. Set up SNS credentials and other settings as environment variables ([config variables in Heroku](https://devcenter.heroku.com/articles/config-vars)).
5. In local environment, create and activate new python virtual environment (`pyvenv push-service-env; source push-service-env/bin/activate`) and install dependencies (`pip install -r requirements.txt`). For Heroku, push to heroku remote (`git push heroku master`).

Configuration
-------------

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

API
---

    POST /device
    DELETE /device/<endpoint_arn>  # base64 encoded endpoint_arn
    GET /status
    GET /topics

TBD:

    GET /
    POST /publish/device/<endpoint_arn>  # base64 encoded endpoint_arn
    POST /publish/topic/<topic_id>  # base64 encoded topic_id


Registering an endpoint
-----------------------

    POST /device

JSON body:

    {
      "platform": "ios",
      "endpoint_arn": "optional, must be added if this device has been registered earlier",
      "notification_token": "token from apns/gcm/..."
    }

1. Send POST request to `/device`. If there is `endpoint_arn` stored on the device, include it.
2. Check that the return code is 200 OK.
3. Store `endpoint_arn` from the response.

`endpoint_arn` in POST request is *not* encoded.

Deregistering a device
----------------------

    DELETE /device/<endpoint_arn>

`endpoint_arn` must be base64 encoded. For example, deleting endpoint with device_arn `arn:aws:sns:eu-west-1:1234567890123:endpoint/GCM/your-application-identifier/1b386cbc-7390-303a-8507-174309a94f4b` would become `DELETE /device/YXJuOmF3czpzbnM6ZXUtd2VzdC0xOjEyMzQ1Njc4OTAxMjM6ZW5kcG9pbnQvR0NNL3lvdXItYXBwbGljYXRpb24taWRlbnRpZmllci8xYjM4NmNiYy03MzkwLTMwM2EtODUwNy0xNzQzMDlhOTRmNGI=`. Padding (trailing `=` characters) must be included.


License
-------

BSD 3-clause. See [LICENSE.txt](LICENSE.txt) for full license text.
