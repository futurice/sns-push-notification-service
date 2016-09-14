# pylint:disable=line-too-long
import base64
import binascii
import json
import logging
import os
import re

import boto3
import botocore.exceptions

from flask import Flask, request, Response
from flask_restful import Resource, Api, abort, reqparse
from flask_restful_url_generator import UrlList


DEBUG = os.environ.get("DEBUG", False) in (True, "true", "True")


def get_logger():
    """ Create a new logger instance """
    logger_instance = logging.getLogger("push-service")
    if DEBUG:
        logger_instance.setLevel(logging.DEBUG)
    else:
        logger_instance.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger_instance.addHandler(handler)
    return logger_instance


logger = get_logger()  # pylint:disable=invalid-name


def get_application_config(environment):
    """ Loads configurations from _PLATFORM_APPLICATION environment variables """
    config = {}
    for variable_name, variable_value in environment.items():
        plain_platform_match = PLATFORM_RE.match(variable_name)
        if plain_platform_match:
            platform_identifier = plain_platform_match.group("platform_identifier").lower()
            logger.debug("Adding new platform application: %s - %s", platform_identifier, variable_value)
            config[platform_identifier] = {
                "platform_application": variable_value
            }
    if len(config) == 0:
        logger.warning("No platform applications defined - registering new endpoints will not succeed.")
    return config


def admin_required():
    if hasattr(request, "is_admin") and request.is_admin:
        return
    abort(401, error_message="Admin token required")


def get_auth_token():
    """ Loads or generates authentication token """
    auth_token = os.environ.get("AUTH_TOKEN")
    if not auth_token:
        logger.warning("No authentication token - generating random token")
        import random
        import string
        # Snipped copied from http://stackoverflow.com/a/2257449
        auth_token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50))
        logger.warning("Auth-Token for this instance is '%s'. This token will be regenerated on restart. Please configure AUTH_TOKEN environment variable.", auth_token)
    return auth_token


AUTH_TOKEN = get_auth_token()
ADMIN_AUTH_TOKEN = os.environ.get("ADMIN_AUTH_TOKEN")
if not ADMIN_AUTH_TOKEN:
    logger.info("ADMIN_AUTH_TOKEN is not specified. Admin access (publishing etc.) is not available.")
if AUTH_TOKEN == ADMIN_AUTH_TOKEN:
    logger.warning("Do not set AUTH_TOKEN == ADMIN_AUTH_TOKEN. Disabling ADMIN_AUTH_TOKEN.")
    ADMIN_AUTH_TOKEN = None
AWS_SECRET_KEY = os.environ["AWS_SECRET_KEY"]
AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]
AWS_REGION = os.environ["AWS_REGION"]
DYNAMODB_TABLE_NAME = os.environ["DYNAMODB_TABLE_NAME"]

AUTOSUBSCRIBE_TOPICS = [topic for topic in os.environ.get("AUTOSUBSCRIBE_TOPICS", "").split(",") if len(topic)]
STATS = {
    "endpoint_deleted": 0,
    "endpoint_registered": 0,
    "endpoint_updated": 0,
    "http_200": 0,
    "http_204": 0,
    "http_400": 0,
    "http_401": 0,
    "http_404": 0,
    "http_500": 0,
    "message_published": 0,
    "sns_command_executed": 0,
    "sns_command_failed": 0,
    "sns_command_succeeded": 0,
    "topic_created": 0,
    "topic_deleted": 0,
    "topic_subscribed": 0,
    "topic_unsubscribed": 0,
}


# Check for path prefix
if os.environ.get("PATH_PREFIX"):
    PATH_PREFIX = "/" + os.environ.get('PATH_PREFIX').strip("/")
    logger.debug("PATH_PREFIX set to '%s'", PATH_PREFIX)
else:
    PATH_PREFIX = ""

PLATFORM_RE = re.compile("(?P<platform_identifier>[A-Z_]{1,50})_PLATFORM_APPLICATION")
CONFIG = get_application_config(os.environ)
BOTO_ERRORS = [
    (re.compile(r".*SignatureDoesNotMatch.*"), 500, "Incorrect upstream credentials"),
    (re.compile(r".*AuthorizationError.*"), 500, "Incorrect access configuration in SNS"),
    (re.compile(r".*InvalidParameter.*"), 400, "Incorrect token"),
]

logger.debug("CONFIG=%s", CONFIG)
logger.debug("Autosubscribe topics: %s", AUTOSUBSCRIBE_TOPICS)


def check_authorization():
    if request.endpoint == "status":
        return
    auth_token = request.headers.get("Auth-Token")
    if auth_token and auth_token == AUTH_TOKEN:
        return
    request.is_admin = False
    if auth_token and auth_token == ADMIN_AUTH_TOKEN:
        request.is_admin = True
        return
    abort(401, error_message="Incorrect or missing Auth-Token header")


def decode_base64_id(encoded_string):
    try:
        item_id = base64.b64decode(encoded_string).decode()
    except (binascii.Error, binascii.Incomplete):
        abort(400, error_message="Incorrect or corrupted base64 data")
    return item_id


app = Flask("push-service")  # pylint:disable=invalid-name
api = Api(app, prefix=PATH_PREFIX)  # pylint:disable=invalid-name
app.before_request(check_authorization)

sns = boto3.client("sns", region_name=AWS_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)  # pylint:disable=invalid-name
dynamodb = boto3.client("dynamodb", region_name=AWS_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)

register_device_parser = reqparse.RequestParser()  # pylint:disable=invalid-name
register_device_parser.add_argument("endpoint_id", required=False, type=str)
register_device_parser.add_argument("platform", required=True, type=str)
register_device_parser.add_argument("notification_token", required=True, type=str)
register_device_parser.add_argument("auto_subscribe", required=False, type=bool, default=True)
register_device_parser.add_argument("user_ids", action="append", required=True, type=str)

unregister_device_parser = reqparse.RequestParser()
unregister_device_parser.add_argument("user_ids", action="append", required=True, type=str)

paging_parser = reqparse.RequestParser()  # pylint:disable=invalid-name
paging_parser.add_argument("page", required=False, type=str)

name_parser = reqparse.RequestParser()  # pylint:disable=invalid-name
name_parser.add_argument("name", required=True, type=str)
TOPIC_NAME_RE = re.compile("[A-Za-z-_0-9]{1,256}")


@app.after_request
def calc_after_request_stats(response):
    status_code = response.status_code
    stats_key = "http_%s" % status_code
    if stats_key not in STATS:
        STATS[stats_key] = 1
    else:
        STATS[stats_key] += 1
    return response


class NotFoundException(Exception):
    pass


class Status(Resource):  # pylint:disable=missing-docstring
    def get(self):  # pylint:disable=no-self-use,missing-docstring
        return "OK"


@app.route("/stats")
def statistics():  # pylint:disable=missing-docstring
    output = ""
    for stat_key, stat_value in STATS.items():
        output += "%s %s\n" % (stat_key, stat_value)
    return Response(output, mimetype="text/plain")


def run_sns_command(command, *args, **kwargs):
    """ Run SNS command, and check for common errors """
    try:
        STATS["sns_command_executed"] += 1
        response = command(*args, **kwargs)
        STATS["sns_command_succeeded"] += 1
    except botocore.exceptions.ClientError as err:
        STATS["sns_command_failed"] += 1
        logger.warning("SNS command %s (args: %s, kwargs: %s) failed with %s", command, args, kwargs, err)
        client_error = str(err)
        if "NotFound" in client_error:
            raise NotFoundException
        for error_re, error_code, error_message in BOTO_ERRORS:
            if error_re.match(client_error):
                abort(error_code, error_message=error_message)
        raise err
    return response


def subscribe_to_topics(endpoint_id, endpoint_type):
    """ Subscribe to all autosubscribe topics """
    subscription_ids = []
    if len(AUTOSUBSCRIBE_TOPICS) > 0:
        for topic in AUTOSUBSCRIBE_TOPICS:
            STATS["topic_subscribed"] += 1
            topic_data = run_sns_command(sns.subscribe, TopicArn=topic, Protocol=endpoint_type, Endpoint=endpoint_id)
            subscription_ids.append(topic_data["SubscriptionArn"])
    return subscription_ids


def register_endpoint(platform_id, notification_token, user_ids):
    """ Create a new endpoint to SNS """
    logger.info("Registering %s to %s", notification_token, platform_id)
    registration_response = run_sns_command(sns.create_platform_endpoint, PlatformApplicationArn=platform_id,
                                            Token=notification_token, CustomUserData=', '.join(user_ids))
    STATS["endpoint_registered"] += 1
    return registration_response["EndpointArn"]


def update_endpoint(endpoint_id, notification_token, user_ids):
    """ Update endpoint details (enable the endpoint, update the token) """
    STATS["endpoint_updated"] += 1
    return run_sns_command(sns.set_endpoint_attributes, EndpointArn=endpoint_id,
                           Attributes={"Enabled": "true", "Token": notification_token, "CustomUserData": ', '.join(user_ids)})


def save_customer_id_endpoint_id_mapping(endpoint_id, customer_id):
    """ Save endpoint to customer id mapping to the dynamodb """
    logger.info("Saving endpoint %s mapped to %s", endpoint_id, customer_id)

    dynamodb.update_item(
        TableName = DYNAMODB_TABLE_NAME,
        Key = {"customerId": {"S": customer_id}},
        UpdateExpression="ADD endpointIds :e",
        ExpressionAttributeValues={":e": {"SS": [endpoint_id]}}
    )


def remove_customer_id_endpoint_id_mapping(endpoint_id, customer_id):
    """ Remove endpoint to customer id mapping to the dynamodb """
    logger.info("Removing endpoint %s mapped to %s", endpoint_id, customer_id)

    dynamodb.update_item(
        TableName = DYNAMODB_TABLE_NAME,
        Key = {"customerId": {"S": customer_id}},
        UpdateExpression="DELETE endpointIds :e",
        ExpressionAttributeValues={":e": {"SS": [endpoint_id]}}
    )

    try:
        dynamodb.delete_item(
            TableName = DYNAMODB_TABLE_NAME,
            Key = {"customerId": {"S": customer_id}},
            ConditionExpression="attribute_not_exists(endpointIds)"
        )
    except botocore.exceptions.ClientError as err:
        if not err.response['Error']['Code'] == "ConditionalCheckFailedException":
            raise


def retrieve_endpoint_ids_by_customer_id(customerId):
    try:
        result = dynamodb.get_item(
            TableName = DYNAMODB_TABLE_NAME,
            Key = {"customerId": {"S": customerId}}
        )
    except botocore.exceptions.ClientError as err:
        logger.warning("Failed to retrieve endpoint ids: %s", err.result['Error']['Message'])
    else:
        try:
           return result['Item']['endpointIds']['SS']
        except KeyError as err:
            abort(404, error_message="Customer ID not found")


class Device(Resource):  # pylint:disable=missing-docstring
    def post(self):  # pylint:disable=no-self-use
        """ Register a new endpoint.

            {
              "platform": "ios",
              "endpoint_id": "optional, must be added if this device has been registered earlier",
              "notification_token": "token from apns/gcm/..."
            }
        """
        args = register_device_parser.parse_args()
        platform = args["platform"].lower().replace("-", "_")
        if platform not in CONFIG:
            logger.warning("Client provided unknown platform: %s", platform)
            abort(400, error_message="Unknown platform")
        platform_id = CONFIG[platform]["platform_application"]
        if not platform_id or len(platform_id) == 0:
            logger.warning("Client provided unconfigured platform: %s (config: %s)", platform, CONFIG)
            abort(400, error_message="Unconfigured platform")

        endpoint_exists = False
        if "endpoint_id" in args and args["endpoint_id"]:
            # Device should already exist in SNS - try updating the metadata
            endpoint_id = args["endpoint_id"]
            logger.info("Updating %s with token %s", endpoint_id, args["notification_token"])
            try:
                update_endpoint(endpoint_id, args["notification_token"], args["user_ids"])
                endpoint_exists = True
            except NotFoundException:
                logger.warning("Tried to update non-existing endpoint: %s", endpoint_id)

        if not endpoint_exists:
            logger.info("Endpoint does not exist. Registering a new endpoint: %s - %s", platform_id, args["notification_token"])
            endpoint_id = register_endpoint(platform_id, args["notification_token"], args["user_ids"])
            for customer_id in args["user_ids"]:
                save_customer_id_endpoint_id_mapping(endpoint_id, customer_id)

        if args["auto_subscribe"]:
            subscription_ids = subscribe_to_topics(endpoint_id, "application")
        else:
            subscription_ids = []
            logger.debug("Did not subscribe device to any topics - auto_subscribe was set to false.")
        return {"endpoint_id": endpoint_id, "subscription_ids": subscription_ids}


class DeviceDetails(Resource):  # pylint:disable=missing-docstring
    def delete(self, endpoint_id):  # pylint:disable=no-self-use
        """ Delete the endpoint. Automatically removes all the subscriptions as well. """
        endpoint_id = decode_base64_id(endpoint_id)
        logger.info("Deleting endpoint %s", endpoint_id)
        sns.delete_endpoint(EndpointArn=endpoint_id)

        args = unregister_device_parser.parse_args()

        for customer_id in args["user_ids"]:
            remove_customer_id_endpoint_id_mapping(endpoint_id, customer_id)

        STATS["endpoint_deleted"] += 1
        return "", 204

    def get(self, endpoint_id):  # pylint:disable=no-self-use
        """ Get endpoint details (enabled, token, endpoint ID) """
        endpoint_id = decode_base64_id(endpoint_id)
        try:
            details = run_sns_command(sns.get_endpoint_attributes, EndpointArn=endpoint_id)
        except NotFoundException:
            abort(404, error_message="Endpoint does not exist")
        logger.debug("Getting information for %s: %s", endpoint_id, details)
        attributes = details["Attributes"]
        return {"endpoint_id": endpoint_id, "enabled": attributes["Enabled"] in (True, "True", "true"), "notification_token": attributes["Token"], "user_ids": attributes["CustomUserData"]}


class Topics(Resource):
    def get(self):  # pylint:disable=no-self-use
        """ List available topics """
        paging = paging_parser.parse_args()
        kwargs = {}
        if "page" in paging and paging["page"]:
            kwargs["NextToken"] = paging["page"]
        topics = run_sns_command(sns.list_topics, **kwargs)
        ret = {"next_page": topics.get("NextToken"),
               "topics": [topic["TopicArn"] for topic in topics.get("Topics", [])]}
        return ret

    def post(self):  # pylint:disable=no-self-use
        admin_required()
        name = name_parser.parse_args()["name"]
        if not TOPIC_NAME_RE.match(name):
            abort(400, error_message="Invalid topic name. Topic name can only contain A-Z, a-z, 0-9, - and _")
        topic_id = run_sns_command(sns.create_topic, Name=name)
        STATS["topic_created"] += 1
        return {"topic_id": topic_id["TopicArn"]}


class Topic(Resource):
    def get(self, topic_id):  # pylint:disable=no-self-use
        topic_id = decode_base64_id(topic_id)
        try:
            topic = run_sns_command(sns.get_topic_attributes, TopicArn=topic_id)["Attributes"]
        except NotFoundException:
            abort(404, error_message="Topic does not exist.")
        return {"topic_id": topic["TopicArn"],
                "pending_subscriptions": int(topic["SubscriptionsPending"]),
                "confirmed_subscriptions": int(topic["SubscriptionsConfirmed"]),
                "deleted_subscriptions": int(topic["SubscriptionsDeleted"]),
                "name": topic["DisplayName"]}

    def delete(self, topic_id):  # pylint:disable=no-self-use
        admin_required()
        topic_id = decode_base64_id(topic_id)
        run_sns_command(sns.delete_topic, TopicArn=topic_id)
        STATS["topic_deleted"] += 1
        return "", 204


class Subscription(Resource):
    def post(self, topic_id, target_id):  # pylint:disable=no-self-use
        topic_id = decode_base64_id(topic_id)
        endpoint_id = decode_base64_id(target_id)
        subscription = run_sns_command(sns.subscribe, TopicArn=topic_id, Protocol="application", Endpoint=endpoint_id)
        STATS["topic_subscribed"] += 1
        return {"subscription_id": subscription["SubscriptionArn"]}

    def delete(self, topic_id, target_id):  # pylint:disable=no-self-use
        topic_id = decode_base64_id(topic_id)
        subscription_id = decode_base64_id(target_id)
        run_sns_command(sns.unsubscribe, SubscriptionArn=subscription_id)
        STATS["topic_unsubscribed"] += 1
        return "", 204


def publish(data, target):
    if data is None:
        abort(400, error_message="Invalid push message body")
    encoded_sns_data = {}
    for platform, platform_data in data.items():
        encoded_sns_data[platform] = json.dumps(platform_data)
    kwargs = {
        "Message": json.dumps(encoded_sns_data),
        "TargetArn": target,
        "MessageStructure": "json",
    }
    message_data = run_sns_command(sns.publish, **kwargs)
    STATS["message_published"] += 1
    return message_data.get("MessageId")


class PublishMessage(Resource):
    def post(self, target_id):  # pylint:disable=no-self-use
        admin_required()
        data = request.get_json()
        target_id = decode_base64_id(target_id)
        message_id = publish(data, target_id)
        return {"message_id": message_id}

class PublishMessageToUser(Resource):
    def post(self, user_id):  # pylint:disable=no-self-use
        admin_required()
        data = request.get_json()
        user_id = decode_base64_id(user_id)
        message_ids = []
        for endpoint_id in retrieve_endpoint_ids_by_customer_id(user_id):
            message_ids.append(publish(data, endpoint_id))
        return {"message_ids": message_ids}

api.add_resource(Device, "/device")
api.add_resource(DeviceDetails, "/device/<endpoint_id>")
api.add_resource(Topics, "/topics")  # POST is admin-only operation.
api.add_resource(Subscription, "/subscription/topic/<topic_id>/target/<target_id>")

api.add_resource(Status, "/status")
api.add_resource(UrlList, "/", resource_class_kwargs={"api": api})

# admin endpoints

# These are separated, as some other services may need different handling for topics and endpoints.
api.add_resource(PublishMessage, "/publish/topic/<target_id>", endpoint="publish_to_topic")
api.add_resource(PublishMessage, "/publish/endpoint/<target_id>", endpoint="publish_to_endpoint")
api.add_resource(PublishMessageToUser, "/publish/user/<user_id>", endpoint="publish_to_user")

api.add_resource(Topic, "/topic/<topic_id>")


def main():  # pylint:disable=missing-docstring
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=DEBUG)

if __name__ == "__main__":
    main()
