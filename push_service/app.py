

# pylint:disable=line-too-long
import base64
import logging
import os
import re

import boto3
import botocore.exceptions

from flask import Flask, request
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
    config = {}
    for variable_name, variable_value in environment.items():
        plain_platform_match = PLATFORM_RE.match(variable_name)
        if plain_platform_match:
            config[plain_platform_match.group("platform_identifier").lower()] = {
                "platform_type": "application",
                "platform_application": variable_value
            }
    return config


def get_auth_token():
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
AWS_SECRET_KEY = os.environ["AWS_SECRET_KEY"]
AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY"]
AWS_REGION = os.environ["AWS_REGION"]
AUTOSUBSCRIBE_TOPICS = [topic for topic in os.environ.get("AUTOSUBSCRIBE_TOPICS", "").split(",") if len(topic)]
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
    if request.headers.get("Auth-Token") == AUTH_TOKEN:
        return
    abort(401, error_message="Incorrect or missing Auth-Token header")


app = Flask("push-service")  # pylint:disable=invalid-name
api = Api(app)  # pylint:disable=invalid-name
app.before_request(check_authorization)

sns = boto3.client("sns", region_name=AWS_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)  # pylint:disable=invalid-name

register_device_parser = reqparse.RequestParser()  # pylint:disable=invalid-name
register_device_parser.add_argument("endpoint_arn", required=False, type=str)
register_device_parser.add_argument("platform", required=True, type=str)
register_device_parser.add_argument("notification_token", required=True, type=str)

paging_parser = reqparse.RequestParser()  # pylint:disable=invalid-name
paging_parser.add_argument("page", required=False, type=str)


class NotFoundException(Exception):
    pass


class Status(Resource):  # pylint:disable=missing-docstring
    def get(self):  # pylint:disable=no-self-use,missing-docstring
        return "OK"


def run_sns_command(command, *args, **kwargs):
    """ Run SNS command, and check for common errors """
    try:
        response = command(*args, **kwargs)
    except botocore.exceptions.ClientError as err:
        logger.warning("SNS command %s (args: %s, kwargs: %s) failed with %s", command, args, kwargs, err)
        client_error = str(err)
        if "NotFound" in client_error:
            raise NotFoundException
        for error_re, error_code, error_message in BOTO_ERRORS:
            if error_re.match(client_error):
                abort(error_code, error_message=error_message)
        raise err
    return response


def subscribe_to_topics(endpoint_arn, endpoint_type):
    """ Subscribe to all autosubscribe topics """
    if len(AUTOSUBSCRIBE_TOPICS) > 0:
        for topic in AUTOSUBSCRIBE_TOPICS:
            run_sns_command(sns.subscribe, TopicArn=topic, Protocol=endpoint_type, Endpoint=endpoint_arn)


def register_endpoint(platform_arn, notification_token):
    """ Create a new endpoint to SNS """
    logger.info("Registering %s to %s", notification_token, platform_arn)
    registration_response = run_sns_command(sns.create_platform_endpoint, PlatformApplicationArn=platform_arn,
                                            Token=notification_token)
    return registration_response["EndpointArn"]


def update_endpoint(endpoint_arn, notification_token):
    """ Update endpoint details (enable the endpoint, update the token) """
    return run_sns_command(sns.set_endpoint_attributes, EndpointArn=endpoint_arn,
                           Attributes={"Enabled": "true", "Token": notification_token})


class Device(Resource):  # pylint:disable=missing-docstring
    def post(self):  # pylint:disable=no-self-use
        """ Register a new endpoint.

            {
              "platform": "ios",
              "endpoint_arn": "optional, must be added if this device has been registered earlier",
              "notification_token": "token from apns/gcm/..."
            }
        """
        args = register_device_parser.parse_args()
        platform = args["platform"].lower().replace("-", "_")
        if platform not in CONFIG:
            logger.warning("Client provided unknown platform: %s", platform)
            abort(400, error_message="Unknown platform")
        platform_arn = CONFIG[platform]["platform_application"]
        if not platform_arn or len(platform_arn) == 0:
            logger.warning("Client provided unconfigured platform: %s (config: %s)", platform, CONFIG)
            abort(400, error_message="Unconfigured platform")

        endpoint_exists = False
        if "endpoint_arn" in args and args["endpoint_arn"]:
            # Device should already exist in SNS - try updating the metadata
            endpoint_arn = args["endpoint_arn"]
            try:
                update_endpoint(endpoint_arn, args["notification_token"])
                endpoint_exists = True
            except NotFoundException:
                logger.warning("Tried to update non-existing endpoint: %s", endpoint_arn)

        if not endpoint_exists:
            endpoint_arn = register_endpoint(platform_arn, args["notification_token"])

        subscribe_to_topics(endpoint_arn, CONFIG[platform]["platform_type"])
        return {"endpoint_arn": endpoint_arn}


class DeviceDetails(Resource):  # pylint:disable=missing-docstring
    def delete(self, endpoint_arn):  # pylint:disable=no-self-use
        """ Delete the endpoint. Automatically removes all the subscriptions as well. """
        endpoint_arn = base64.b64decode(endpoint_arn).decode()
        sns.delete_endpoint(EndpointArn=endpoint_arn)
        return "", 204

    def get(self, endpoint_arn):  # pylint:disable=no-self-use
        """ Get endpoint details (enabled, token, endpoint ARN) """
        endpoint_arn = base64.b64decode(endpoint_arn).decode()
        try:
            details = run_sns_command(sns.get_endpoint_attributes, EndpointArn=endpoint_arn)
        except NotFoundException:
            abort(404, error_message="Endpoint does not exist")
        attributes = details["Attributes"]
        return {"endpoint_arn": endpoint_arn, "enabled": attributes["Enabled"] in (True, "True", "true"), "notification_token": attributes["Token"]}


class Topics(Resource):
    def get(self):
        paging = paging_parser.parse_args()
        kwargs = {}
        if "page" in paging and paging["page"]:
            kwargs["NextToken"] = paging["page"]
        topics = run_sns_command(sns.list_topics, **kwargs)
        ret = {"next_page": topics.get("NextToken"),
               "topics": [topic["TopicArn"] for topic in topics.get("Topics", [])]}
        return ret


api.add_resource(Device, "/device")
api.add_resource(DeviceDetails, "/device/<endpoint_arn>")
api.add_resource(Status, "/status")
api.add_resource(UrlList, "/", resource_class_kwargs={"api": api})
api.add_resource(Topics, "/topics")


def main():  # pylint:disable=missing-docstring
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=DEBUG)

if __name__ == "__main__":
    main()
