import unittest

import base64
import boto
from moto import mock_sns, mock_dynamodb
import application

@mock_sns
@mock_dynamodb
class ApplicationTestCase(unittest.TestCase):
    def test_create_delete_device(self):
        sns_mock = mock_sns()
        sns_mock.start()
        dynamodb_mock = mock_dynamodb()
        dynamodb_mock.start()

        response = application.DeviceDetails.delete(None, base64.b64encode('endpoint-d'.encode()))

        self.assertEqual(response, ('', 204));


if __name__ == '__main__':
    unittest.main()
