# -*- coding: utf-8 -*-
# Created by restran on 2016/11/15
from __future__ import unicode_literals, absolute_import

import logging
import os
import unittest

from fomalhaut.settings import PORT as API_SERVER_PORT
from fomalhaut.tests.api_client import APIClient, APIRequest
from fomalhaut.utils import utf8

logger = logging.getLogger(__name__)

IMG_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'img.jpg')


class MethodTest(unittest.TestCase):
    def setUp(self):
        self.access_key = 'abcd'
        self.secret_key = '1234'
        self.api_server = 'http://127.0.0.1:%s' % API_SERVER_PORT
        self.endpoint = 'test_api'
        self.version = 'v1'

    def test_head(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.head('/resource')
        logger.debug(r.content)
        self.assertEqual(r.status_code, 200)

    def test_options(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.options('/resource')
        logger.debug(r.headers)
        logger.debug(r.content)
        self.assertEqual(r.status_code, 200)

    def test_put(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.put('/resource')
        logger.debug(r.content)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, utf8('put'))

    def test_delete(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.delete('/resource')
        logger.debug(r.content)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, utf8('delete'))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
