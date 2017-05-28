# -*- coding: utf-8 -*-
# Created by restran on 2016/11/15
from __future__ import unicode_literals, absolute_import

import json
import logging
import os
import unittest

import requests

from fomalhaut.settings import PORT as API_SERVER_PORT
from fomalhaut.tests.api_client import APIClient, APIRequest
from fomalhaut.utils import *

logger = logging.getLogger(__name__)

IMG_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'img.jpg')


class ClientPublicAPITest(unittest.TestCase):
    def setUp(self):
        self.access_key = 'public'
        self.secret_key = ''
        self.api_server = 'http://127.0.0.1:%s' % API_SERVER_PORT
        self.endpoint = 'public'
        self.version = 'v1'

    def test_post(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version,
                         require_hmac=False, sign_response=False)

        json_data = {
            'a': 1,
            'b': 'test string',
            'c': '中文'
        }

        body = json.dumps(json_data)
        r = req.post('/resource/', json=json_data)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8(body), utf8(r.content))

    def test_post_img(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version,
                         require_hmac=False, sign_response=False)

        with open(IMG_FILE, 'rb') as f:
            body = f.read()
            r = req.post('/resource/', data=body)

            self.assertEqual(r.status_code, 200)
            self.assertEqual(utf8(r.content), utf8(body))

    def test_get(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version,
                         require_hmac=False, sign_response=False)

        r = req.get('/resource/')

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8('get'), utf8(r.content))


class RawPublicAPITest(unittest.TestCase):
    """
    不通过 API Client 来访问, 没有带 API 网关定义的特殊 Header 来访问 public API
    """

    def setUp(self):
        self.access_key = 'public'
        self.secret_key = ''
        self.api_server = 'http://127.0.0.1:%s' % API_SERVER_PORT
        self.endpoint = 'public'
        self.version = 'v1'

    def test_post(self):
        json_data = {
            'a': 1,
            'b': 'test string',
            'c': '中文'
        }

        url = '%s/%s/%s/resource/' % (self.api_server, self.endpoint, self.version)
        r = requests.post(url, json=json_data)
        self.assertEqual(r.status_code, 200)

    def test_post_img(self):
        url = '%s/%s/%s/resource/' % (self.api_server, self.endpoint, self.version)
        with open(IMG_FILE, 'rb') as f:
            body = f.read()
            r = requests.post(url, data=body)

            self.assertEqual(r.status_code, 200)
            self.assertEqual(utf8(r.content), utf8(body))

    def test_get(self):
        url = '%s/%s/%s/resource/' % (self.api_server, self.endpoint, self.version)
        r = requests.get(url)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8('get'), utf8(r.content))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
