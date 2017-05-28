# -*- coding: utf-8 -*-
# Created by restran on 2016/11/15
from __future__ import unicode_literals, absolute_import

import json
import logging
import os
import unittest

from fomalhaut.settings import PORT as API_SERVER_PORT
from fomalhaut.tests.api_client import APIClient, APIRequest
from fomalhaut.utils import *

logger = logging.getLogger(__name__)

IMG_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'img.jpg')


class AESTest(unittest.TestCase):
    def setUp(self):
        self.access_key = 'abcd'
        self.secret_key = '1234'
        self.api_server = 'http://127.0.0.1:%s' % API_SERVER_PORT
        self.endpoint = 'test_api'
        self.version = 'v1'

    def test_aes_post(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version, encrypt_type='aes')

        json_data = {
            'a': 1,
            'b': 'test string',
            'c': '中文'
        }

        body = json.dumps(json_data)
        r = req.post('/resource/', json=json_data)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8(body), utf8(r.content))

    def test_aes_post_img(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version, encrypt_type='aes')

        with open(IMG_FILE, 'rb') as f:
            body = f.read()
            r = req.post('/resource/', data=body)

            self.assertEqual(r.status_code, 200)
            self.assertEqual(utf8(r.content), utf8(body))

    def test_aes_get(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version, encrypt_type='aes')

        r = req.get('/resource/')

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8('get'), utf8(r.content))

    def test_aes_no_uri(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version, encrypt_type='aes')
        r = req.get('/')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8('get'), utf8(r.content))

        r = req.get('')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8('get'), utf8(r.content))


def main():
    unittest.main()


if __name__ == '__main__':
    main()
