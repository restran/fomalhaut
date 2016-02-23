#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals
import unittest
from settings import PORT as API_SERVER_PORT, GATEWAY_ERROR_STATUS_CODE
from handlers.endpoint import APIStatusCode
from cerberus import Validator
from utils import *
from tests.api_client import APIClient, APIRequest


class APIAuthTest(unittest.TestCase):
    def setUp(self):
        self.access_key = 'abcd'
        self.secret_key = '1234'
        self.api_server = 'http://127.0.0.1:%s' % API_SERVER_PORT
        self.endpoint = 'test_api'
        self.version = 'v1'

    def test_auth(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.get('/resource')
        self.assertEqual(r.status_code, 200)
        r = req.get('/resource/not_exist')
        self.assertEqual(r.status_code, 404)

    def test_signature(self):
        client = APIClient(self.access_key, 'bad secret key', self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.get('/resource/')
        self.assertEqual(r.status_code, GATEWAY_ERROR_STATUS_CODE)

        client = APIClient(self.access_key, 'bad secret key', self.api_server)
        req = APIRequest(client, self.endpoint, self.version)

        r = req.get('/resource/')
        self.assertEqual(r.status_code, GATEWAY_ERROR_STATUS_CODE)

    def test_acl(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.get('/resource')
        self.assertEqual(r.status_code, 200)

        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        r = req.get('/forbidden/')
        self.assertEqual(r.status_code, GATEWAY_ERROR_STATUS_CODE)

    def test_post_json(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        json_data = {
            'a': 1,
            'b': 'test string',
            'c': '中文'
        }

        body = json.dumps(json_data, ensure_ascii=False)
        r = req.post('/resource/', json=json_data)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8(r.content), utf8(body))

    def test_post_img(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)

        with open('img.jpg', 'rb') as f:
            body = f.read()
            r = req.post('/resource/', data=body)

            self.assertEqual(r.status_code, 200)
            self.assertEqual(utf8(r.content), utf8(body))


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

        body = json.dumps(json_data, ensure_ascii=False)
        r = req.post('/resource/', json=json_data)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8(body), utf8(r.content))

    def test_aes_post_img(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version, encrypt_type='aes')

        with open('img.jpg', 'rb') as f:
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


class AuthEndpointTest(unittest.TestCase):
    def setUp(self):
        self.access_key = 'abcd'
        self.secret_key = '1234'
        self.api_server = 'http://127.0.0.1:%s' % API_SERVER_PORT
        self.endpoint = 'auth'
        self.version = '1'

    def test_login_refresh_logout(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)

        r = req.get('/login')
        self.assertEqual(r.status_code, 405)
        json_data = {
            'name': 'name',
            'password': 'password'
        }
        r = req.post('/login', json=json_data)
        self.assertEqual(r.status_code, 200)
        schema = {
            'code': {
                'type': 'integer',
                'required': True,
                'allowed': [APIStatusCode.SUCCESS]
            },
            'msg': {
                'type': 'string',
                'required': True,
            },
            'data': {
                'type': 'dict',
                'required': True,
            }
        }
        v = Validator(schema=schema, allow_unknown=True)
        logger.debug(r.json())
        logger.debug(v.validate(r.json()))
        self.assertEqual(v.validate(r.json()), True)

        # refresh_token
        json_data = {
            'refresh_token': r.json()['data']['refresh_token']
        }
        logger.debug(json_data)
        r = req.post('/token', json=json_data)
        self.assertEqual(r.status_code, 200)
        v = Validator(schema=schema, allow_unknown=True)
        logger.debug(r.json())
        self.assertEqual(v.validate(r.json()), True)

        # ---------------------
        json_data = {
            'test': 'test'
        }

        auth_req = APIRequest(client, 'test_api_login', 'v1')

        access_token = r.json()['data']['access_token']
        ar = auth_req.post('/protected/?access_token=%s' % access_token,
                           json=json_data)
        self.assertEqual(r.status_code, 200)
        v = Validator(schema=schema, allow_unknown=True)
        logger.debug(ar.json())
        self.assertEqual(v.validate(ar.json()), True)
        # ---------------------
        # logout
        json_data = {
            'access_token': r.json()['data']['access_token']
        }
        r = req.post('/logout', json=json_data)
        self.assertEqual(r.status_code, 200)
        schema = {
            'code': {
                'type': 'integer',
                'required': True,
                'allowed': [APIStatusCode.SUCCESS]
            },
            'msg': {
                'type': 'string',
                'required': True,
            }
        }
        v = Validator(schema=schema, allow_unknown=True)
        self.assertEqual(v.validate(r.json()), True)


if __name__ == '__main__':
    unittest.main()
