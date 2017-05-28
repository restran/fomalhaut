#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals, absolute_import

import json
import logging
import os
import unittest

from cerberus import Validator

from fomalhaut.handlers.endpoints.base import APIStatusCode
from fomalhaut.settings import PORT as API_SERVER_PORT, GATEWAY_ERROR_STATUS_CODE
from fomalhaut.tests.api_client import APIClient, APIRequest
from fomalhaut.utils import *

logger = logging.getLogger(__name__)

IMG_FILE = os.path.join(
    os.path.abspath(os.path.dirname(__file__)), 'img.jpg')


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
        r = req.get('/')
        self.assertEqual(r.status_code, 200)
        r = req.get('')
        logger.debug(r.content)
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

        body = json.dumps(json_data, sort_keys=True)
        r = req.post('/resource/', json=json_data)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(utf8(json.dumps(r.json(), sort_keys=True)), utf8(body))

    def test_post_img(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)

        with open(IMG_FILE, 'rb') as f:
            body = f.read()
            r = req.post('/resource/', data=body)

            self.assertEqual(r.status_code, 200)
            self.assertEqual(utf8(r.content), utf8(body))


class AuthEndpointTest(unittest.TestCase):
    def setUp(self):
        self.access_key = 'abcd'
        self.secret_key = '1234'
        self.api_server = 'http://127.0.0.1:%s' % API_SERVER_PORT
        self.endpoint = 'auth'
        self.version = 'v1'

    def test_login_refresh_logout(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        req2 = APIRequest(client, 'account', 'v1')

        r = req.get('/login')
        print(r.content)
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
        self.assertEqual(v.validate(r.json()), True)

        # 测试access_token存活性
        access_token = r.json()['data']['access_token']
        refresh_token = r.json()['data']['refresh_token']
        json_data = {
            'access_token': access_token
        }
        r = req.post('/token/alive/', json=json_data)
        self.assertEqual(r.status_code, 200)
        v = Validator(schema=schema, allow_unknown=True)
        self.assertEqual(v.validate(r.json()), True)
        # 无效的 access_token
        json_data = {
            'access_token': 'test_test'
        }
        r = req.post('/token/alive/', json=json_data)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()['data']['expires_in'] < 0, True)

        # refresh_token
        json_data = {
            'refresh_token': refresh_token
        }
        logger.debug(json_data)

        r = req.post('/token/refresh/', json=json_data)
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
        self.assertEqual(v.validate(ar.json()), True)

        # 测试非法的 access_token 请求
        r = auth_req.post('/protected/', json=json_data)
        self.assertEqual(r.status_code, GATEWAY_ERROR_STATUS_CODE)
        r = auth_req.post('/protected/', json=json_data,
                          access_token='123')
        self.assertEqual(r.status_code, GATEWAY_ERROR_STATUS_CODE)
        # ---------------------
        # logout
        # 通过 headers 传递 access_token
        r = req2.post('/logout', access_token=access_token)
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

    def test_sms_login_refresh_logout(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        req2 = APIRequest(client, 'account', 'v1')

        json_data = {
            'name': 'name',
            'sms_code': '1234'
        }
        r = req.post('/login/?login_type=sms', json=json_data)
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
        logger.info(r.json())
        self.assertEqual(v.validate(r.json()), True)

        # refresh_token
        json_data = {
            'refresh_token': r.json()['data']['refresh_token']
        }
        logger.debug(json_data)

        r = req.post('/token/refresh/', json=json_data)
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
        # logger.debug(ar.content)
        logger.debug(ar.json())
        self.assertEqual(v.validate(ar.json()), True)
        # ---------------------
        # logout

        r = req2.post('/logout?access_token=%s' % access_token)
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

    def test_aes_login_refresh_logout(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version, encrypt_type='aes')
        req2 = APIRequest(client, 'account', 'v1', encrypt_type='aes')

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
        self.assertEqual(v.validate(r.json()), True)

        # refresh_token
        json_data = {
            'refresh_token': r.json()['data']['refresh_token']
        }
        logger.debug(json_data)

        r = req.post('/token/refresh/', json=json_data)
        self.assertEqual(r.status_code, 200)
        v = Validator(schema=schema, allow_unknown=True)
        logger.debug(r.json())
        self.assertEqual(v.validate(r.json()), True)

        # ---------------------
        json_data = {
            'test': 'test'
        }

        auth_req = APIRequest(client, 'test_api_login', 'v1', encrypt_type='aes')

        access_token = r.json()['data']['access_token']
        ar = auth_req.post('/protected/?access_token=%s' % access_token,
                           json=json_data)
        self.assertEqual(r.status_code, 200)
        v = Validator(schema=schema, allow_unknown=True)
        logger.debug(ar.content)
        logger.debug(ar.json())
        self.assertEqual(v.validate(ar.json()), True)
        # ---------------------
        # logout
        r = req2.post('/logout', access_token=access_token)
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

    def test_login_change_password(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        req2 = APIRequest(client, 'account', 'v1')

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
            }
        }

        access_token = r.json()['data']['access_token']
        json_data = {
            'new_password': '123',
            'old_password': '456'
        }
        r = req2.post('/password/change', json=json_data, access_token=access_token)
        self.assertEqual(r.status_code, 200)
        v = Validator(schema=schema, allow_unknown=True)
        logger.debug(r.json())
        self.assertEqual(v.validate(r.json()), True)
        # 测试非法的 access_token 请求
        req3 = APIRequest(client, 'test_api_login', 'v1')
        r = req3.post('/protected/', access_token=access_token)
        logger.debug(r.content)
        self.assertEqual(r.status_code, GATEWAY_ERROR_STATUS_CODE)

    def test_login_change_password_sms(self):
        client = APIClient(self.access_key, self.secret_key, self.api_server)
        req = APIRequest(client, self.endpoint, self.version)
        req2 = APIRequest(client, 'account', 'v1')

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
            }
        }

        access_token = r.json()['data']['access_token']
        json_data = {
            'new_password': '123',
            'old_password': '456'
        }
        r = req2.post('/password/change/?change_type=sms', json=json_data, access_token=access_token)
        self.assertEqual(r.status_code, 200)
        v = Validator(schema=schema, allow_unknown=True)
        self.assertEqual(v.validate(r.json()), True)
        # 测试非法的 access_token 请求
        r = req2.post('/protected/', json=json_data, access_token=access_token)
        self.assertEqual(r.status_code, GATEWAY_ERROR_STATUS_CODE)


def main():
    unittest.main()


if __name__ == '__main__':
    main()
