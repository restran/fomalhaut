#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals
import random
import unittest
import time
import hmac
from hashlib import sha256
from urlparse import urlparse, urlunparse

import requests

from utils import *


class RequestObject(object):
    """
    请求的数据对象的封装
    """

    def __init__(self, method=None, uri=None, headers=None, body=None, host=None):
        self.method = method
        self.uri = uri
        self.headers = headers
        self.body = body
        self.host = host


class ClientAuthRequest(object):
    def __init__(self, access_key, secret_key, api_server,
                 endpoint, uri_prefix='', encrypt_type='raw'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.api_server = api_server
        self.endpoint = endpoint
        self.uri_prefix = uri_prefix
        self.encrypt_type = encrypt_type
        self.request_data = RequestObject()

    @staticmethod
    def parse_uri(url):
        url_parsed = urlparse(url)
        uri = urlunparse(('', '', url_parsed.path, url_parsed.params,
                          url_parsed.query, url_parsed.fragment))

        return uri

    def get_auth_headers(self):
        headers = {
            'X-Api-Timestamp': text_type(int(time.time())),
            'X-Api-Nonce': text_type(random.random()),
            'X-Api-Access-Key': text_type(self.access_key),
            'X-Api-Encrypt-Type': text_type(self.encrypt_type)
        }

        return headers

    def get_real_url(self, uri):
        url = '/'.join([self.api_server.strip(), self.endpoint.strip().strip('/'),
                        self.uri_prefix.strip().strip('/')]) + uri.strip()
        return url

    def get(self, uri, headers=None):
        url = self.get_real_url(uri)
        logger.debug(url)
        self.request_data.host = urlparse(url).netloc
        self.request_data.uri = self.parse_uri(url)
        self.request_data.method = 'GET'
        if headers is None:
            headers = self.get_auth_headers()
        else:
            headers.update(self.get_auth_headers())

        # headers 是字典
        self.request_data.headers = headers
        self.request_data.body = ''

        signature = self.signature_request()
        self.request_data.headers['X-Api-Signature'] = signature
        self.request_data.headers['Accept'] = 'application/json; charset=utf-8'
        r = requests.get(url, headers=self.request_data.headers)

        return r

    def post(self, uri, headers=None, body=None):
        url = self.get_real_url(uri)
        logger.debug(url)
        self.request_data.host = urlparse(url).netloc
        self.request_data.uri = self.parse_uri(url)
        self.request_data.method = 'POST'
        if headers is None:
            headers = self.get_auth_headers()
        else:
            headers.update(self.get_auth_headers())

        # headers 是字典
        self.request_data.headers = headers
        self.request_data.body = body

        signature = self.signature_request()
        self.request_data.headers['X-Api-Signature'] = signature
        self.request_data.headers['Accept'] = 'application/json; charset=utf-8'
        r = requests.post(url, headers=self.request_data.headers, data=get_utf8_value(body))

        return r

    def sign_string(self, string_to_sign):
        new_hmac = hmac.new(get_utf8_value(self.secret_key), digestmod=sha256)
        new_hmac.update(get_utf8_value(string_to_sign))
        return new_hmac.hexdigest()

    def headers_to_sign(self):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        headers_to_sign = {'Host': self.request_data.host}
        for name, value in self.request_data.headers.items():
            l_name = name.lower()
            if l_name.startswith('x-api'):
                headers_to_sign[name] = value
        return headers_to_sign

    def canonical_headers(self, headers_to_sign):
        """
        Return the headers that need to be included in the StringToSign
        in their canonical form by converting all header keys to lower
        case, sorting them in alphabetical order and then joining
        them into a string, separated by newlines.
        """
        l = sorted(['%s: %s' % (n.lower().strip(),
                                headers_to_sign[n].strip()) for n in headers_to_sign])
        return '\n'.join(l)

    def string_to_sign(self):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        headers_to_sign = self.headers_to_sign()
        canonical_headers = self.canonical_headers(headers_to_sign)
        string_to_sign = b'\n'.join([get_utf8_value(self.request_data.method.upper()),
                                     get_utf8_value(self.request_data.uri),
                                     get_utf8_value(canonical_headers),
                                     get_utf8_value(self.request_data.body)])
        return string_to_sign

    def signature_request(self):
        string_to_sign = self.string_to_sign()
        # 如果不是 unicode 输出会引发异常
        # logger.debug('string_to_sign: %s' % string_to_sign.decode('utf-8'))
        hash_value = sha256(get_utf8_value(string_to_sign)).hexdigest()
        signature = self.sign_string(hash_value)
        return signature


class APIAuthTest(unittest.TestCase):
    """
    redis 中需要先设置 client 的配置信息
    key: config:abcd
    value:
    {
        "secret_key": "1234",
        "access_key": "abcd",
        "name": "test_client",
        "id": 123,
        "enable": true,
        "endpoints": {
            "test": {
                "name": "test",
                "id": 101,
                "enable": true,
                "enable_acl": true,
                "uri_prefix": "aaa",
                "url": "http://127.0.0.1:8000",
                "netloc": "127.0.0.1:8000",
                "acl_rules": [
                    {
                        "re_uri": "^/forbidden.*",
                        "is_permit": false
                    },
                    {
                        "re_uri": "^/resource",
                        "is_permit": true
                    }
                ]
            }
        }
    }
    """

    def setUp(self):
        self.access_key = 'abcd'
        self.secret_key = '1234'
        self.api_server = 'http://127.0.0.1:9000'
        self.endpoint = 'test'
        self.uri_prefix = 'aaa'

    def test_auth(self):
        req = ClientAuthRequest(self.access_key, self.secret_key,
                                self.api_server, self.endpoint, self.uri_prefix)
        r = req.get('/resource')
        self.assertEqual(r.status_code, 200)
        r = req.get('/resource/not_exist')
        self.assertEqual(r.status_code, 404)

    def test_signature(self):
        req = ClientAuthRequest(self.access_key, 'bad secret key',
                                self.api_server, self.endpoint, self.uri_prefix)
        r = req.get('/resource/')
        self.assertEqual(r.status_code, 403)

        req = ClientAuthRequest('bad access key', 'bad secret key',
                                self.api_server, self.endpoint, self.uri_prefix)
        r = req.get('/resource/')
        self.assertEqual(r.status_code, 403)

    def test_acl(self):
        req = ClientAuthRequest(self.access_key, self.secret_key,
                                self.api_server, self.endpoint, self.uri_prefix)
        r = req.get('/resource')
        self.assertEqual(r.status_code, 200)

        req = ClientAuthRequest(self.access_key, self.secret_key,
                                self.api_server, self.endpoint, self.uri_prefix)
        r = req.get('/forbidden/')
        self.assertEqual(r.status_code, 403)

    def test_post_json(self):
        req = ClientAuthRequest(self.access_key, self.secret_key,
                                self.api_server, self.endpoint, self.uri_prefix)
        json_data = {
            'a': 1,
            'b': 'test string',
            'c': '中文'
        }

        body = json.dumps(json_data, ensure_ascii=False)
        r = req.post('/resource/', body=body)

        self.assertEqual(r.status_code, 200)
        self.assertEqual(get_utf8_value(r.content), get_utf8_value(body))

    def test_post_img(self):
        req = ClientAuthRequest(self.access_key, self.secret_key,
                                self.api_server, self.endpoint, self.uri_prefix)

        with open('img.jpg', 'rb') as f:
            body = f.read()
            r = req.post('/resource/', body=body)

            self.assertEqual(r.status_code, 200)
            self.assertEqual(get_utf8_value(r.content), get_utf8_value(body))


if __name__ == '__main__':
    unittest.main()
