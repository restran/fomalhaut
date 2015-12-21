#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals
import random

import unittest
import urllib
import requests
from utils import *

import time
import logging
import hmac
from hashlib import sha256
import re
import settings
from handlers.base import AuthRequestException, NoClientConfigException
from utils import RedisHelper
from urlparse import urlparse, urlunparse
import json


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

    def get(self, uri, headers=None):
        url = '/'.join([self.api_server.strip(), self.endpoint.strip().strip('/'),
                        self.uri_prefix.strip().strip('/')]) + uri.strip()
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

        print r.content

    def sign_string(self, string_to_sign):
        new_hmac = hmac.new(self.secret_key.encode('utf-8'), digestmod=sha256)
        new_hmac.update(string_to_sign.encode('utf-8'))
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
        string_to_sign = '\n'.join([self.request_data.method,
                                    self.request_data.uri,
                                    canonical_headers,
                                    self.request_data.body])
        return string_to_sign

    def signature_request(self):
        string_to_sign = self.string_to_sign()
        logger.debug('string_to_sign: %s' % string_to_sign)
        hash_value = sha256(string_to_sign.encode('utf-8')).hexdigest()
        signature = self.sign_string(hash_value)
        return signature


class TestAESHelper(unittest.TestCase):
    def setUp(self):
        pass

    def test_shuffle(self):
        pass


class APITest(unittest.TestCase):
    def test_api_auth(self):
        access_key = 'abcd'
        secret_key = '1234'
        api_server = 'http://127.0.0.1:9000'
        endpoint = 'test'
        uri_prefix = 'aaa'
        r = ClientAuthRequest(access_key, secret_key, api_server, endpoint, uri_prefix)
        r.get('/justnow')


if __name__ == '__main__':
    unittest.main()
