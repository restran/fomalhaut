#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals, absolute_import

import time
import logging
import hmac
from hashlib import sha256

import settings
from handlers.base import AuthRequestException, NoClientConfigException
from utils import RedisHelper

logger = logging.getLogger(__name__)


class Client(object):
    def __init__(self, request):
        self.access_key = request.headers.get('X-Api-Access-Key')
        self.get_client_config()
        self.config = {}
        self.request = {}

    def get_client_config(self):
        redis_helper = RedisHelper()
        config_data = redis_helper.get_client_config(self.access_key)
        if config_data is None:
            raise NoClientConfigException(403, 'no client config')

        secret_key = config_data.get('secret_key')
        setattr(self, 'secret_key', secret_key)
        setattr(self, 'config', config_data)


class HMACAuthHandler(object):
    def __init__(self, client):
        self.client = client

    def sign_string(self, string_to_sign):
        new_hmac = hmac.new(self.client.secret_key.encode('utf-8'), digestmod=sha256)
        new_hmac.update(string_to_sign.encode('utf-8'))
        return new_hmac.hexdigest()

    def headers_to_sign(self, request):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        headers_to_sign = {'Host': request.headers.get('Host')}
        for name, value in request.headers.items():
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

    def string_to_sign(self, request):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        headers_to_sign = self.headers_to_sign(request)
        canonical_headers = self.canonical_headers(headers_to_sign)
        string_to_sign = '\n'.join([request.method,
                                    request.uri,
                                    canonical_headers,
                                    request.body])
        return string_to_sign

    def auth_request(self, req, **kwargs):
        timestamp = req.headers.get('X-Api-Timestamp')
        now_ts = int(time.time())
        if abs(timestamp - now_ts) > settings.SIGNATURE_EXPIRE_SECONDS:
            logger.debug('Expired signature, timestamp: %s' % timestamp)
            raise AuthRequestException(403, 'Expired Signature')

        signature = req.headers.get('X-Api-Signature')
        if signature:
            del req.headers['X-Api-Signature']
        else:
            logger.debug('No signature provide')
            raise AuthRequestException(403, 'No Signature Provide')

        string_to_sign = self.string_to_sign(req)
        logger.debug('string_to_sign: %s' % string_to_sign)
        hash_value = sha256(string_to_sign.encode('utf-8')).hexdigest()
        real_signature = self.sign_string(hash_value)
        if signature != real_signature:
            logger.debug('Signature not match: %s, %s' % (signature, real_signature))
            raise AuthRequestException(403, 'Invalid Signature')


class AuthRequestHandler(object):
    def __int__(self, handler):
        self.handler = handler

    def parse_uri(self, client):
        """
        解析请求的 uri
        :return:
        """
        try:
            _, req_endpoint, uri = self.handler.request.uri.split('/', 2)
        except ValueError:
            raise AuthRequestException(403, 'Invalid Request Uri')

        endpoints = client.config.get('endpoints')
        endpoint = endpoints.get(req_endpoint)
        if endpoint is None:
            raise AuthRequestException(403, 'No Permission to Access %s' % req_endpoint)

        uri_prefix = endpoint.get('uri_prefix')
        if uri_prefix and uri_prefix != '':
            try:
                # 处理 uri 前缀
                _, uri = uri.split(uri_prefix, 1)
            except ValueError:
                raise AuthRequestException(403, 'Invalid Request Uri Prefix')

        if not uri.startswith('/'):
            uri = '/' + uri

        return endpoint, uri

    def process_request(self):
        logger.debug('process_request')
        client = Client(self.handler.request)
        auth_handler = HMACAuthHandler(client)
        auth_handler.auth_request(self.handler.request)

        endpoint, uri = self.parse_uri(client)

        client.request = {
            'endpoint': endpoint,
            'uri': uri,
        }

        # 设置 client 的相应配置信息
        self.handler._client = client

    def process_response(self, chunk):
        logger.debug('process_response')
