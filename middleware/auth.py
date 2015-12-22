#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals, absolute_import

import time
import logging
import hmac
from hashlib import sha256
import re
import settings
from handlers.base import AuthRequestException, ClientBadConfigException
from utils import RedisHelper, get_utf8_value, text_type
from urlparse import urlparse, urlunparse
from middleware import BaseMiddleware

logger = logging.getLogger(__name__)


class Client(object):
    def __init__(self, request):
        self.access_key = request.headers.get('X-Api-Access-Key')
        self.secret_key = None
        logger.debug(self.access_key)
        self.config = {}
        self.request = {}
        self.get_client_config()

    def get_client_config(self):
        config_data = RedisHelper.get_client_config(self.access_key)
        if config_data is None:
            raise ClientBadConfigException(403, 'no client config')

        logger.debug(config_data)

        self.secret_key = config_data.get('secret_key')
        self.config = config_data


class HMACAuthHandler(object):
    def __init__(self, client):
        self.client = client

    def sign_string(self, string_to_sign):
        new_hmac = hmac.new(get_utf8_value(self.client.secret_key), digestmod=sha256)
        new_hmac.update(get_utf8_value(string_to_sign))
        return new_hmac.hexdigest()

    def headers_to_sign(self, request):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        headers_to_sign = {'Host': request.headers.get('Host')}
        for name, value in request.headers.items():
            if name.lower().startswith('x-api'):
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
        string_to_sign = b'\n'.join([get_utf8_value(request.method.upper()),
                                     get_utf8_value(request.uri),
                                     get_utf8_value(canonical_headers),
                                     get_utf8_value(request.body)])
        return string_to_sign

    def auth_request(self, req, **kwargs):
        try:
            timestamp = int(req.headers.get('X-Api-Timestamp'))
        except ValueError:
            raise AuthRequestException(403, 'Invalid X-Api-Timestamp Header')

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
        # 如果不是 unicode 输出会引发异常
        # logger.debug('string_to_sign: %s' % string_to_sign.decode('utf-8'))
        hash_value = sha256(get_utf8_value(string_to_sign)).hexdigest()
        real_signature = self.sign_string(hash_value)
        if signature != real_signature:
            logger.debug('Signature not match: %s, %s' % (signature, real_signature))
            raise AuthRequestException(403, 'Invalid Signature')


class AuthRequestHandler(BaseMiddleware):
    """
    对访问请求进行鉴权
    """

    def parse_uri(self, client):
        """
        解析请求的 uri
        :return:
        """
        try:
            _, req_endpoint, uri = self.handler.request.uri.split('/', 2)
        except ValueError:
            raise AuthRequestException(403, 'Invalid Request Uri')

        endpoints = client.config.get('endpoints', {})
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

        # 解析要转发的地址
        endpoint_url = endpoint.get('url')
        if endpoint_url is None:
            raise AuthRequestException(403, 'No Endpoint Url Config')

        endpoint_netloc = endpoint.get('netloc')
        if endpoint_netloc is None:
            url_parsed = urlparse(endpoint_url)
            endpoint['netloc'] = url_parsed.netloc

        if endpoint_url.endswith('/'):
            forward_url = endpoint_url + uri[1:]
        else:
            forward_url = endpoint_url + uri

        request_data = {
            'endpoint': endpoint,
            'uri': uri,
            'forward_url': forward_url,
        }

        logger.debug(request_data)

        return request_data

    def acl_filter(self):
        """
        如果启用访问控制列表，就需要检查URI是否允许访问
        :return:
        """
        client = self.handler.client
        uri = client.request['uri']

        endpoint = client.request['endpoint']
        enable_acl = endpoint.get('enable_acl', False)
        if enable_acl:
            acl_rules = endpoint.get('acl_rules', [])
            # 如果都没有找到匹配的规则，默认返回Tue，放行
            allow_access = True
            for r in acl_rules:
                re_uri, is_permit = r['re_uri'], r['is_permit']
                pattern = re.compile(re_uri)
                match = pattern.search(uri)
                if match:
                    allow_access = is_permit
                    break

            # 禁止访问该 uri
            if not allow_access:
                logger.info('forbidden uri %s' % uri)
                raise AuthRequestException(403, 'Forbidden Uri')

    def process_request(self):
        logger.debug('process_request')
        client = Client(self.handler.request)
        auth_handler = HMACAuthHandler(client)
        auth_handler.auth_request(self.handler.request)
        # 解析 uri,获取该请求实际要转发的地址
        client.request = self.parse_uri(client)
        # 设置 client 的相应配置信息
        self.handler.client = client

        # 进行 acl 过滤
        self.acl_filter()
