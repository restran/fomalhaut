#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals, absolute_import
import time
import logging
import hmac
from hashlib import sha256, sha1
import re
import random
import traceback
# pycharm 无法识别, 会标记错误, 原因不明
from six.moves.urllib.parse import urlparse
import settings
from handlers.base import AuthRequestException, ClientBadConfigException
from utils import RedisHelper, utf8, text_type
from middleware import BaseMiddleware
from cerberus import Validator
from handlers.proxy import BackendAPIHandler

logger = logging.getLogger(__name__)

"""
处理请求的鉴权,ACL过滤
"""


class Client(object):
    # redis 中存储的 config 数据的格式
    config_schema = {
        'secret_key': {
            'type': 'string',
            'required': True
        },
        'access_key': {
            'type': 'string',
            'required': True
        },
        'name': {
            'type': 'string',
            'required': True
        },
        'id': {
            'type': 'integer',
            'required': True
        },
        'endpoints': {
            'type': 'dict',
            'required': True,
            # 字典的 key
            'propertyschema': {
                'type': 'string'
            },
            # 字典的 value
            'valueschema': {
                'type': 'dict',
                'allow_unknown': True,
                'schema': {
                    'name': {
                        'type': 'string',
                        'required': True
                    },
                    'id': {
                        'type': 'integer',
                        'required': True
                    },
                    'version': {
                        'type': 'string',
                        'required': True
                    },
                    'url': {
                        'type': 'string',
                        'required': True
                    },
                    'netloc': {
                        'type': 'string',
                        'required': True
                    },
                    'enable_acl': {
                        'type': 'boolean',
                        'required': True
                    },
                    'enable_hmac': {
                        'type': 'boolean',
                        'required': True
                    },
                    'acl_rules': {
                        'type': 'list',
                        'required': True,
                        'allow_unknown': True,
                        'items': {
                            're_uri': {
                                'type': 'string',
                                'required': True,
                            },
                            'is_permit': {
                                'type': 'boolean',
                                'required': True,
                            }
                        }
                    },
                }
            }
        },
    }

    def __init__(self, request):
        self.access_key = request.headers.get(
            'X-Api-Access-Key', settings.DEFAULT_PUBLIC_APP_ACCESS_KEY)
        self.secret_key = None
        logger.debug(self.access_key)
        self.config = {}
        self.request = {}
        self.raw_uri = request.uri
        self.get_client_config()

    def get_client_config(self):
        config_data = RedisHelper.get_client_config(self.access_key)
        if config_data is None:
            raise ClientBadConfigException('No Client Config')
        else:
            # 校验 config 数据是否正确
            v = Validator(self.config_schema, allow_unknown=True)
            if not v.validate(config_data):
                logger.error(v.errors)
                raise ClientBadConfigException('Bad Client Config')

        logger.debug(config_data)
        if not config_data.get('enable', True):
            raise AuthRequestException('Disabled Client')

        self.secret_key = config_data.get('secret_key')
        # 内置的 endpoint 由控制台配置, 不再自动添加
        # for t in settings.BUILTIN_ENDPOINTS:
        #     endpoint = t['config']
        #     k = '%s:%s' % (endpoint['name'], endpoint['version'])
        #     config_data['endpoints'][k] = endpoint

        self.config = config_data


class HMACHandler(object):
    def __init__(self, client):
        self.client = client

    def sign_string(self, string_to_sign):
        logger.debug(string_to_sign)
        new_hmac = hmac.new(utf8(self.client.secret_key), digestmod=sha256)
        new_hmac.update(utf8(string_to_sign))
        return new_hmac.digest().encode("base64").rstrip('\n')

    def _request_headers_to_sign(self, request):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        headers_to_sign = {'Host': request.headers.get('Host')}
        for name, value in request.headers.items():
            l_name = name.lower()
            # 计算签名的时候, 不能包含 x-api-signature
            if l_name.startswith('x-api-') and l_name != 'x-api-signature':
                headers_to_sign[name] = value
        return headers_to_sign

    def _response_headers_to_sign(self, response_headers):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        headers_to_sign = {}
        for name, value in response_headers.items():
            l_name = name.lower()
            # 计算签名的时候, 不能包含 x-api-signature
            if l_name.startswith('x-api-') and l_name != 'x-api-signature':
                headers_to_sign[name] = value
            logger.debug(headers_to_sign)
        return headers_to_sign

    def _canonical_headers(self, headers_to_sign):
        """
        Return the headers that need to be included in the StringToSign
        in their canonical form by converting all header keys to lower
        case, sorting them in alphabetical order and then joining
        them into a string, separated by newlines.
        """
        l = sorted(['%s: %s' % (n.lower().strip(),
                                headers_to_sign[n].strip()) for n in headers_to_sign])
        return '\n'.join(l)

    def _request_string_to_sign(self, request):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        headers_to_sign = self._request_headers_to_sign(request)
        canonical_headers = self._canonical_headers(headers_to_sign)
        string_to_sign = b'\n'.join([utf8(request.method.upper()),
                                     utf8(request.uri),
                                     utf8(canonical_headers),
                                     utf8(request.body)])
        return string_to_sign

    def _response_string_to_sign(self, response_headers, request, response_body):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        headers_to_sign = self._response_headers_to_sign(response_headers)
        canonical_headers = self._canonical_headers(headers_to_sign)
        string_to_sign = b'\n'.join([utf8(request.method.upper()),
                                     utf8(self.client.raw_uri),
                                     utf8(canonical_headers),
                                     utf8(response_body)])
        return string_to_sign

    def signature_response(self, response_header, request, response_body):
        string_to_sign = self._response_string_to_sign(
            response_header, request, response_body)
        # logger.debug(string_to_sign.decode('utf-8'))
        # 如果不是 unicode 输出会引发异常
        # logger.debug('string_to_sign: %s' % string_to_sign.decode('utf-8'))
        # 先用 sha1 计算出需要被签名的字符串的 hash 值, 然后再用 sha256 进行 HMAC
        hash_value = sha1(utf8(string_to_sign)).hexdigest()
        signature = self.sign_string(hash_value)
        return signature

    def auth_request(self, request):
        try:
            timestamp = int(request.headers.get('X-Api-Timestamp'))
        except ValueError:
            raise AuthRequestException('Invalid X-Api-Timestamp Header')

        now_ts = int(time.time())
        if abs(timestamp - now_ts) > settings.SIGNATURE_EXPIRE_SECONDS:
            logger.debug('Expired signature, timestamp: %s' % timestamp)
            raise AuthRequestException('Expired Signature')

        signature = request.headers.get('X-Api-Signature')
        if not signature:
            logger.debug('No Signature Provided')
            raise AuthRequestException('No Signature Provided')

        string_to_sign = self._request_string_to_sign(request)
        # 如果不是 unicode 输出会引发异常
        # logger.debug('string_to_sign: %s' % string_to_sign.decode('utf-8'))
        hash_value = sha1(utf8(string_to_sign)).hexdigest()
        real_signature = self.sign_string(hash_value)
        if signature != real_signature:
            logger.debug('Signature not match: %s, %s' % (signature, real_signature))
            raise AuthRequestException('Invalid Signature')


class PrepareAuthHandler(BaseMiddleware):
    """
    获取 client 和 endpoint
    """

    def process_request(self, *args, **kwargs):
        logger.debug('process_request')
        self.handler.client = Client(self.handler.request)

        # 解析 uri, 获取该请求对应的 endpoint
        try:
            _, req_endpoint, version, uri = self.handler.request.uri.split('/', 3)
        except ValueError:
            raise AuthRequestException('Invalid Request Uri, Fail to Get Endpoint and Version')

        endpoints = self.handler.client.config.get('endpoints', {})
        endpoint = endpoints.get('%s:%s' % (req_endpoint, version))
        if endpoint is None:
            raise AuthRequestException('No Permission to Access %s/%s' % (req_endpoint, version))

        if not endpoint.get('enable', True):
            raise AuthRequestException('Disabled Endpoint')

        self.handler.client.request = {
            'endpoint': endpoint,
        }


class HMACAuthenticateHandler(BaseMiddleware):
    def process_request(self, *args, **kwargs):
        """
        对访问请求进行HMAC签名校验
        """
        logger.debug('process_request')
        # self.handler.client = Client(self.handler.request)
        endpoint = self.handler.client.request['endpoint']
        # 判断是否需要进行 HMAC 签名校验
        if endpoint.get('enable_hmac', True):
            auth_handler = HMACHandler(self.handler.client)
            auth_handler.auth_request(self.handler.request)

    def process_response(self, *args, **kwargs):
        """
        对响应结果进行HMAC签名校验
        """
        logger.debug('process_response')
        # 判断是否需要对返回的数据进行 HMAC 签名校验
        require_res_sign = self.handler.request.headers.get('X-Api-Require-Response-Signature')

        if require_res_sign is None:
            return

        auth_handler = HMACHandler(self.handler.client)
        headers = {
            'X-Api-Timestamp': text_type(int(time.time())),
            'X-Api-Nonce': text_type(random.random()),
        }
        for k, v in headers.items():
            self.handler.set_header(k, v)

        response_body = b''.join(self.handler.get_write_buffer())
        response_headers = self.handler.get_response_headers()
        # logger.debug(response_body.decode('utf-8'))
        # logger.debug(dict(self.handler.get_response_headers()))
        signature = auth_handler.signature_response(
            response_headers,
            self.handler.request, response_body)

        # 对返回结果进行签名
        self.handler.set_header('X-Api-Signature', signature)

        self.handler.response['headers'] = response_headers
        self.handler.response['body'] = response_body
        logger.debug('process_response_done')


class ParseEndpointHandler(BaseMiddleware):
    """
    解析出需要访问的 Forward Url
    """

    def _parse_uri(self, client):
        """
        解析请求的 uri
        :type client: Client
        :return:
        """
        try:
            _, req_endpoint, version, uri = self.handler.request.uri.split('/', 3)
        except ValueError:
            raise AuthRequestException('Invalid Request Uri, Fail to Get Endpoint and Version')

        endpoint = self.handler.client.request['endpoint']

        if not uri.startswith('/'):
            uri = '/' + uri

        if endpoint.get('is_builtin', False):
            # 如果是内置的 endpoint, 就没有 forward_url
            forward_url = None

            # 寻找匹配的内置 Endpoint Handler
            key = '%s/%s' % (endpoint['name'], endpoint['version'])
            builtin_handlers = self.handler.builtin_endpoints.get(key, [])
            self.handler.real_api_handler = None
            for t in builtin_handlers:
                re_uri, _handler = t
                pattern = re.compile(re_uri)
                match = pattern.search(uri)
                if match:
                    self.handler.real_api_handler = _handler
                    break
        else:
            # 后端的 API, 需要代理访问
            self.handler.real_api_handler = BackendAPIHandler
            # 解析要转发的地址
            endpoint_url = endpoint.get('url')
            if endpoint_url is None:
                raise AuthRequestException('No Endpoint Url Config')

            endpoint_netloc = endpoint.get('netloc')
            if endpoint_netloc is None:
                url_parsed = urlparse(endpoint_url)
                endpoint['netloc'] = url_parsed.netloc

            if endpoint_url.endswith('/'):
                forward_url = endpoint_url + uri[1:]
            else:
                forward_url = endpoint_url + uri

        self.handler.client.request['uri'] = uri
        self.handler.client.request['forward_url'] = forward_url

    def _acl_filter(self):
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
                raise AuthRequestException('Forbidden Uri')

    def process_request(self, *args, **kwargs):
        logger.debug('process_request')
        # 解析 uri, 获取该请求实际要转发的地址
        self._parse_uri(self.handler.client)
        # 进行 acl 过滤
        self._acl_filter()
