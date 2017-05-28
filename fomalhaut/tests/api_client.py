# -*- coding: utf-8 -*-
# created by restran on 2016/02/22

from __future__ import unicode_literals, absolute_import

import hmac
import json as json_util
import logging
import random
import time
import traceback
from base64 import urlsafe_b64encode
from hashlib import sha1

import requests
from future.moves.urllib.parse import urlparse, urlunparse, urlencode
from future.utils import iteritems

from fomalhaut.settings import SIGNATURE_EXPIRE_SECONDS, \
    GATEWAY_ERROR_STATUS_CODE, HEADER_X_SIGNATURE, \
    HEADER_X_TIMESTAMP, HEADER_X_APP_ID, HEADER_X_ENCRYPT_TYPE, \
    HEADER_X_NONCE, HEADER_X_SIGN_RESPONSE, HEADER_X_ACCESS_TOKEN, \
    HEADER_X_ENCRYPTED_HEADERS, HEADER_X_ENCRYPTED_URI, HEADER_X_PREFIX
from fomalhaut.utils import utf8, utf8_encoded_dict, text_type, \
    AESCipher, unicode_encoded_dict, to_unicode

logger = logging.getLogger(__name__)


class RequestObject(object):
    """
    请求的数据对象的封装
    """

    def __init__(self, method=None, uri=None, headers=None, body=None):
        self.method = method
        self.uri = uri
        self.headers = headers
        self.body = body


class APIClient(object):
    def __init__(self, access_key, secret_key, api_server, *args, **kwargs):
        self.access_key = access_key
        self.secret_key = secret_key
        self.api_server = api_server

        self.gateway_error_status_code = kwargs.get(
            'gateway_error_status_code', GATEWAY_ERROR_STATUS_CODE)
        self.signature_expire_seconds = kwargs.get(
            'signature_expire_seconds', SIGNATURE_EXPIRE_SECONDS)


class HMACHandler(object):
    def __init__(self, client, algorithm=sha1):
        self.client = client
        self.algorithm = algorithm

    def sign_string(self, string_to_sign):
        logger.debug(string_to_sign)
        new_hmac = hmac.new(
            utf8(self.client.secret_key), utf8(string_to_sign),
            digestmod=self.algorithm)
        return to_unicode(urlsafe_b64encode(new_hmac.digest()).rstrip(b'='))

    def string_to_sign(self, request):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        headers_to_sign = self.headers_to_sign(request.headers)
        canonical_headers = self.canonical_headers(headers_to_sign)
        string_to_sign = b'\n'.join([utf8(request.method.upper()),
                                     utf8(request.uri),
                                     utf8(canonical_headers),
                                     utf8(request.body)])
        return string_to_sign

    def response_headers_to_sign(self, headers):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        headers_to_sign = {}
        for name, value in iteritems(headers):
            # l_name = name.lower()
            if name.startswith(HEADER_X_PREFIX):
                headers_to_sign[name] = value
        return headers_to_sign

    def response_string_to_sign(self, request, response):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        headers_to_sign = self.response_headers_to_sign(response.headers)
        canonical_headers = self.canonical_headers(headers_to_sign)
        string_to_sign = b'\n'.join([utf8(request.method.upper()),
                                     utf8(request.uri),
                                     utf8(canonical_headers),
                                     utf8(response.content)])
        return string_to_sign

    def headers_to_sign(self, headers):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        new_headers = {name: value for name, value in iteritems(headers)
                       if name.startswith(HEADER_X_PREFIX) and name != HEADER_X_SIGNATURE}
        new_headers['Host'] = headers.get('Host', '')

        return new_headers

    def canonical_headers(self, headers):
        """
        Return the headers that need to be included in the StringToSign
        in their canonical form by converting all header keys to lower
        case, sorting them in alphabetical order and then joining
        them into a string, separated by newlines.
        """
        new_headers = unicode_encoded_dict(headers)
        l = sorted(['%s: %s' % (n.lower().strip(),
                                new_headers[n].strip()) for n in new_headers])
        return '\n'.join(l)

    def signature_request(self, request):
        signature = self.sign_string(utf8(self.string_to_sign(request)))
        logger.debug('signature: %s' % signature)
        return signature

    def check_response(self, sign_response, request, response):
        # 不需要检查返回的签名就直接返回
        if not sign_response:
            return True

        # logger.debug(response.headers)
        try:
            timestamp = int(response.headers.get(HEADER_X_TIMESTAMP))
        except ValueError:
            logger.debug('Invalid X-Api-Timestamp Header')
            return False

        now_ts = int(time.time())
        if abs(timestamp - now_ts) > self.client.signature_expire_seconds:
            logger.debug('Expired signature, timestamp: %s' % timestamp)
            return False

        signature = response.headers.get(HEADER_X_SIGNATURE)
        if signature:
            del response.headers[HEADER_X_SIGNATURE]
        else:
            logger.debug('No signature provide')
            return False

        string_to_sign = self.response_string_to_sign(request, response)
        # 如果不是 unicode 输出会引发异常
        # logger.debug('string_to_sign: %s' % string_to_sign.decode('utf-8'))
        # hash_value = sha1(utf8(string_to_sign)).hexdigest()
        real_signature = self.sign_string(utf8(string_to_sign))
        if signature != real_signature:
            logger.debug('Signature not match: %s, %s' % (signature, real_signature))
            return False
        else:
            return True


class APIRequest(object):
    def __init__(self, client, endpoint, version='', encrypt_type='raw',
                 require_hmac=True, sign_response=True, hmac_algorithm=sha1, *args, **kwargs):
        self.access_key = client.access_key
        self.secret_key = client.secret_key
        self.api_server = client.api_server.strip()
        self.endpoint = endpoint.strip().strip('/')
        self.version = version.strip().strip('/')
        self.encrypt_type = encrypt_type
        self.require_hmac = require_hmac
        self.sign_response = sign_response
        self.request_data = RequestObject()

        self.gateway_error_status_code = client.gateway_error_status_code
        self.hmac_handler = HMACHandler(client, hmac_algorithm)

    def prepare_request(self, method, uri, params=None, headers=None,
                        data=None, json=None, access_token=None):
        params = {} if params is None else params
        if not isinstance(params, dict):
            raise TypeError('params should be dict')

        if uri == '':
            uri = '/'

        method = method.upper()
        params = utf8_encoded_dict(params)
        url = '/'.join([self.api_server, self.endpoint, self.version]) + uri.strip()
        logger.debug(url)
        url_parsed = urlparse(url)
        enc_params = urlencode(params)
        logger.debug(enc_params)
        if url_parsed.query == '' or url_parsed.query is None:
            query = enc_params
        elif enc_params == '' or enc_params is None:
            query = url_parsed.query
        else:
            query = '%s&%s' % (url_parsed.query, enc_params)

        real_uri = urlunparse(('', '', url_parsed.path, url_parsed.params,
                               query, url_parsed.fragment))

        real_url = urlunparse((url_parsed.scheme, url_parsed.netloc, url_parsed.path,
                               url_parsed.params,
                               query, url_parsed.fragment))

        self.request_data.uri = real_uri
        self.request_data.method = method
        self.request_data.headers = {
            # 'Accept': 'application/json; charset=utf-8',
            'Host': url_parsed.netloc
        }

        if headers is not None and isinstance(headers, dict):
            # headers 是字典
            self.request_data.headers.update(headers)

        if access_token is not None:
            self.request_data.headers[HEADER_X_ACCESS_TOKEN] = access_token

        self.request_data.body = ''
        if method in ['POST', 'PUT']:
            if json is not None:
                self.request_data.headers['Content-Type'] = 'application/json; charset=utf-8'
                self.request_data.body = json_util.dumps(json)
            else:
                self.request_data.body = '' if data is None else data

        return real_url

    def get_auth_headers(self):
        headers = {
            HEADER_X_TIMESTAMP: text_type(int(time.time())),
            HEADER_X_NONCE: text_type(random.random()),
            HEADER_X_APP_ID: text_type(self.access_key),
            HEADER_X_ENCRYPT_TYPE: text_type(self.encrypt_type)
        }

        # 检查是否需要返回结果的签名
        if self.sign_response:
            headers[HEADER_X_SIGN_RESPONSE] = '1'

        return headers

    def encrypt_data(self):
        aes_cipher = AESCipher(self.secret_key)
        headers_str = json_util.dumps(self.request_data.headers)
        # 加密 Headers 和 url
        self.request_data.headers = {
            'Content-Type': 'application/octet-stream',
            'Host': self.request_data.headers.get('Host', ''),
            HEADER_X_ENCRYPTED_HEADERS: aes_cipher.encrypt(utf8(headers_str)),
            HEADER_X_ENCRYPTED_URI: aes_cipher.encrypt(utf8(self.request_data.uri)),
        }
        self.request_data.uri = '/%s/%s/?_t=%d&_nonce=%s' % \
                                (self.endpoint, self.version,
                                 int(time.time()), text_type(random.random()))

        # 设置一个新的 url
        url = self.api_server + self.request_data.uri

        if self.request_data.body is not None and len(self.request_data.body) > 0:
            self.request_data.body = aes_cipher.encrypt(utf8(self.request_data.body))
            # logger.debug(self.request_data.body)
        return url

    def decrypt_data(self, body):
        try:
            aes_cipher = AESCipher(self.secret_key)
            if body and len(body) > 0:
                logger.debug('解密 body')
                body = aes_cipher.decrypt(utf8(body))
                # logger.debug(body.decode('hex'))
        except Exception as e:
            logger.error('解密数据出错')
            logger.error(e)
            logger.error(traceback.format_exc())
            return None

        # 由于 requests 的 content 不是 unicode 类型, 为了兼容, 这里改成 utf8
        if isinstance(body, text_type):
            body = body.encode('utf-8')

        return body

    def _do_fetch(self, method, uri, params=None, headers=None, data=None,
                  json=None, access_token=None, **kwargs):
        url = self.prepare_request(method, uri, params=params,
                                   data=data, json=json, headers=headers,
                                   access_token=access_token)

        if self.encrypt_type == 'aes':
            url = self.encrypt_data()

        self.request_data.headers.update(self.get_auth_headers())
        # 需要对请求的内容进行 hmac 签名
        if self.require_hmac:
            signature = self.hmac_handler.signature_request(self.request_data)
            self.request_data.headers[HEADER_X_SIGNATURE] = signature

        if method in ['get', 'head', 'options', 'delete']:
            func = getattr(requests, method)
            r = func(url, headers=self.request_data.headers, **kwargs)
        elif method in ['post', 'put']:
            func = getattr(requests, method)
            r = func(url, headers=self.request_data.headers,
                     data=utf8(self.request_data.body), **kwargs)
        else:
            raise ValueError('method not allowed')

        if r.status_code != GATEWAY_ERROR_STATUS_CODE:
            is_valid = self.hmac_handler.check_response(
                self.sign_response, self.request_data, r)
            if not is_valid:
                logger.debug('返回结果签名不正确')

        r_encrypt_type = r.headers.get(HEADER_X_ENCRYPT_TYPE, 'raw')
        if r_encrypt_type == 'aes':
            r._content = self.decrypt_data(r.content)

        return r

    def head(self, uri, params=None, headers=None, access_token=None, **kwargs):
        return self._do_fetch(
            'head', uri, params, headers,
            access_token=access_token, **kwargs)

    def options(self, uri, params=None, headers=None,
                access_token=None, **kwargs):
        return self._do_fetch(
            'options', uri, params, headers,
            access_token=access_token, **kwargs)

    def delete(self, uri, params=None, headers=None,
               access_token=None, **kwargs):
        return self._do_fetch(
            'delete', uri, params, headers,
            access_token=access_token, **kwargs)

    def get(self, uri, params=None, headers=None,
            access_token=None, **kwargs):
        return self._do_fetch(
            'get', uri, params, headers,
            access_token=access_token, **kwargs)

    def post(self, uri, data=None, json=None, params=None,
             headers=None, access_token=None, **kwargs):
        return self._do_fetch(
            'post', uri, params, headers, data, json,
            access_token=access_token, **kwargs)

    def put(self, uri, data=None, json=None, params=None,
            headers=None, access_token=None, **kwargs):
        return self._do_fetch(
            'put', uri, params, headers, data, json,
            access_token=access_token, **kwargs)


def main():
    access_key = 'abcd'
    secret_key = '1234'
    api_gateway = 'http://127.0.0.1:6500'
    endpoint = 'test_api'
    version = 'v1'
    client = APIClient(access_key, secret_key, api_gateway)
    request = APIRequest(client, endpoint, version)
    params = {'a': 1, 'b': '2'}
    r = request.get('/resource/?q=123', params=params)
    # print(r.content)

    json_data = {
        'a': 1,
        'b': 'test string',
        'c': '中文'
    }

    r = request.post('/resource/', json=json_data)
    print(type(r.content))
    print(type(r.text))
    print(r.json())

    request = APIRequest(client, endpoint, version, 'aes')
    r = request.post('/resource/', json=json_data)
    print(r.content)
    print(r.text)
    print(r.json())


if __name__ == '__main__':
    main()
