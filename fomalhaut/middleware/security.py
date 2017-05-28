#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals, absolute_import

import hmac
import logging
import random
import time
from base64 import urlsafe_b64encode
from hashlib import sha1

from future.utils import iteritems
from tornado.escape import to_unicode

from ..i18n import PromptMessage
from ..middleware.base import BaseMiddleware, ResultCode
from ..middleware.exceptions import ClientErrorException
from ..settings import HEADER_X_SIGN_RESPONSE, \
    SIGNATURE_EXPIRE_SECONDS, HEADER_X_SIGNATURE, HEADER_X_TIMESTAMP, \
    HEADER_X_NONCE, HEADER_X_PREFIX
from ..utils import utf8, text_type, unicode_encoded_dict

logger = logging.getLogger(__name__)

"""
处理安全相关的
"""


class HMACHandler(object):
    """
    HMAC 签名
    """

    def __init__(self, client, algorithm=sha1):
        self.client = client
        self.algorithm = algorithm

    def sign_string(self, string_to_sign):
        logger.debug(string_to_sign)
        new_hmac = hmac.new(
            utf8(self.client.secret_key), utf8(string_to_sign),
            digestmod=self.algorithm)
        logger.debug(new_hmac.hexdigest())
        return to_unicode(urlsafe_b64encode(new_hmac.digest()).rstrip(b'='))

    def _request_headers_to_sign(self, request):
        """
        """
        # 计算签名的时候, 不能包含 signature
        # 如果要获取多个同名的 headers 使用 request.headers.get_all()
        # 虽然有可能会有同名的 headers，但是网关使用的特殊headers，不能存在同名多个的
        # 因此这种方法是可以的
        headers_to_sign = {name: value for name, value in iteritems(request.headers)
                           if name.startswith(HEADER_X_PREFIX) and name != HEADER_X_SIGNATURE}
        headers_to_sign['Host'] = request.headers.get('Host', '')

        return headers_to_sign

    def _response_headers_to_sign(self, response_headers):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        # 计算签名的时候, 不能包含 signature
        headers_to_sign = {name: value for name, value in iteritems(response_headers)
                           if name.startswith(HEADER_X_PREFIX) and name != HEADER_X_SIGNATURE}

        return headers_to_sign

    def _canonical_headers(self, headers_to_sign):
        """
        """
        headers_to_sign = unicode_encoded_dict(headers_to_sign)
        l = sorted(['%s: %s' % (n.lower().strip(),
                                headers_to_sign[n].strip()) for n in headers_to_sign])
        return '\n'.join(l)

    def _request_string_to_sign(self, request):
        """
        """
        headers_to_sign = self._request_headers_to_sign(request)
        canonical_headers = self._canonical_headers(headers_to_sign)
        # 只对 uri 进行签名而不是完整的 url 进行签名，是因为前端可能使用 Nginx 反代，
        # 所以请求这里的时候，url 和用户发起的 url 是不一样的，而 uri 则是一样的
        # 同样 scheme 也存在这样的问题，因此也没有进行签名
        # 只所以再多加上了 Host，是因为避免部署了多套系统，然后用另外一套系统的签名来访问这套
        string_to_sign = b'\n'.join([utf8(request.method.upper()),
                                     utf8(self.client.raw_uri),
                                     utf8(canonical_headers),
                                     utf8(request.body)])
        return string_to_sign

    def _response_string_to_sign(self, response_headers, request, response_body):
        """
        """
        headers_to_sign = self._response_headers_to_sign(response_headers)
        canonical_headers = self._canonical_headers(headers_to_sign)
        string_to_sign = b'\n'.join([utf8(request.method.upper()),
                                     utf8(self.client.raw_uri),
                                     utf8(canonical_headers),
                                     utf8(response_body)])
        # logger.debug(string_to_sign)
        return string_to_sign

    def signature_response(self, response_header, request, response_body):
        string_to_sign = self._response_string_to_sign(
            response_header, request, response_body)
        return self.sign_string(utf8(string_to_sign))

    def auth_request(self, request):
        try:
            timestamp = int(request.headers.get(HEADER_X_TIMESTAMP))
        except ValueError:
            raise ClientErrorException(ResultCode.BAD_REQUEST, PromptMessage.INVALID_TIMESTAMP)

        now_ts = int(time.time())
        if abs(timestamp - now_ts) > SIGNATURE_EXPIRE_SECONDS:
            # logger.debug('Expired signature, timestamp: %s' % timestamp)
            raise ClientErrorException(ResultCode.EXPIRED_SIGNATURE, PromptMessage.EXPIRED_SIGNATURE)

        signature = to_unicode(request.headers.get(HEADER_X_SIGNATURE))
        if not signature:
            # logger.debug('No Signature Provided')
            raise ClientErrorException(ResultCode.BAD_REQUEST, PromptMessage.NO_SIGNATURE_PROVIDED)

        string_to_sign = self._request_string_to_sign(request)
        real_signature = self.sign_string(utf8(string_to_sign))
        if signature != real_signature:
            logger.debug('Signature not match: %s, %s' % (signature, real_signature))
            raise ClientErrorException(ResultCode.INVALID_SIGNATURE, PromptMessage.INVALID_SIGNATURE)


class HMACAuthenticateMiddleware(BaseMiddleware):
    def process_request(self, *args, **kwargs):
        """
        对访问请求进行HMAC签名校验
        """
        # logger.debug('process_request')
        handler = self.handler
        endpoint = handler.client.request.endpoint
        # 判断是否需要进行 HMAC 签名校验
        if endpoint.get('enable_hmac', True):
            auth_handler = HMACHandler(handler.client)
            auth_handler.auth_request(handler.request)

    def process_response(self, *args, **kwargs):
        """
        对响应结果进行HMAC签名校验
        """
        # logger.debug('process_response')
        handler = self.handler
        handler.set_header(HEADER_X_TIMESTAMP, text_type(int(time.time())))
        # 判断是否需要对返回的数据进行 HMAC 签名校验
        if handler.request.headers.get(HEADER_X_SIGN_RESPONSE, '0') != '1':
            return

        # 执行签名
        auth_handler = HMACHandler(handler.client)
        handler.set_header(HEADER_X_NONCE, text_type(random.random()))

        response_headers = handler.get_response_headers()
        response_body = b''.join(handler.get_write_buffer())
        # logger.debug(response_body.decode('utf-8'))
        # logger.debug(dict(self.handler.get_response_headers()))
        signature = auth_handler.signature_response(
            response_headers,
            handler.request, response_body)

        # 对返回结果进行签名
        handler.set_header(HEADER_X_SIGNATURE, signature)
