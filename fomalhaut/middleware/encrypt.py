#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/22


from __future__ import unicode_literals, absolute_import

import copy
import traceback

from future.utils import iteritems
from tornado.escape import json_decode
from tornado.httputil import parse_qs_bytes

from ..i18n import PromptMessage
from ..middleware.base import BaseMiddleware, ResultCode
from ..middleware.exceptions import ClientErrorException, ServerErrorException
from ..settings import *
from ..utils import AESCipher, utf8, text_type

logger = logging.getLogger(__name__)

"""
处理请求和响应内容的解密和加密
"""


class EncryptMiddleware(BaseMiddleware):
    """
    处理解密和加密相关的
    """

    def decrypt_data(self):
        request = self.handler.request
        client = self.handler.client
        logger.debug('client: %s' % client)
        aes_cipher = AESCipher(client.secret_key)
        encrypted_uri = self.handler.request.headers.get(HEADER_X_ENCRYPTED_URI)
        if encrypted_uri is not None:
            request.uri = aes_cipher.decrypt(utf8(encrypted_uri))
            logger.debug('decrypted uri %s' % request.uri)
            # 因为修改了 uri，需要重新生成 query_arguments
            request.path, sep, request.query = request.uri.partition('?')
            request.arguments = parse_qs_bytes(request.query, keep_blank_values=True)
            request.query_arguments = copy.deepcopy(request.arguments)

        encrypted_headers = self.handler.request.headers.get(HEADER_X_ENCRYPTED_HEADERS)

        if encrypted_headers is not None:
            headers_str = aes_cipher.decrypt(utf8(encrypted_headers))
            headers = dict(json_decode(headers_str))
            # logger.debug('raw headers %s' % request.headers)
            for k, v in iteritems(headers):
                # 要全部使用 text_type，否则会出现有的为 str，有的为 unicode
                # 导致422错误
                request.headers[text_type(k)] = text_type(v)

        if request.body and len(request.body) > 0:
            logger.debug('解密 body')
            logger.debug(request.body)
            request.body = aes_cipher.decrypt(utf8(request.body))
            # 因为修改了 body，需要重新 _parse_body
            request._parse_body()
            # 解密完之后不需要重新计算 Content-Length,
            # 因为请求后端 API 时不带 Content-Length

    def encrypt_data(self, body):
        handler = self.handler
        # 如果请求的使用 AES 加密，则加密返回的数据
        logger.debug('使用 AES 加密 body')
        aes_cipher = AESCipher(handler.client.secret_key)
        body = aes_cipher.encrypt(utf8(body))
        # 更新为加密后的数据
        handler.clear_write_buffer()
        handler.write(body)
        handler.set_header(HEADER_X_ENCRYPT_TYPE, 'aes')

    def process_request(self, *args, **kwargs):
        handler = self.handler
        handler.client.encrypt_type = handler.request.headers.get(HEADER_X_ENCRYPT_TYPE, 'raw')
        if handler.client.encrypt_type != 'aes':
            return
        try:
            self.decrypt_data()
        except Exception as e:
            logger.error('解密数据出错')
            logger.error(e)
            logger.error(traceback.format_exc())
            raise ClientErrorException(ResultCode.AES_DECRYPT_ERROR, PromptMessage.AES_DECRYPT_ERROR)

    def process_response(self, *args, **kwargs):
        handler = self.handler
        response_body = b''.join(handler.get_write_buffer())
        if handler.client.encrypt_type == 'raw' or len(response_body) <= 0:
            handler.set_header(HEADER_X_ENCRYPT_TYPE, 'raw')
            return

        try:
            self.encrypt_data(response_body)
        except Exception as e:
            handler.clear()
            logger.error('使用 AES 加密 body 出错')
            logger.error(e)
            logger.error(traceback.format_exc())
            raise ServerErrorException(ResultCode.AES_ENCRYPT_ERROR, PromptMessage.AES_ENCRYPT_ERROR)
