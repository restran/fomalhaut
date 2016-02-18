#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/22


from __future__ import unicode_literals, absolute_import
import json

import time
import logging
import hmac
from hashlib import sha256
import re
import settings
from handlers.base import AuthRequestException, ServerErrorException
from utils import RedisHelper, utf8, text_type, binary_type
from urlparse import urlparse, urlunparse
import traceback
from utils import AESCipher
from copy import deepcopy
from middleware import BaseMiddleware

logger = logging.getLogger(__name__)

"""
处理请求和响应内容的解密和加密
"""


class EncryptHandler(BaseMiddleware):
    """
    处理解密和加密相关的
    """

    def process_request(self, *args, **kwargs):
        request = self.handler.request
        client = self.handler.client
        logger.debug('client: %s' % client)
        client.encrypt_type = request.headers.get('X-Api-Encrypt-Type', 'raw')
        if client.encrypt_type != 'aes':
            return

        def decrypt_data():
            aes_cipher = AESCipher(client.secret_key)
            encrypted_uri = self.handler.request.headers.get('X-Api-Encrypted-Uri')
            if encrypted_uri:
                request.uri = aes_cipher.decrypt(utf8(encrypted_uri))
                logger.debug('decrypted uri %s' % request.uri)

            encrypted_headers = self.handler.request.headers.get('X-Api-Encrypted-Headers')

            if encrypted_headers:
                headers_str = aes_cipher.decrypt(utf8(encrypted_headers))
                headers = dict(json.loads(headers_str))
                logger.debug('raw headers %s' % request.headers)
                for k, v in headers.iteritems():
                    # 要全部使用 text_type，否则会出现有的为 str，有的为 unicode
                    # 导致422错误
                    request.headers[text_type(k)] = text_type(v)

                logger.debug('decrypted headers %s' % request.headers)

            if request.body and len(request.body) > 0:
                logger.debug('解密 body')
                logger.debug(request.body)
                request.body = aes_cipher.decrypt(utf8(request.body))

                # 解密完之后不需要重新计算 Content-Length,
                # 因为请求后端 API 时不带 Content-Length

        try:
            decrypt_data()
        except Exception as e:
            logger.error('解密数据出错')
            logger.error(e)
            logger.error(traceback.format_exc())
            raise AuthRequestException('AES decrypt error')

    def process_response(self, *args, **kwargs):
        client = self.handler.client
        response_body = b''.join(self.handler.get_write_buffer())
        if client.encrypt_type == 'raw' or not len(response_body) > 0:
            return

        def encrypt_data(body):
            # 如果请求的使用 AES 加密，则加密返回的数据
            logger.debug('使用 AES 加密 body')
            aes_cipher = AESCipher(client.secret_key)
            body = aes_cipher.encrypt(utf8(body))
            # 更新为加密后的数据
            self.handler.clear_write_buffer()
            self.handler.write(body)
            self.handler.set_header('X-Api-Encrypt-Type', 'aes')

        try:
            encrypt_data(response_body)
        except Exception as e:
            self.handler.clear()
            logger.error('使用 AES 加密 body 出错')
            logger.error(e)
            logger.error(traceback.format_exc())
            raise ServerErrorException('Encrypt body error')
