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
from utils import RedisHelper, get_utf8_value, text_type, binary_type
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
                request.uri = aes_cipher.decrypt(get_utf8_value(encrypted_uri))
                logger.debug('decrypted uri %s' % request.uri)

            encrypted_headers = self.handler.request.headers.get('X-Api-Encrypted-Headers')

            if encrypted_headers:
                headers_str = aes_cipher.decrypt(get_utf8_value(encrypted_headers))
                headers = dict(json.loads(headers_str))
                logger.debug('raw headers %s' % request.headers)
                for k, v in headers.iteritems():
                    # 要全部使用 text_type，否则会出现有的为 str，有的为 unicode
                    # 导致422错误
                    request.headers[text_type(k)] = text_type(v)

                logger.debug('decrypted headers %s' % request.headers)

            if request.body and len(request.body) > 0:
                logger.debug('解密 body')
                logger.debug(request.body.encode('hex'))
                request.body = aes_cipher.decrypt(get_utf8_value(request.body))

            # 重新计算一下 Content-Length
            # 如果 Content-Length 不正确, 请求后端网站会出错,
            # 太大会出现超时问题, 太小会出现内容被截断
            # prepare_content_length(request.body)

        # def prepare_content_length(body):
        #     """
        #     requests prepare_content_length
        #     :param body:
        #     :return:
        #     """
        #     if hasattr(body, 'seek') and hasattr(body, 'tell'):
        #         body.seek(0, 2)
        #         request.headers['Content-Length'] = binary_type(body.tell())
        #         body.seek(0, 0)
        #     elif body is not None:
        #         l = len(body)
        #         if l:
        #             request.headers['Content-Length'] = binary_type(l)
        #     elif (request.method not in ('GET', 'HEAD')) and \
        #             (request.headers.get('Content-Length') is None):
        #         request.headers['Content-Length'] = '0'

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
            body = aes_cipher.encrypt(get_utf8_value(body))
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
            raise ServerErrorException(500, 'Encrypt body error')
