# -*- coding: utf-8 -*-
# created by restran on 2016/02/21
from __future__ import unicode_literals, absolute_import
import base64
import json
import logging
import traceback

from handlers.base import AuthRequestException
from utils import RedisHelper
from middleware import BaseMiddleware

logger = logging.getLogger(__name__)


class AuthAccessTokenHandler(BaseMiddleware):
    """
    对 access_token 信息进行验证
    """

    def process_request(self, *args, **kwargs):
        logger.debug('process_request')
        if 'X-Api-User-Json' in self.handler.request.headers:
            del self.handler.request.headers['X-Api-User-Json']

        endpoint = self.handler.client.request['endpoint']
        require_login = endpoint.get('require_login', False)
        if not require_login:
            return

        access_token = self.handler.request.get_query_argument('access_token')
        token_info = RedisHelper.get_access_token_info(access_token)

        if token_info is not None:
            if token_info['access_key'] != self.handler.client.access_key:
                raise AuthRequestException('This Access Token is Belongs to Another Client App')

            logger.debug('允许访问')
            try:
                json_str = json.dumps(token_info['user_info'], ensure_ascii=False)
                # 用户信息使用 json 存储，并编码为 base64
                self.handler.request.headers['X-Api-User-Json'] = base64.b64encode(json_str.encode('utf8'))
            except Exception, e:
                logger.error('设置 X-Api-User-Json 失败')
                logger.error(e.message)
                logger.error(traceback.format_exc())
        else:
            logger.info('没有获取到用户信息，不允许访问')
            # 获取用户信息失败
            raise AuthRequestException('Expired or Invalid Access Token')


class AuthEndpointHandler(BaseMiddleware):
    """
    登录, 并返回 access_token, expires_in, refresh_token
    """

    def process_request(self, *args, **kwargs):
        logger.debug('process_request')
        endpoint = self.handler.client.request['endpoint']
        if endpoint == 'auth':
            pass


class AuthLogoutHandler(BaseMiddleware):
    """
    对 access_token 信息进行验证
    """

    def process_request(self, *args, **kwargs):
        logger.debug('process_request')
        if 'X-Api-User-Json' in self.handler.request.headers:
            del self.handler.request.headers['X-Api-User-Json']

        endpoint = self.handler.client.request['endpoint']
        require_login = endpoint.get('require_login', False)
        if not require_login:
            return

        access_token = self.handler.request.get_query_argument('access_token')
        token_info = RedisHelper.get_access_token_info(access_token)

        if token_info is not None:
            if token_info['access_key'] != self.handler.client.access_key:
                raise AuthRequestException('This Access Token is Belongs to Another Client App')

            logger.debug('允许访问')
            try:
                json_str = json.dumps(token_info['user_info'], ensure_ascii=False)
                # 用户信息使用 json 存储，并编码为 base64
                self.handler.request.headers['X-Api-User-Json'] = base64.b64encode(json_str.encode('utf8'))
            except Exception, e:
                logger.error('设置 X-Api-User-Json 失败')
                logger.error(e.message)
                logger.error(traceback.format_exc())
        else:
            logger.info('没有获取到用户信息，不允许访问')
            # 获取用户信息失败
            raise AuthRequestException('Expired or Invalid Access Token')
