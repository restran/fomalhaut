# -*- coding: utf-8 -*-
# created by restran on 2016/02/21
from __future__ import unicode_literals, absolute_import

import logging
import traceback

from tornado import gen
from tornado.escape import json_decode
from tornado.httpclient import HTTPRequest

from fomalhaut.handlers.base import ServerErrorException
from fomalhaut.handlers.endpoints.base import APIStatusCode, BuiltinAPIHandler
from fomalhaut.i18n import PromptMessage
from fomalhaut.middleware.base import ResultCode
from fomalhaut.settings import ASYNC_HTTP_CONNECT_TIMEOUT, ASYNC_HTTP_REQUEST_TIMEOUT
from fomalhaut.utils import RedisHelper, AsyncHTTPClient

logger = logging.getLogger(__name__)


class Login(BuiltinAPIHandler):
    """
    登录
    """

    @gen.coroutine
    def post(self, *args, **kwargs):
        client = self.client
        login_type = self.handler.get_query_argument('login_type', 'password')
        if login_type == 'sms':
            login_auth_url = client.config.sms_login_auth_url
            if login_auth_url is None or login_auth_url == '':
                raise ServerErrorException(
                    ResultCode.BAD_CLIENT_CONFIG,
                    PromptMessage.NO_AUTH_LOGIN_SMS_URL_CONFIG)
        else:
            login_auth_url = client.config.login_auth_url
            if login_auth_url is None or login_auth_url == '':
                raise ServerErrorException(
                    ResultCode.BAD_CLIENT_CONFIG,
                    PromptMessage.NO_AUTH_LOGIN_URL_CONFIG)

        # access_token 多少秒后过期
        access_token_ex = client.config.access_token_ex
        refresh_token_ex = client.config.refresh_token_ex

        headers = {'Content-Type': 'application/json; charset=utf-8'}
        try:
            response = yield AsyncHTTPClient().fetch(
                HTTPRequest(url=login_auth_url,
                            method=self.request.method,
                            body=self.request.body,
                            headers=headers,
                            connect_timeout=ASYNC_HTTP_CONNECT_TIMEOUT,
                            request_timeout=ASYNC_HTTP_REQUEST_TIMEOUT))
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            raise ServerErrorException(
                ResultCode.ENDPOINT_REQUEST_ERROR,
                PromptMessage.FAIL_TO_REQ_LOGIN_URL)

        # logger.debug(response.body)
        try:
            json_data = json_decode(response.body)
        except:
            raise ServerErrorException(
                ResultCode.BAD_ENDPOINT_RESPONSE,
                PromptMessage.BAD_ENDPOINT_RESPONSE)

        code = json_data.get('code', APIStatusCode.FAIL)
        if code == APIStatusCode.SUCCESS:
            user_info = json_data.get('value', {})
            token_info = {
                'app_id': client.app_id,
                'user_info': user_info
            }

            token_info = RedisHelper.set_token_info(
                token_info, access_token_ex, refresh_token_ex)
            if token_info is None:
                self.error(msg=PromptMessage.SAVE_ACCESS_TOKEN_ERROR)
            else:
                data = {
                    'access_token': token_info['access_token'],
                    'refresh_token': token_info['refresh_token'],
                    # access_token 在多久后过期，不是具体的过期时间，而是将在多少秒后过期
                    'expires_in': access_token_ex,
                    'user_info': user_info
                }
                self.success(data)
        else:
            self.fail(msg=json_data.get('message', PromptMessage.BAD_LOGIN_INFO))


class RefreshToken(BuiltinAPIHandler):
    """
    用 refresh_token 来获取新的 access_token
    """
    schema = {
        'refresh_token': {
            'type': 'string',
            'required': True
        }
    }

    def post(self, *args, **kwargs):
        refresh_token = self.post_data.get('refresh_token')
        if refresh_token is None:
            return self.fail(msg=PromptMessage.INVALID_REQUEST_DATA)

        token_info = RedisHelper.get_token_info(refresh_token=refresh_token)
        access_token_ex = self.client.config.access_token_ex
        refresh_token_ex = self.client.config.refresh_token_ex
        if token_info:
            RedisHelper.clear_token_info(refresh_token=refresh_token)
            token_info = RedisHelper.set_token_info(
                token_info, access_token_ex, refresh_token_ex)
            if token_info is None:
                self.error(msg=PromptMessage.SAVE_ACCESS_TOKEN_ERROR)
            else:
                return_token_info = {
                    'access_token': token_info['access_token'],
                    'refresh_token': token_info['refresh_token'],
                    'expires_in': access_token_ex,
                }
                self.success(return_token_info)
        else:
            self.fail(msg=PromptMessage.INVALID_REFRESH_TOKEN)


class CheckTokenAlive(BuiltinAPIHandler):
    """
    检查 access_token 是否有效，并返回剩余的过期时间
    """

    def post(self, *args, **kwargs):
        access_token = self.post_data.get('access_token')
        if access_token is None:
            return self.fail(msg=PromptMessage.INVALID_REQUEST_DATA)

        # 如果 key 不存在会返回 -2
        ttl = RedisHelper.get_access_token_ttl(access_token)
        if ttl is None:
            ttl = -1

        # 无论如何，都会返回，如果不存在就返回 -1
        data = {
            'expires_in': ttl,
        }
        self.success(data)
