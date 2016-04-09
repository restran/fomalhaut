# -*- coding: utf-8 -*-
# created by restran on 2016/02/21
from __future__ import unicode_literals, absolute_import

import json
import logging
import sys
import time
import traceback
from functools import wraps

import cerberus
from tornado import gen
from tornado.concurrent import is_future
from tornado.curl_httpclient import CurlAsyncHTTPClient as AsyncHTTPClient
from tornado.httpclient import HTTPRequest

from handlers.base import AuthRequestException
from settings import GATEWAY_ERROR_STATUS_CODE, \
    ASYNC_HTTP_CONNECT_TIMEOUT, ASYNC_HTTP_REQUEST_TIMEOUT
from utils import RedisHelper

logger = logging.getLogger(__name__)


class APIStatusCode(object):
    SUCCESS = 200  # 成功
    FAIL = 400  # 客户端的错误, 例如请求信息不正确
    ERROR = 500  # 服务端的错误, 例如出现异常


class Validator(object):
    @classmethod
    def schema(cls, input_schema=None):
        """
        验证提交的 json 数据格式是否正确
        :param input_schema:
        :return:
        """

        def _validate(func):
            @wraps(func)
            @gen.coroutine
            def _wrapper(self, *args, **kwargs):
                try:
                    # 因为这段代码是在 @gen.coroutine 装饰器中，
                    # 如果这段代码发生异常，没有用 except 捕获的话就无法自动调用 write_error
                    validate_success = True
                    errors = None
                    if input_schema is not None:
                        v = cerberus.Validator(input_schema)
                        # 允许提交未知的数据
                        v.allow_unknown = True
                        if not v.validate(self.post_data):
                            validate_success = False
                            errors = v.errors

                    if not validate_success:
                        logger.warning(errors)
                        # 验证失败，返回错误
                        self.fail(msg='提交的数据格式不正确')
                    else:
                        # Call the request_handler method
                        ret = func(self, *args, **kwargs)
                        if is_future(ret):
                            yield ret
                            # 如果 rh_method 用了 coroutine，并且这个函数中抛出了异常，
                            # 但是这里没有用 yield 的话，就无法捕获到异常，从而调用 write_error
                            logger.debug('yield')
                except gen.Return:
                    pass
                except Exception as e:
                    logger.debug(traceback.format_exc())
                    logger.debug(e)
                    self.write_error(GATEWAY_ERROR_STATUS_CODE, exc_info=sys.exc_info())

            return _wrapper

        return _validate


class BuiltinAPIHandler(object):
    def __init__(self, handler, *args, **kwargs):
        self.post_data = {}
        self.handler = handler
        self.request = self.handler.request
        self.client = self.handler.client
        self.write = self.handler.write
        self.set_header = self.handler.set_header
        self.finish = self.handler.finish

        if self.request.method == 'POST':
            content_type = self.request.headers.get('Content-Type', '').lower()
            logger.debug(content_type)
            if content_type.startswith('application/json'):
                try:
                    self.post_data = json.loads(self.request.body)
                except Exception as e:
                    logger.error(e)
            logger.debug(self.post_data)

        self.set_header("Content-Type", "application/json; charset=utf-8")

    def success(self, data=None, msg=''):
        json_str = json.dumps({
            'code': APIStatusCode.SUCCESS, 'data': data,
            'msg': msg}, ensure_ascii=False)
        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)

    def fail(self, data=None, msg='', code=APIStatusCode.FAIL):
        json_str = json.dumps({
            'code': code, 'data': data, 'msg': msg
        }, ensure_ascii=False)

        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)

    def error(self, data=None, msg='', code=APIStatusCode.ERROR):
        json_str = json.dumps({
            'code': code, 'data': data, 'msg': msg
        }, ensure_ascii=False)
        logger.debug(json_str)
        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)


class AuthLoginHandler(BuiltinAPIHandler):
    """
    登录
    """

    @gen.coroutine
    def post(self, *args, **kwargs):
        logger.debug('AuthLoginHandler')
        login_auth_url = self.client.config.get('login_auth_url')
        logger.debug(login_auth_url)
        if login_auth_url is None:
            raise AuthRequestException('Missing Login Auth Url in Client Config')
        # access_token 多少秒后过期
        access_token_ex = self.client.config.get('access_token_ex')
        refresh_token_ex = self.client.config.get('refresh_token_ex')

        # 设置超时时间
        async_http_connect_timeout = ASYNC_HTTP_CONNECT_TIMEOUT
        async_http_request_timeout = ASYNC_HTTP_REQUEST_TIMEOUT
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        try:
            response = yield AsyncHTTPClient().fetch(
                HTTPRequest(url=login_auth_url,
                            method=self.request.method,
                            body=self.request.body,
                            headers=headers,
                            connect_timeout=async_http_connect_timeout,
                            request_timeout=async_http_request_timeout))
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            raise AuthRequestException('Fail to Request Login Auth Url')

        json_data = json.loads(response.body)
        if json_data['code'] == APIStatusCode.SUCCESS:
            user_info = json_data['data']
            token_info = {
                'access_key': self.client.access_key,
                'user_info': user_info
            }

            token_info = RedisHelper.set_token_info(
                token_info, access_token_ex, refresh_token_ex)
            if token_info is None:
                self.error(msg='Save Access Token Error')
            else:
                data = {
                    'access_token': token_info['access_token'],
                    'refresh_token': token_info['refresh_token'],
                    # access_token 过期时间
                    'expires_in': int(time.time()) + access_token_ex,
                    'user_info': user_info
                }
                self.success(data)
        else:
            self.fail(msg=json_data['msg'])


class AuthLogoutHandler(BuiltinAPIHandler):
    """
    登出
    """
    schema = {
        'access_token': {
            'type': 'string',
            'required': True
        }
    }

    @Validator.schema(schema)
    def post(self, *args, **kwargs):
        access_token = self.post_data['access_token']
        RedisHelper.clear_token_info(access_token=access_token)
        self.success(msg='Logout Success')


class AuthTokenHandler(BuiltinAPIHandler):
    """
    用 refresh_token 来获取新的 access_token
    """
    schema = {
        'refresh_token': {
            'type': 'string',
            'required': True
        }
    }

    @Validator.schema(schema)
    def post(self, *args, **kwargs):
        refresh_token = self.post_data['refresh_token']
        token_info = RedisHelper.get_refresh_token_info(refresh_token)
        access_token_ex = self.client.config.get('access_token_ex')
        refresh_token_ex = self.client.config.get('refresh_token_ex')
        if token_info:
            RedisHelper.clear_token_info(refresh_token=refresh_token)
            token_info = RedisHelper.set_token_info(
                token_info, access_token_ex, refresh_token_ex)
            if token_info is None:
                self.error(msg='Save Access Token Error')
            else:
                self.success(token_info)
        else:
            self.fail(msg='Invalid or Expired Refresh Token')
