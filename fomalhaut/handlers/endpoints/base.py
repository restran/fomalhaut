# -*- coding: utf-8 -*-
# created by restran on 2016/02/21
from __future__ import unicode_literals, absolute_import

import json
import logging
import sys
import traceback
from functools import wraps

import cerberus
from tornado import gen
from tornado.concurrent import is_future
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from fomalhaut.i18n import PromptMessage
from fomalhaut.settings import HEADER_BACKEND_APP_ID, \
    HEADER_BACKEND_USER_JSON
from fomalhaut.utils import text_type

logger = logging.getLogger(__name__)


class APIStatusCode(object):
    SUCCESS = 200  # 成功
    FAIL = 400  # 客户端的错误, 例如请求信息不正确
    ERROR = 500  # 服务端的错误, 例如出现异常
    FORBIDDEN = 403  # 禁止访问


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
                        self.fail(msg=PromptMessage.INVALID_REQUEST_DATA)
                    else:
                        # Call the request_handler method
                        ret = func(self, *args, **kwargs)
                        if is_future(ret):
                            yield ret
                            # 如果 rh_method 用了 coroutine，并且这个函数中抛出了异常，
                            # 但是这里没有用 yield 的话，就无法捕获到异常，从而调用 write_error
                            logger.debug('yield')
                except gen.Return as r:
                    raise r
                except Exception as e:
                    logger.debug(traceback.format_exc())
                    logger.debug(e)
                    self.write_error(500, exc_info=sys.exc_info())

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
                    self.post_data = json_decode(self.request.body)
                except Exception as e:
                    logger.error(e)
            logger.debug(self.post_data)

        self.set_header("Content-Type", "application/json; charset=utf-8")

    def success(self, data=None, msg=''):
        json_str = json.dumps({
            'code': APIStatusCode.SUCCESS, 'value': data,
            'message': msg}, ensure_ascii=False)
        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)

    def fail(self, data=None, msg='', code=APIStatusCode.FAIL):
        json_str = json.dumps({
            'code': code, 'value': data, 'message': msg
        }, ensure_ascii=False)

        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)

    def error(self, data=None, msg='', code=APIStatusCode.ERROR):
        json_str = json.dumps({
            'code': code, 'message': data, 'value': msg
        }, ensure_ascii=False)
        logger.debug(json_str)
        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)


class LoginRequiredHandler(BuiltinAPIHandler):
    """
    需要登录的接口
    """

    def get_required_headers(self):
        """
       获取需要传递给后端的 headers
        :return:
        """
        new_headers = HTTPHeaders()
        # 如果 header 有的是 str，有的是 unicode
        # 会出现 422 错误
        for name, value in self.request.headers.get_all():
            # 这些 x-api 开头的 headers 是需要传递给后端
            required_headers = [
                HEADER_BACKEND_USER_JSON
            ]
            if name in required_headers:
                new_headers.add(text_type(name), text_type(value))

        # 传递 app_id
        new_headers[HEADER_BACKEND_APP_ID] = self.client.app_id
        return new_headers
