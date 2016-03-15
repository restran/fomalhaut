#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals

import logging
import traceback
import sys
from middleware.analytics import ResultCode
from middleware.exceptions import *
from tornado.web import RequestHandler
from tornado.concurrent import is_future
from tornado import gen
from tornado.httputil import HTTPHeaders
from tornado.web import HTTPError
from middleware.analytics import AnalyticsData
from utils import text_type, copy_list

logger = logging.getLogger(__name__)

_REQUEST, _RESPONSE, _FINISHED = 0, 1, 2


class BaseHandler(RequestHandler):
    _call_mapper = {
        _REQUEST: 'process_request',
        _RESPONSE: 'process_response',
        _FINISHED: 'process_finished',
    }

    def __init__(self, application, request, **kwargs):
        super(BaseHandler, self).__init__(application, request, **kwargs)
        logger.debug('base init')

        # 请求 client 的相关信息
        self.client = None
        # 对应的 API Handler, 可能是内置的, 也可能是后端的 API
        self.real_api_handler = None
        self.analytics = AnalyticsData()
        self.response = {'headers': HTTPHeaders(), 'body': ''}
        # 拷贝一份中间件的列表
        self.middleware_list = copy_list(self.application.middleware_list)
        self.builtin_endpoints = self.application.builtin_endpoints

    def clear_nested_middleware(self, mw_class):
        """
        清除该中间件下级的所有中间件
        :param mw_class:
        :return:
        """
        logger.debug('clear_nested_middleware')
        logger.debug(self.middleware_list)
        for i, m in enumerate(self.middleware_list):
            if mw_class == m:
                self.middleware_list = self.middleware_list[:i]
                break

        logger.debug(self.middleware_list)

    def get_response_headers(self):
        return getattr(self, '_headers', HTTPHeaders())

    def clear_write_buffer(self):
        setattr(self, '_write_buffer', [])

    def get_write_buffer(self):
        return getattr(self, '_write_buffer', [])

    def write_error(self, status_code, **kwargs):
        """Override of RequestHandler.write_error
        :type  status_code: int
        :param status_code: HTTP status code
        """
        logger.debug('write_error')

        def get_exc_message(e):
            return e.log_message if \
                hasattr(e, 'log_message') else text_type(e)

        self.clear()
        # 因为执行了 clear，把之前设置的 header 也清理掉了，需要重新设置
        self.set_header("Content-Type", "application/json; charset=utf-8")

        try:
            if status_code == GATEWAY_ERROR_STATUS_CODE:
                self.set_status(status_code, 'Invalid Request')
            else:
                self.set_status(status_code)
        except Exception as e:
            logger.error(e)
            self.set_status(status_code, 'Unknown Status Code')

        ex = kwargs['exc_info'][1]
        # any 表示只要有一个为 true 就可以
        if any(isinstance(ex, c) for c in [APIGatewayException]):
            logger.debug('api exception')
            # 根据异常,设置相应的 result_code
            if isinstance(ex, AuthRequestException):
                self.analytics.result_code = ResultCode.BAD_AUTH_REQUEST
            elif isinstance(ex, ClientBadConfigException):
                self.analytics.result_code = ResultCode.CLIENT_CONFIG_ERROR
            elif isinstance(ex, LoginAuthException):
                self.analytics.result_code = ResultCode.BAD_ACCESS_TOKEN
            elif isinstance(ex, ServerErrorException):
                self.analytics.result_code = ResultCode.INTERNAL_SERVER_ERROR
            elif self.analytics.result_code is None:
                self.analytics.result_code = ResultCode.INTERNAL_SERVER_ERROR

            self.write('%s %s' % (status_code, get_exc_message(ex)))
        else:
            logger.error(get_exc_message(ex))
            logger.error(traceback.format_exc())
            self.analytics.result_code = ResultCode.INTERNAL_SERVER_ERROR
            self.write('500 Internal Error')

        if not self._finished:
            self.finish()

    @gen.coroutine
    def execute_next(self, request, mv_type, handler, *args, **kwargs):
        method_name = self._call_mapper.get(mv_type)
        if method_name == 'process_request':
            middleware_list = self.middleware_list
        elif method_name in ['process_response', 'process_finished']:
            # 这两个方法的处理顺序是反序
            middleware_list = self.middleware_list[-1::-1]
        else:
            return
        try:
            for mv_class in middleware_list:
                instance = mv_class(handler)
                # 如果不提供 default, 不存在时会出现异常
                m = getattr(instance, method_name, None)
                logger.debug('%s, %s, %s' % (mv_class, m, method_name))
                if m and callable(m):
                    try:
                        result = m(*args, **kwargs)
                        if is_future(result):
                            yield result
                    except Exception as e:
                        if not isinstance(e, APIGatewayException):
                            logger.error(e)
                            logger.error(traceback.format_exc())
                        # 在某一层的中间件出现异常,下一级的都不执行
                        self.clear_nested_middleware(mv_class)
                        # 如果在 request 阶段就出现了异常,直接进入 finish
                        if mv_type == _REQUEST and not self._finished:
                            status_code = getattr(e, 'status_code', GATEWAY_ERROR_STATUS_CODE)
                            logger.debug('exception write error')
                            self.write_error(status_code, exc_info=sys.exc_info())
                        # 不再往下执行
                        break
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            # 出现了预料之外的错误, 清理所有中间件, 结束
            self.middleware_list = []
            status_code = getattr(e, 'status_code', GATEWAY_ERROR_STATUS_CODE)
            self.write_error(status_code, exc_info=sys.exc_info())

    @gen.coroutine
    def _process_request(self, handler):
        logger.debug('_process_request')
        yield self.execute_next(handler.request, _REQUEST, handler)

    @gen.coroutine
    def _process_response(self, handler, chunk):
        logger.debug('_process_response')
        yield self.execute_next(handler.request, _RESPONSE, handler, chunk)

    @gen.coroutine
    def _process_finished(self, handler):
        logger.debug('_process_finished')
        yield self.execute_next(handler.request, _FINISHED, handler)

    @gen.coroutine
    def prepare(self):
        super(BaseHandler, self).prepare()

        logger.info('base prepare')
        yield self._process_request(self)

    @gen.coroutine
    def finish(self, chunk=None):
        if chunk:
            self.write(chunk)
            chunk = None

        yield self._process_response(self, self._write_buffer)

        # 执行完父类的 finish 方法后, 就会开始调用 on_finish
        super(BaseHandler, self).finish(chunk)

    def write(self, chunk):
        super(BaseHandler, self).write(chunk)

    @gen.coroutine
    def on_finish(self):
        """
        Called after the end of a request.
        :return:
        """
        super(BaseHandler, self).on_finish()
        yield self._process_finished(self)

    @gen.coroutine
    def get(self, *args, **kwargs):
        if self.real_api_handler is None:
            self.set_status(404)
            self.write('404 Not Found')
        else:
            handler = self.real_api_handler(self)
            if not hasattr(handler, 'get'):
                self.set_status(405)
                self.write('405 Method Not Allowed')
            else:
                yield handler.get(*args, **kwargs)

    @gen.coroutine
    def post(self, *args, **kwargs):
        if self.real_api_handler is None:
            self.set_status(404)
            self.write('404 Not Found')
        else:
            handler = self.real_api_handler(self)
            if not hasattr(handler, 'post'):
                self.set_status(405)
                self.write('405 Method Not Allowed')
            else:
                yield handler.post(*args, **kwargs)
