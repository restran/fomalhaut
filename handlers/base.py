#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals

import logging
import traceback
import sys

from tornado.web import RequestHandler
from tornado.concurrent import is_future
from tornado import gen
from tornado.web import HTTPError
from utils import text_type, copy_list

logger = logging.getLogger(__name__)

_REQUEST, _RESPONSE, _FINISHED = 0, 1, 2


class APIException(HTTPError):
    pass


class NoClientConfigException(APIException):
    """
    签名错误,非法的请求
    """


class AuthRequestException(APIException):
    """
    非法请求,签名错误,时间戳过期
    """


class BaseHandler(RequestHandler):
    _call_mapper = {
        _REQUEST: ('request_middleware', 'process_request'),
        _RESPONSE: ('response_middleware', 'process_response'),
        _FINISHED: ('finished_middleware', 'process_response'),
    }

    def __init__(self, application, request, **kwargs):
        super(BaseHandler, self).__init__(application, request, **kwargs)
        logger.debug('base init')

        # 请求 client 的相关信息
        self.client = None

        # 拷贝一份中间件的列表
        self.request_middleware = \
            copy_list(self.application.request_middleware)
        self.response_middleware = \
            copy_list(self.application.response_middleware)
        self.finished_middleware = \
            copy_list(self.application.finished_middleware)

    def clear_all_middleware(self):
        self.request_middleware = []
        self.response_middleware = []
        self.finished_middleware = []

    def write_error(self, status_code, **kwargs):
        """Override of RequestHandler.write_error
        :type  status_code: int
        :param status_code: HTTP status code
        """
        logger.debug('write_error')
        # 出现异常,清理所有的中间件,
        # self.clear_all_middleware()

        def get_exc_message(e):
            return e.log_message if \
                hasattr(e, 'log_message') else text_type(e)

        self.clear()
        self.set_status(status_code)

        exception = kwargs['exc_info'][1]
        # any 表示只要有一个为 true 就可以
        if any(isinstance(exception, c) for c in [HTTPError, APIException]):
            logger.debug('api exception')
            self.write('%s %s' % (status_code, get_exc_message(exception)))
        else:
            self.write('500 Internal Error')

        if not self._finished:
            self.finish()

    @gen.coroutine
    def execute_next(self, request, mv_type, handler, *args, **kwargs):
        try:
            middleware = self._call_mapper.get(mv_type)
            if not middleware:
                return

            classes = getattr(self, middleware[0], [])
            logger.debug(classes)
            for c in classes:
                instance = c(handler)
                m = getattr(instance, middleware[1])
                if m and callable(m):
                    result = m(*args, **kwargs)
                    if is_future(result):
                        yield result
        except gen.Return:
            pass
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error(e)
            # 触发异常后,会自动调用 self.write_error
            # 这里不需要再调用,否则会出现递归调用 self.write_error
            # self.write_error(500, exc_info=sys.exc_info())

    @gen.coroutine
    def _process_request(self, handler):
        yield self.execute_next(handler.request, _REQUEST, handler)

    @gen.coroutine
    def _process_response(self, handler, chunk):
        yield self.execute_next(handler.request, _RESPONSE, handler, chunk)

    @gen.coroutine
    def _process_finished(self, handler):
        yield self.execute_next(handler.request, _FINISHED, handler)

    @gen.coroutine
    def prepare(self):
        super(BaseHandler, self).prepare()

        logger.info('base prepare')
        yield self._process_request(self)

    @gen.coroutine
    def finish(self, chunk=None):
        # finish之前可能执行过多次write，反而chunk可能为None
        # 真正的chunk数据在self._write_buffer中，包含历次write的数据
        # 这里将chunk数据write进_write_buffer中，然后将chunk置空
        if chunk:
            self.write(chunk)
            chunk = None
        yield self._process_response(self, self._write_buffer)
        super(BaseHandler, self).finish(chunk)

    def write(self, chunk, status=None):
        if status:
            self.set_status(status)
        super(BaseHandler, self).write(chunk)

    @gen.coroutine
    def on_finish(self):
        """
        Called after the end of a request.
        :return:
        """
        super(BaseHandler, self).on_finish()
        yield self._process_finished(self)
