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
from tornado.web import HTTPError
from middleware.analytics import AnalyticsData
from utils import text_type, copy_list

logger = logging.getLogger(__name__)

_REQUEST, _RESPONSE, _FINISHED = 0, 1, 2


class BaseHandler(RequestHandler):
    _call_mapper = {
        _REQUEST: ('request_middleware', 'process_request'),
        _RESPONSE: ('response_middleware', 'process_response'),
        _FINISHED: ('finished_middleware', 'process_finished'),
    }

    def __init__(self, application, request, **kwargs):
        super(BaseHandler, self).__init__(application, request, **kwargs)
        logger.debug('base init')

        # 请求 client 的相关信息
        self.client = None
        self.analytics = AnalyticsData()
        self.endpoint_response = None

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

    def clear_nested_middleware(self, mw_class):
        """
        清除该中间件下级的所有中间件
        :param mw_class:
        :return:
        """
        # TODO 清理中间件,必须按照settings中配置的顺序来遍历,不能单独为每个列表遍历
        
        logger.debug('clear_nested_middleware!!!')
        for i, m in enumerate(self.request_middleware):
            if mw_class == m:
                logger.debug('----hit----')
                self.request_middleware = \
                    self.request_middleware[i + 1:]
                break

        # response_middleware 和 finished_middleware
        for i, m in enumerate(self.response_middleware):
            if mw_class == m:
                logger.debug('----hit----')
                self.response_middleware = self.response_middleware[:i]
                logger.debug(self.response_middleware)
                break

        for i, m in enumerate(self.finished_middleware):
            if mw_class == m:
                logger.debug('----hit----')
                self.finished_middleware = self.finished_middleware[:i]
                break

        logger.debug(self.request_middleware)
        logger.debug(self.response_middleware)
        logger.debug(self.finished_middleware)

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

        ex = kwargs['exc_info'][1]
        # any 表示只要有一个为 true 就可以
        if any(isinstance(ex, c) for c in
               [ClientErrorException, ServerErrorException]):
            logger.debug('api exception')
            # 根据异常,设置相应的 result_code
            if isinstance(ex, AuthRequestException):
                self.analytics.result_code = ResultCode.BAD_AUTH_REQUEST
            elif isinstance(ex, ClientBadConfigException):
                self.analytics.result_code = ResultCode.CLIENT_CONFIG_ERROR
            elif self.analytics.result_code is None:
                self.analytics.result_code = ResultCode.INTERNAL_SERVER_ERROR

            self.write('%s %s' % (status_code, get_exc_message(ex)))
        else:
            self.analytics.result_code = ResultCode.INTERNAL_SERVER_ERROR
            self.write('500 Internal Error')

        if not self._finished:
            self.finish()

    @gen.coroutine
    def execute_next(self, request, mv_type, handler, *args, **kwargs):
        middleware = self._call_mapper.get(mv_type)
        if not middleware:
            return

        classes = getattr(self, middleware[0], [])
        logger.debug(classes)
        for c in classes:
            instance = c(handler)
            m = getattr(instance, middleware[1])
            if m and callable(m):
                try:
                    result = m(*args, **kwargs)
                    if is_future(result):
                        yield result
                except Exception as e:
                    logger.error(e)
                    logger.error(traceback.format_exc())
                    # 在某一层的中间件出现异常,下一级的都不执行
                    self.clear_nested_middleware(c)
                    # 如果在 request 阶段就出现了异常,直接进入 finish
                    if mv_type == _REQUEST and not self._finished:
                        status_code = getattr(e, 'status_code', 500)
                        self.write_error(status_code, exc_info=sys.exc_info())
                    # 不再往下执行
                    break

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
        # finish之前可能执行过多次write，反而chunk可能为None
        # 真正的chunk数据在self._write_buffer中，包含历次write的数据
        # 这里将chunk数据write进_write_buffer中，然后将chunk置空
        if chunk:
            self.write(chunk)
            chunk = None
        yield self._process_response(self, self._write_buffer)

        # 等到最后才 write endpoint 返回的数据
        if self.endpoint_response is not None:
            self.write(self.endpoint_response.body)

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
