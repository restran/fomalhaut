#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals

import logging
import traceback

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.gen
import tornado.httpclient
from tornado.httputil import HTTPHeaders
from tornado.httpclient import HTTPRequest
from tornado.curl_httpclient import CurlAsyncHTTPClient as AsyncHTTPClient

from tornado import gen

from middleware.analytics import ResultCode
from utils import text_type
import settings
from handlers.base import BaseHandler

logger = logging.getLogger(__name__)


class BackendAPIHandler(BaseHandler):
    """
    处理代理请求
    """

    @gen.coroutine
    def get(self):
        logger.debug('get')
        yield self._do_fetch('GET')

    @gen.coroutine
    def post(self):
        logger.debug('post')
        yield self._do_fetch('POST')

    def _clean_headers(self):
        """
        清理headers中不需要的部分，以及替换值
        :return:
        """
        headers = self.request.headers
        # 更新host字段为后端访问网站的host
        headers['Host'] = self.client.request['endpoint']['netloc']
        new_headers = HTTPHeaders()
        # 如果 header 有的是 str，有的是 unicode
        # 会出现 422 错误
        for name, value in headers.get_all():
            # 过滤 x-api 开头的,这些只是发给 api-gateway
            l_name = name.lower()
            if l_name.startswith('x-api-') and l_name != 'x-api-user-json':
                pass
            # 不需要提供 Content-Length, 自动计算
            # 如果 Content-Length 不正确, 请求后端网站会出错,
            # 太大会出现超时问题, 太小会出现内容被截断
            elif l_name == 'content-length':
                pass
            else:
                new_headers.add(text_type(name), text_type(value))

        return new_headers

    @gen.coroutine
    def _do_fetch(self, method):
        forward_url = self.client.request['forward_url']
        # TODO 执行了 AES 加密请求后, 这里的 forward_url 就为 None
        logger.debug('请求的后端网站 %s' % forward_url)
        logger.debug('原始的 headers %s' % self.request.headers)
        # 清理和处理一下 header
        headers = self._clean_headers()
        logger.debug('修改后的 headers %s' % headers)

        try:
            if method == 'GET':
                # GET 方法 Body 必须为 None，否则会出现异常
                body = None
            else:
                body = self.request.body

            # 设置超时时间
            async_http_connect_timeout = self.client.config.get(
                'async_http_connect_timeout',
                settings.ASYNC_HTTP_CONNECT_TIMEOUT)
            async_http_request_timeout = self.client.config.get(
                'async_http_request_timeout',
                settings.ASYNC_HTTP_REQUEST_TIMEOUT)

            response = yield AsyncHTTPClient().fetch(
                HTTPRequest(url=forward_url,
                            method=method,
                            body=body,
                            headers=headers,
                            decompress_response=True,
                            connect_timeout=async_http_connect_timeout,
                            request_timeout=async_http_request_timeout,
                            follow_redirects=False))
            self._on_proxy(response)
        except tornado.httpclient.HTTPError as x:
            if hasattr(x, 'response') and x.response:
                self._on_proxy(x.response)
            else:
                self.analytics.result_code = ResultCode.REQUEST_ENDPOINT_ERROR
                logger.error(u'proxy failed for %s, error: %s' % (forward_url, x))
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            self.analytics.result_code = ResultCode.REQUEST_ENDPOINT_ERROR

    def _on_proxy(self, response):
        forward_url = self.client.request['forward_url']
        if response.error and not isinstance(
                response.error, tornado.httpclient.HTTPError):
            self.analytics.result_code = ResultCode.REQUEST_ENDPOINT_ERROR
            logger.error(u'proxy failed for %s, error: %s' % (forward_url, response.error))
            return

        try:
            # 如果response.code是非w3c标准的，而是使用了自定义，就必须设置reason，
            # 否则会出现unknown status code的异常
            self.set_status(response.code, response.reason)
        except ValueError:
            self.set_status(response.code, 'Unknown Status Code')
            logger.warning('proxy %s encounters unknown status code,  %s' % (forward_url, response.code))

        # 这里要用 get_all 因为要按顺序
        for (k, v) in response.headers.get_all():
            # 隐藏后端网站真实服务器名称
            if k == 'Server' or k == 'X-Powered-By':
                pass
            elif k == 'Transfer-Encoding' and v.lower() == 'chunked':
                # 如果设置了分块传输编码，但是实际上代理这边已经完整接收数据
                # 到了浏览器端会导致(failed)net::ERR_INVALID_CHUNKED_ENCODING
                pass
            elif k == 'Location':
                # API不存在304跳转,过滤Location
                pass
            elif k == 'Content-Length':
                # 代理传输过程如果采用了压缩，会导致remote传递过来的content-length与实际大小不符
                # 会导致后面self.write(response.body)出现错误
                # 可以不设置remote headers的content-length
                # "Tried to write more data than Content-Length")
                # HTTPOutputError: Tried to write more data than Content-Length
                pass
            elif k == 'Content-Encoding':
                # 采用什么编码传给请求的客户端是由Server所在的HTTP服务器处理的
                pass
            elif k == 'Set-Cookie':
                # Set-Cookie是可以有多个，需要一个个添加，不能覆盖掉旧的
                # 理论上不存在 Set-Cookie,可以过滤
                self.add_header(k, v)
            else:
                self.set_header(k, v)

        logger.debug("local response headers: %s" % self._headers)
        # 更新返回的 headers
        response.headers = self._headers
        # 这里不直接 write,等到最后要finish的时候才write
        # 因为在上一级的中间件中会对数据重新处理,比如加密
        self.write(response.body)
        self.analytics.result_code = ResultCode.OK
        logger.info('proxy success for %s' % forward_url)
