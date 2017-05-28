#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals, absolute_import

import time
from base64 import b64encode

from tornado.concurrent import run_on_executor
from tornado.ioloop import IOLoop

from ..middleware.base import BaseMiddleware, ResultCode
from ..settings import *
from ..utils import RedisHelper, thread_pool_executor, \
    utf8, to_unicode, UniqueId, json_dumps

logger = logging.getLogger(__name__)


class HTTPData(object):
    def __init__(self):
        self.content_type = ''
        self.headers = None
        self.body = None

    def get_json(self):
        j = {
            'content_type': to_unicode(self.content_type),
            'headers': '',
            'body': ''
        }

        headers_dict = {} if self.headers is None else self.headers.get_all()
        header_content = '\n'.join(['%s: %s' % (k, v) for k, v in headers_dict])

        # 内容过长, 截断
        if len(header_content) > ACCESS_LOG_HEADERS_MAX_LENGTH:
            header_content = header_content[:ACCESS_LOG_HEADERS_MAX_LENGTH]

        j['headers'] = to_unicode(b64encode(utf8(header_content)))

        if self.body is not None and len(self.body) > 0:
            # 内容过长, 截断
            if len(self.body) > ACCESS_LOG_BODY_MAX_LENGTH:
                body_content = self.body[:ACCESS_LOG_BODY_MAX_LENGTH]
            else:
                body_content = self.body
        else:
            body_content = ''

        try:
            j['body'] = to_unicode(b64encode(utf8(body_content)))
        except Exception as e:
            j['body'] = ''
            logger.error(e)

        return j


class HTTPRequestData(HTTPData):
    """
    request 数据
    """

    def __init__(self):
        super(HTTPRequestData, self).__init__()
        self.uri = None
        self.method = None

    def get_json(self):
        j = super(HTTPRequestData, self).get_json()
        j['method'] = self.method
        j['uri'] = self.uri
        return j


class HTTPResponseData(HTTPData):
    """
    response 数据
    """

    def __init__(self):
        super(HTTPResponseData, self).__init__()
        self.status = None

    def get_json(self):
        j = super(HTTPResponseData, self).get_json()
        j['status'] = self.status
        return j


class AnalyticsData(object):
    """
    统计数据
    """

    def __init__(self):
        self.ip = ''
        self.request_uri = ''
        self.encrypt_type = 'raw'
        self.is_builtin = False
        self.client_id = None
        self.client_name = ''
        # 请求的 api 名称
        self.endpoint_name = ''
        self.endpoint_id = None
        self.version = ''
        self.forward_url = ''
        # 访问时间戳,精确到毫秒
        self.timestamp = int(time.time() * 1000)
        # 访问耗时
        self.elapsed = None
        # 返回结果的状态码
        self.status_code = 200
        # API 访问结果代码
        self.result_code = ResultCode.OK
        self.result_msg = ''
        self.request = HTTPRequestData()
        self.response = HTTPResponseData()

    def get_json(self):
        return {
            'ip': self.ip,
            'client': {
                'id': self.client_id,
                'name': self.client_name,
            },
            'endpoint': {
                'id': self.endpoint_id,
                'name': self.endpoint_name,
                'version': self.version,
                'is_builtin': self.is_builtin,
            },
            'forward_url': self.forward_url,
            'elapsed': self.elapsed,
            'result_code': self.result_code,
            'result_msg': self.result_msg,
            'request': self.request.get_json(),
            'response': self.response.get_json(),
            'accessed_at': self.timestamp
        }

    def save_to_redis(self):
        r = RedisHelper.get_client()
        access_log = json_dumps(self.get_json())
        key = '%s:%s' % (ANALYTICS_LOG_REDIS_PREFIX, UniqueId.new_object_id())
        # 数据存储在 key value 结构中，并设置过期时间
        r.setex(key, ANALYTICS_LOG_EXPIRE_SECONDS, access_log)
        # 队列里面只存储 key
        r.rpush(ANALYTICS_LOG_REDIS_LIST_KEY, key)


class AnalyticsMiddleware(BaseMiddleware):
    """
    处理访问统计
    """

    def __init__(self, *args, **kwargs):
        self.io_loop = IOLoop.current()
        self.executor = thread_pool_executor
        super(AnalyticsMiddleware, self).__init__(*args, **kwargs)

    def process_request(self):
        """
        请求开始
        :return:
        """
        # logger.debug('process_request')
        request = self.handler.request
        analytics = self.handler.analytics
        x_real_ip = request.headers.get('X-Real-Ip')
        remote_ip = request.remote_ip if not x_real_ip else x_real_ip
        analytics.ip = remote_ip

    def process_response(self, *args, **kwargs):
        """
        在结果返回前, 先记录响应数据
        """
        # logger.debug('process_response')
        response_headers = self.handler.get_response_headers()
        response_body = b''.join(self.handler.get_write_buffer())
        analytics = self.handler.analytics
        analytics.response.content_type = response_headers.get('Content-Type', '')
        analytics.response.headers = response_headers
        analytics.response.body = response_body

    @run_on_executor
    def process_finished(self):
        """
        结果已经返回, 处理访问日志
        :return:
        """
        # logger.debug('process_finished')
        analytics = self.handler.analytics
        analytics.response.status = self.handler.get_status()
        now_ts = int(time.time() * 1000)
        analytics.elapsed = now_ts - analytics.timestamp

        # 如果使用了 AES 加密, 那么在 process_request 阶段获取到的只是加密后的数据
        request = self.handler.request
        analytics.request.uri = request.uri
        analytics.request.method = request.method
        analytics.request.content_type = request.headers.get('Content-Type', '')
        analytics.request.headers = request.headers
        analytics.request.body = request.body

        client = self.handler.client
        if client is not None:
            analytics.client_name = client.config.name
            analytics.client_id = client.config.id
            analytics.forward_url = client.request.forward_url
            endpoint = client.request.endpoint
            if endpoint is not None:
                analytics.endpoint_name = endpoint.get('name')
                analytics.endpoint_id = endpoint.get('id')
                analytics.version = endpoint.get('version')
                analytics.is_builtin = endpoint.get('is_builtin', False)

        # db = self.handler.settings['db']
        # 将统计数据存储在 MongoDB 中, 性能较差
        # yield analytics.save(db)

        # 日志先临时保存到 redis 中
        analytics.save_to_redis()
