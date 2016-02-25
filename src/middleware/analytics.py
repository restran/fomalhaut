#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals, absolute_import

import time
from gridfs.errors import FileExists
from middleware.exceptions import *
from middleware import BaseMiddleware
from tornado import gen
import motor
from cStringIO import StringIO
import hashlib

logger = logging.getLogger(__name__)


class ResultCode(object):
    """
    响应结果的编码
    """
    # 访问正常
    OK = 200
    # 请求的参数不完整
    BAD_REQUEST = 400
    # 鉴权失败,禁止访问
    BAD_AUTH_REQUEST = 403
    # 服务器处理发生异常
    INTERNAL_SERVER_ERROR = 500
    # 访问 endpoint server 出现错误
    REQUEST_ENDPOINT_ERROR = 502
    # client 缺少配置,或配置有误
    CLIENT_CONFIG_ERROR = 503


class HTTPData(object):
    content_type = ''
    headers = None
    body = None
    headers_id = None
    body_id = None

    def get_json(self):
        j = {
            'content_type': self.content_type,
            'headers_id': self.headers_id,
            'body_id': self.body_id
        }
        return j

    @gen.coroutine
    def save(self, db, data_type):
        if self.headers is not None:
            header_list = []
            for k, v in self.headers.get_all():
                header_list.append('%s: %s' % (k, v))

            self.headers_id = yield self.write_file(
                db, '%s_%s' % (data_type, 'headers'), '\n'.join(header_list),
                'text/plain', True)

        if self.body is not None:
            self.body_id = yield self.write_file(
                db, '%s_%s' % (data_type, 'body'), self.body,
                self.content_type, True)

    @gen.coroutine
    def write_file(self, db, collection, data, content_type='', hash_id=False):
        fs = motor.motor_tornado.MotorGridFS(db, collection=collection)
        content = StringIO(data)
        if not hash_id:
            _id = yield fs.put(content, content_type=content_type)
        else:
            _id = hashlib.sha1(content.getvalue()).hexdigest()
            exists = yield fs.exists(_id=_id)
            if not exists:
                try:
                    yield fs.put(content, content_type=content_type, _id=_id)
                except FileExists:
                    pass

            yield db['ref_%s' % collection].update({'_id': _id}, {'$inc': {'count': 1}}, upsert=True)

        gen.Return(_id)


class AnalyticsData(object):
    """
    统计数据
    """
    remote_ip = ''
    request_uri = ''
    encrypt_type = 'raw'
    builtin_endpoint = False
    client_id = None
    client_name = ''
    # 请求的 api 名称
    endpoint_name = ''
    endpoint_id = None
    version = ''
    forward_url = ''
    method = ''
    # 访问时间戳,精确到毫秒
    timestamp = None
    # 访问耗时
    elapsed = None
    # 返回结果的状态码
    status_code = None
    # API 访问结果代码
    result_code = None
    result_msg = ''
    request = HTTPData()
    response = HTTPData()

    def get_json(self):
        json_data = {
            'remote_ip': self.remote_ip,
            'request_uri': self.request_uri,
            'client_id': self.client_id,
            'client_name': self.client_name,
            'endpoint_name': self.endpoint_name,
            'endpoint_id': self.endpoint_id,
            'builtin_endpoint': self.builtin_endpoint,
            'version': self.version,
            'forward_url': self.forward_url,
            'method': self.method,
            'timestamp': self.timestamp,
            'elapsed': self.elapsed,
            'status_code': self.status_code,
            'result_code': self.result_code,
            'result_msg': self.result_msg,
            'request': self.request.get_json(),
            'response': self.response.get_json(),
        }

        return json_data

    @gen.coroutine
    def save(self, database):
        logger.debug(type(self.request.headers))

        yield self.request.save(database, 'request')
        yield self.response.save(database, 'response')
        future = yield database.access_log.insert(self.get_json())
        logger.debug(future)


class AnalyticsHandler(BaseMiddleware):
    """
    处理访问统计
    """

    def process_request(self):
        """
        请求开始
        :return:
        """
        logger.debug('process_request')
        request = self.handler.request
        analytics = self.handler.analytics
        x_real_ip = request.headers.get('X-Real-Ip')
        remote_ip = request.remote_ip if not x_real_ip else x_real_ip
        analytics.remote_ip = remote_ip
        analytics.request_uri = request.uri
        analytics.method = request.method
        analytics.timestamp = int(time.time() * 1000)
        analytics.request.content_type = request.headers.get('Content-Type', '')
        analytics.request.headers = request.headers
        analytics.request.body = request.body

    @gen.coroutine
    def process_finished(self):
        """
        结果已经返回,处理访问日志
        :return:
        """
        logger.debug('process_finished')
        analytics = self.handler.analytics
        analytics.status_code = self.handler.get_status()
        now_ts = int(time.time() * 1000)
        analytics.elapsed = now_ts - analytics.timestamp

        client = self.handler.client
        # 如果 client 为空表示未能通过 HMAC 签名鉴权
        if client is not None:
            analytics.client_name = client.config.get('name')
            analytics.client_id = client.config.get('id')
            endpoint = client.request.get('endpoint', {})
            analytics.endpoint_name = endpoint.get('name')
            analytics.endpoint_id = endpoint.get('id')
            analytics.version = endpoint.get('version')
            analytics.builtin_endpoint = endpoint.get('builtin_endpoint', False)
            analytics.forward_url = client.request.get('forward_url')
            response = self.handler.endpoint_response
            analytics.response.content_type = response.headers.get('Content-Type', '')
            analytics.response.headers = response.headers
            analytics.response.body = response.body

        db = self.handler.settings['db']
        # 将统计数据存储在 MongoDB 中
        yield analytics.save(db)
