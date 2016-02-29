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
    def __init__(self):
        self.content_type = ''
        self.headers = None
        self.body = None
        self.headers_id = None
        self.body_id = None

    def get_json(self):
        j = {
            'content_type': self.content_type,
            'headers_id': self.headers_id,
            'body_id': self.body_id
        }
        logger.debug(j)
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
            logger.debug(self.headers_id)

        if self.body is not None:
            self.body_id = yield self.write_file(
                db, '%s_%s' % (data_type, 'body'), self.body,
                self.content_type, True)
            logger.debug(self.body_id)

    @gen.coroutine
    def write_file(self, db, collection, data, content_type='', hash_id=False):
        fs = motor.motor_tornado.MotorGridFS(db, collection=collection)
        content = StringIO(data)
        if not hash_id:
            _id = yield fs.put(content, content_type=content_type)
            logger.debug(_id)
        else:
            _id = hashlib.sha1(content.getvalue()).hexdigest()
            exists = yield fs.exists(_id=_id)
            if not exists:
                try:
                    yield fs.put(content, content_type=content_type, _id=_id)
                except FileExists:
                    pass

            yield db['ref_%s' % collection].update({'_id': _id}, {'$inc': {'count': 1}}, upsert=True)

        raise gen.Return(_id)


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
        self.remote_ip = ''
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
        self.timestamp = None
        # 访问耗时
        self.elapsed = None
        # 返回结果的状态码
        self.status_code = None
        # API 访问结果代码
        self.result_code = None
        self.result_msg = ''
        self.request = HTTPRequestData()
        self.response = HTTPResponseData()

    def get_json(self):
        json_data = {
            'remote_ip': self.remote_ip,
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
            'timestamp': self.timestamp,
            'elapsed': self.elapsed,
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
        analytics.request.uri = request.uri
        analytics.timestamp = int(time.time() * 1000)
        analytics.request.method = request.method
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
        analytics.response.status = self.handler.get_status()
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
            analytics.is_builtin = endpoint.get('is_builtin', False)
            analytics.forward_url = client.request.get('forward_url')
            response = self.handler.endpoint_response
            analytics.response.content_type = response.headers.get('Content-Type', '')
            analytics.response.headers = response.headers
            analytics.response.body = response.body

        db = self.handler.settings['db']
        # 将统计数据存储在 MongoDB 中
        yield analytics.save(db)
