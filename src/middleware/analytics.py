#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals, absolute_import

import time
from settings import ACCESS_LOG_BODY_MAX_LENGTH, ACCESS_LOG_HEADERS_MAX_LENGTH
from middleware.exceptions import *
from middleware import BaseMiddleware
from tornado import gen
import motor
import hashlib
from utils import utf8, BytesIO
from datetime import datetime

logger = logging.getLogger(__name__)


class ResultCode(object):
    """
    响应结果的编码
    """
    # 成功
    OK = 200
    # 请求的参数不完整
    BAD_REQUEST = 400
    # 登录验证失败
    BAD_ACCESS_TOKEN = 401
    # HMAC 鉴权失败,禁止访问
    BAD_AUTH_REQUEST = 403
    # 服务器处理发生异常
    INTERNAL_SERVER_ERROR = 500
    # 访问 endpoint server 出现错误, 服务不可用
    REQUEST_ENDPOINT_ERROR = 503
    # client 缺少配置,或配置有误
    CLIENT_CONFIG_ERROR = 510


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
            'headers': self.headers_id,
            'body': self.body_id
        }
        logger.debug(j)
        return j

    @gen.coroutine
    def save(self, db, data_type):
        if self.headers is not None:
            header_list = []
            for k, v in self.headers.get_all():
                header_list.append('%s: %s' % (k, v))
            content = '\n'.join(header_list)
            if content == '':
                self.headers_id = None
            else:
                # 内容过长, 截断
                if len(content) > ACCESS_LOG_HEADERS_MAX_LENGTH:
                    content = content[:ACCESS_LOG_HEADERS_MAX_LENGTH]

                self.headers_id = yield self.write_file(
                    db, '%s_%s' % (data_type, 'headers'), content,
                    'text/plain', True)
                logger.debug(self.headers_id)

        if self.body is not None and len(self.body) > 0:
            # 内容过长, 截断
            if len(self.body) > ACCESS_LOG_BODY_MAX_LENGTH:
                content = self.body[:ACCESS_LOG_BODY_MAX_LENGTH]
            else:
                content = self.body

            self.body_id = yield self.write_file(
                db, '%s_%s' % (data_type, 'body'), content,
                self.content_type, True)
            logger.debug(self.body_id)

    @gen.coroutine
    def write_file(self, db, collection, data, content_type='', hash_id=False):
        fs = motor.motor_tornado.MotorGridFS(db, collection=collection)
        content = BytesIO(utf8(data))
        if not hash_id:
            _id = yield fs.put(content, content_type=content_type)
            logger.debug(_id)
        else:
            # TODO md5 may not safe to check content unique
            md5 = hashlib.md5(content.getvalue()).hexdigest()
            # file_name = hashlib.sha1(content.getvalue()).digest().encode("base64").rstrip('\n')
            grid_out = yield fs.find_one({'md5': md5})
            if not grid_out:
                _id = yield fs.put(content, content_type=content_type)
            else:
                _id = grid_out._id

            # 直接让引用计数的 _id 等于 file 的 _id
            logger.debug(_id)
            logger.debug(collection)
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
        self.status_code = None
        # API 访问结果代码
        self.result_code = None
        self.result_msg = ''
        self.request = HTTPRequestData()
        self.response = HTTPResponseData()

    def get_json(self):
        json_data = {
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
            'accessed_at': datetime.fromtimestamp(self.timestamp / 1000.0),
            'elapsed': self.elapsed,
            'result_code': self.result_code,
            'result_msg': self.result_msg,
            'request': self.request.get_json(),
            'response': self.response.get_json(),
        }

        return json_data

    @gen.coroutine
    def save(self, database):
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
        analytics.ip = remote_ip

    def process_response(self, *args, **kwargs):
        """
        在结果返回前, 先记录响应数据
        """
        logger.debug('process_response')
        response_headers = self.handler.get_response_headers()
        response_body = b''.join(self.handler.get_write_buffer())
        analytics = self.handler.analytics
        analytics.response.content_type = response_headers.get('Content-Type', '')
        analytics.response.headers = response_headers
        analytics.response.body = response_body

    @gen.coroutine
    def process_finished(self):
        """
        结果已经返回, 处理访问日志
        :return:
        """
        logger.debug('process_finished')
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
            analytics.client_name = client.config.get('name')
            analytics.client_id = client.config.get('id')
            endpoint = client.request.get('endpoint', {})
            analytics.endpoint_name = endpoint.get('name')
            analytics.endpoint_id = endpoint.get('id')
            analytics.version = endpoint.get('version')
            analytics.is_builtin = endpoint.get('is_builtin', False)
            analytics.forward_url = client.request.get('forward_url')

        db = self.handler.settings['db']
        # 将统计数据存储在 MongoDB 中
        yield analytics.save(db)
