#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21
from __future__ import unicode_literals, absolute_import

import time
import logging
import hmac
from hashlib import sha256
import re
import settings
from middleware.exceptions import *
from utils import RedisHelper, get_utf8_value, text_type
from urlparse import urlparse, urlunparse
from middleware import BaseMiddleware
from datetime import datetime

logger = logging.getLogger(__name__)


class ResultCode(object):
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


class AnalyticsData(object):
    remote_ip = ''
    request_uri = ''

    client_id = None
    client_name = ''
    # 请求的 api 名称
    endpoint_name = ''
    endpoint_id = None
    uri_prefix = ''
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

    def get_json(self):
        json_data = {
            'remote_ip': self.remote_ip,
            'request_uri': self.request_uri,
            'client_id': self.client_id,
            'client_name': self.client_name,
            'endpoint_name': self.endpoint_name,
            'endpoint_id': self.endpoint_id,
            'uri_prefix': self.uri_prefix,
            'forward_url': self.forward_url,
            'method': self.method,
            'timestamp': self.timestamp,
            'elapsed': self.elapsed,
            'status_code': self.status_code,
            'result_code': self.result_code,
            'result_msg': self.result_msg
        }

        return json_data


class AnalyticsHandler(BaseMiddleware):
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
        # 如果 client 为空表示未能通过鉴权
        if client is not None:
            analytics.client_name = client.config.get('name')
            analytics.client_id = client.config.get('id')
            endpoint = client.request.get('endpoint', {})
            analytics.endpoint_name = endpoint.get('name')
            analytics.endpoint_id = endpoint.get('id')
            analytics.uri_prefix = endpoint.get('uri_prefix')
            analytics.forward_url = client.request.get('forward_url')

        logger.debug(analytics.get_json())
