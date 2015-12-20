#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals

import time
import hashlib
import hmac
import tornado.gen
from tornado.httpclient import HTTPRequest
from utils import AESHelper, ACLFilter
import settings
from session import SessionBaseHandler
from utils import encoded_dict, RedisHelper
import json
from datetime import datetime
import base64
import urllib
import six
from six import text_type
import traceback
from urlparse import urlparse, urlunparse
import logging
from tornado.web import HTTPError
from tornado import gen
import random

logger = logging.getLogger(__name__)


class RequestToken(object):
    """
    用来检查TokenGenerator生成的令牌的正确性
    """

    def __init__(self, _access_key, _secret_key,
                 _server_url, _site_name, *args, **kwargs):
        self.access_key = _access_key
        self.secret_key = _secret_key
        self.server_url = _server_url
        self.site_name = _site_name

    def make_token(self):
        token = self._make_token_with_timestamp(self._timestamp())
        return token

    def check_token(self, token):
        """
        检查鉴权令牌
        :param token:
        :return: 令牌是否有效，令牌是否过期
        """
        # logger.debug('request token %s' % token)
        try:
            ts, hash_value = token.split("|")
        except ValueError:
            return False, True

        try:
            ts = int(ts)
        except ValueError:
            return False, True

        if self._make_token_with_timestamp(ts) != token:
            return False, True

        # 判断是否在有效期内
        # timestamp是以秒为单位
        if abs(self._timestamp() - ts) > settings.TOKEN_EXPIRES_SECONDS:
            return True, True

        return True, False

    def _make_token_with_timestamp(self, timestamp):
        ts = str(timestamp)
        hmac_256 = hmac.new(self.secret_key.encode(), digestmod=hashlib.sha256)
        to_signed_data = self._get_utf8_value('\n'.join(
            [self.server_url, self.site_name, self.access_key, ts]))

        hmac_256.update(to_signed_data)
        hash_value = hmac_256.hexdigest()
        return "%s|%s" % (ts, hash_value)

    @staticmethod
    def _get_utf8_value(value):
        """Get the UTF8-encoded version of a value."""
        if not isinstance(value, str) and not isinstance(value, unicode):
            value = str(value)
        if isinstance(value, unicode):
            return value.encode('utf-8')
        else:
            return value

    @staticmethod
    def _timestamp():
        # 返回时间戳
        # 时间戳类型:自1970年1月1日(00:00:00 GMT)以来的秒数
        return int(time.time())


class ResponseSignature(object):
    """
    响应结果签名
    """

    def __init__(self, _access_key, _secret_key,
                 _uri, _encrypt_type, _nonce, _timestamp, *args, **kwargs):
        self.access_key = _access_key
        self.secret_key = _secret_key
        self.uri = _uri
        self.encrypt_type = _encrypt_type
        self.nonce = _nonce
        self.timestamp = _timestamp

    def make_signature(self):
        sign = self._make_sign_with_timestamp(self.timestamp)
        return sign

    def check_signature(self, signature):
        """
        检查鉴权令牌
        :param signature:
        :return: 签名是否有效，签名是否过期
        """
        if self._make_sign_with_timestamp(self.timestamp) != signature:
            return False, True

        # 判断是否在有效期内
        # timestamp是以秒为单位
        if (ResponseSignature.now_timestamp() - int(self.timestamp)) > settings.TOKEN_EXPIRES_SECONDS:
            return True, True

        return True, False

    def _make_sign_with_timestamp(self, timestamp):
        """
        生成签名
        :param timestamp:
        :return:
        """
        ts = str(timestamp)
        params_dict = {
            settings.HEADER_X_ACCESS_KEY: self.access_key,
            settings.HEADER_X_ENCRYPT_TYPE: self.encrypt_type,
            settings.R_HEADER_X_Timestamp: ts,
            settings.R_HEADER_X_Nonce: self.nonce,
            # 这个参数不返回
            'X-Uri': self.uri
        }
        # 按照参数名称的字典排序
        sorted_list = sorted(params_dict.items(), key=lambda e: e[0])
        sorted_list = [t[1] if t[1] is not None else '' for t in sorted_list]
        to_signed_data = self._get_utf8_value('\n'.join(sorted_list))
        hmac_256 = hmac.new(self.secret_key.encode(), digestmod=hashlib.sha256)
        hmac_256.update(to_signed_data)
        signature = hmac_256.hexdigest()
        return signature

    @staticmethod
    def _get_utf8_value(value):
        """Get the UTF8-encoded version of a value."""
        if not isinstance(value, str) and not isinstance(value, unicode):
            value = str(value)
        if isinstance(value, unicode):
            return value.encode('utf-8')
        else:
            return value

    @staticmethod
    def now_timestamp():
        # 返回时间戳
        # 时间戳类型:自1970年1月1日(00:00:00 GMT)以来的秒数
        return int(time.time())


class RequestAuth(object):
    # def process_init(self, application):
    #     self._cachestore = caches[settings.SESSION.session_cache_alias]

    def process_request(self, handler):
        logger.debug('process_request')

    # def _get_auth_required_params(self):
    #     """
    #     从cookie、header和查询参数中获取鉴权需要用到的信息
    #     :return:
    #     """
    #     # 自定义字段，用来授权登录
    #     auth_token = self.request.headers.get(settings.HEADER_X_AUTH_TOKEN)
    #     access_key = self.request.headers.get(settings.HEADER_X_ACCESS_KEY)
    #     site_name = self.request.headers.get(settings.HEADER_X_SITE)
    #
    #     # 设置 token 是在 header 中，还是 cookie 中
    #     # 如果是在 cookie 中，则是属于页面内的引用文件的请求，或者 ajax 请求
    #     self._log_data['header_token'] = True if auth_token else False
    #
    #     logger.debug('%s, %s, %s' % (site_name, auth_token, access_key))
    #
    #     # 如果header中没有，就从cookie中查找
    #     if site_name is None:
    #         # 不使用get_secure_cookie，否则tornado_proxy无法识别出site_name
    #         site_name = self.get_cookie(settings.COOKIE_X_SITE)
    #         logger.debug('cookie site_name: %s' % site_name)
    #
    #     if auth_token is None:
    #         auth_token = self.get_secure_cookie(
    #             settings.COOKIE_X_AUTH_TOKEN,
    #             max_age_days=settings.COOKIE_EXPIRES_DAYS)
    #         logger.debug('cookie auth_token: %s' % auth_token)
    #
    #     if access_key is None:
    #         access_key = self.get_secure_cookie(
    #             settings.COOKIE_X_ACCESS_KEY,
    #             max_age_days=settings.COOKIE_EXPIRES_DAYS)
    #         logger.debug('cookie access_key: %s' % access_key)
    #
    #     # 从查询参数中获取
    #     if site_name is None:
    #         site_name = self.get_query_argument(settings.COOKIE_X_SITE, default=None)
    #         logger.debug('query_argument site_name: %s' % site_name)
    #
    #     if auth_token is None:
    #         auth_token = self.get_query_argument(
    #             settings.COOKIE_X_AUTH_TOKEN, default=None)
    #         # 如果鉴权令牌是在查询参数中，也认为是页面访问，所以设置header_token
    #         self._log_data['header_token'] = True if auth_token else False
    #         logger.debug('query_argument auth_token: %s' % auth_token)
    #
    #     if access_key is None:
    #         access_key = self.get_query_argument(
    #             settings.COOKIE_X_ACCESS_KEY, default=None)
    #         logger.debug('query_argument access_key: %s' % access_key)
    #
    #     return site_name, auth_token, access_key

    # def check_access_agent(self):
    #     """
    #     对访问请求进行授权认证，判断是否可以访问
    #     """
    #     logger.debug('auth_request')
    #
    #     site_name, auth_token, access_key = self._get_auth_required_params()
    #     logger.debug('%s, %s, %s' % (site_name, auth_token, access_key))
    #     if not site_name or not access_key or not auth_token:
    #         # 无法通过验证
    #         logger.warning('auth failed, insufficient auth params')
    #         logger.warning('请求的uri: %s' % self.request.uri)
    #         logger.warning('site_name:%s, access_key:%s, auth_token：%s' %
    #                        (site_name, access_key, auth_token))
    #
    #         # 这里是屏蔽未授权访问的
    #         return False
    #
    #     self._access_key = access_key
    #     self._auth_token = auth_token
    #
    #     # 授权成功之后，就不需要把 headers 中的授权认证信息传到后端网站
    #     map(lambda s: self.request.headers.pop(s) if s in self.request.headers else None,
    #         ['X-Site', 'X-Access-Key', 'X-Authorization'])
    #
    #     # 注意：X-AccessKey 设置后会变成 X-Accesskey
    #     # headers['X-Access-Key'] = access_key
    #     self._site_name = site_name
    #     # 确定访问的来源，例如是某个APP
    #     self._access_agent = self.redis_helper.get_app_config(self._access_key)
    #     # 如果禁用了，则禁止访问
    #     if self._access_agent is None or not self._access_agent.get('enable', False):
    #         return False
    #     self._secret_key = self._access_agent.get('secret_key', '')
    #     return True

    def process_response(self, handler, chunk):
        logger.debug('process_response')
