#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals, absolute_import

import logging.config
import os

# 当前目录所在路径
BASE_PATH = os.path.abspath(os.path.dirname(__file__))
# 日志所在目录
LOG_PATH = os.path.join(BASE_PATH, 'logs')

HOST = '127.0.0.1'
PORT = 6500
# 是否调试模式
DEBUG = True
# 代码修改时, 是否自动重启
AUTO_RELOAD = True if DEBUG else False

PACKAGE_NAME = 'fomalhaut'

# 中间件会按顺序执行
MIDDLEWARE_CLASSES = [
    'middleware.analytics.AnalyticsMiddleware',
    'middleware.base.PrepareMiddleware',
    'middleware.security.HMACAuthenticateMiddleware',
    'middleware.encrypt.EncryptMiddleware',
    'middleware.endpoint.ParseEndpointMiddleware',
    'middleware.auth.AuthAccessTokenMiddleware',
]

# api-gateway 内置的 API Endpoint
BUILTIN_ENDPOINTS = [
    {
        'config': {
            'name': 'auth',
            'version': 'v1'
        },
        'handlers': [
            (r'^/login/?$', 'handlers.endpoints.auth.Login'),
            (r'^/token/refresh/?$', 'handlers.endpoints.auth.RefreshToken'),
            (r'^/token/alive/?$', 'handlers.endpoints.auth.CheckTokenAlive')
        ]
    },
    {
        'config': {
            'name': 'account',
            'version': 'v1'
        },
        'handlers': [
            (r'^/logout/?$', 'handlers.endpoints.account.Logout'),
            (r'^/password/change/?$', 'handlers.endpoints.account.ChangePassword'),
        ]
    }
]

# 未通过网关鉴权, 或者未能正确请求时返回的状态码
# 通过特殊的状态码, 区分后端 API Server 返回的状态码
GATEWAY_ERROR_STATUS_CODE = 949

# 可以给日志对象设置日志级别，低于该级别的日志消息将会被忽略
# CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET
LOGGING_LEVEL = 'DEBUG' if DEBUG else 'INFO'
LOGGING_HANDLERS = ['console'] if DEBUG else ['file']

DEFAULT_TIMEZONE = 'Asia/Shanghai'

# 访问签名的有效时间，秒
SIGNATURE_EXPIRE_SECONDS = 600

# default zh-Hans
LANGUAGE = 'zh-Hans'

# Redis 配置
# 这里如果使用localhost会导致速度变慢
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = 'secret'

# client 配置 redis 中 key 前缀
CLIENT_CONFIG_REDIS_PREFIX = 'config'
# access_token redis 中 key 前缀
ACCESS_TOKEN_REDIS_PREFIX = 't'
# access_token redis 中 key 前缀
REFRESH_TOKEN_REDIS_PREFIX = 'r'
# redis 中统计分析日志 key 的前缀
ANALYTICS_LOG_REDIS_PREFIX = 'l'
# redis 中统计分析日志列表的 key
ANALYTICS_LOG_REDIS_LIST_KEY = 'logs'
# redis 中统计分析日志有效时间，秒
ANALYTICS_LOG_EXPIRE_SECONDS = 600

# 控制和认证相关的 HEADERS
HEADER_X_PREFIX = 'X-Fo'
# Client 版本号
HEADER_X_VERSION = '%s-Version' % HEADER_X_PREFIX
# 签名值
HEADER_X_SIGNATURE = '%s-Signature' % HEADER_X_PREFIX
# 时间戳
HEADER_X_TIMESTAMP = '%s-Timestamp' % HEADER_X_PREFIX
# App Id
HEADER_X_APP_ID = '%s-App-Id' % HEADER_X_PREFIX
# 数据加密类型，默认为 raw
HEADER_X_ENCRYPT_TYPE = '%s-Encrypt-Type' % HEADER_X_PREFIX
# 随机数
HEADER_X_NONCE = '%s-Nonce' % HEADER_X_PREFIX
# 请求服务端对返回结果签名
HEADER_X_SIGN_RESPONSE = '%s-Sign-Response' % HEADER_X_PREFIX
# AccessToken
HEADER_X_ACCESS_TOKEN = '%s-Access-Token' % HEADER_X_PREFIX
# AES 加密后的 headers
HEADER_X_ENCRYPTED_HEADERS = '%s-Encrypted-Headers' % HEADER_X_PREFIX
# AES 加密后的 uri
HEADER_X_ENCRYPTED_URI = '%s-Encrypted-Uri' % HEADER_X_PREFIX

# 传递给后端API的用户信息，没有加上前缀
HEADER_BACKEND_USER_JSON = 'X-User-Json'
# 没有加上前缀
HEADER_BACKEND_APP_ID = 'X-App-Id'

# 为了避免每次请求都读取一次 redis, 在程序内实现一个缓存
# 超过指定时间就重新读取
CONFIG_CACHE_EXPIRE_SECONDS = 1 * 60
# 分析统计日志，在 redis 中的过期时间
# ANALYTICS_LOG_REDIS_EXPIRE_SECONDS = 30 * 60

# 最大的 headers, 超过的部分会被截断
ACCESS_LOG_HEADERS_MAX_LENGTH = 50 * 1024
# 最大的 body, 超过的部分会被截断
ACCESS_LOG_BODY_MAX_LENGTH = 500 * 1024

# 线程池线程个数
THREAD_POOL_EXECUTOR_WORKER_NUM = 10

# 用来配置 ASYNC_HTTP_CLIENT 最大并发请求数量
# 如果后端网站响应很慢，就可能占用连接数，导致其他网站的代理也跟着慢
# 因此需要设置一个足够大的并发数量，默认是10
ASYNC_HTTP_CLIENT_MAX_CLIENTS = 500

# 当访问请求没有设置 app_id 时, 将其设置为默认的 App 的 app_id
# 需要根据访问控制台上配置的 App 的 app_id 来设置
# 这样的请求, 一般是允许公开访问的 API 请求
DEFAULT_PUBLIC_APP_ID = 'public'

# 请求后端网站时，避免占用太长时间
# 异步HTTP请求时的 connect 超时时间
# 只是连接的时间
ASYNC_HTTP_CONNECT_TIMEOUT = 20.0
# 异步HTTP请求时的 request 超时时间
# 整个请求的时间
ASYNC_HTTP_REQUEST_TIMEOUT = 20.0

if not os.path.exists(LOG_PATH):
    # 创建日志文件夹
    os.makedirs(LOG_PATH)

logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': "[%(asctime)s] %(levelname)s [%(name)s:%(lineno)s] %(message)s",
            'datefmt': "%Y-%m-%d %H:%M:%S"
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'null': {
            'level': 'DEBUG',
            'class': 'logging.NullHandler',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose'
        },
        'file': {
            'level': 'DEBUG',
            # 'class': 'logging.FileHandler',
            # 'class': 'logging.handlers.TimedRotatingFileHandler',
            # 如果没有使用并发的日志处理类，在多实例的情况下日志会出现缺失
            'class': 'cloghandler.ConcurrentRotatingFileHandler',
            # 当达到10MB时分割日志
            'maxBytes': 1024 * 1024 * 10,
            'backupCount': 10,
            # If delay is true,
            # then file opening is deferred until the first call to emit().
            'delay': True,
            'filename': os.path.join(LOG_PATH, 'server.log'),
            'formatter': 'verbose'
        }
    },
    'loggers': {
        'tornado.curl_httpclient': {
            'handlers': LOGGING_HANDLERS,
            'level': 'INFO',
        },
        '': {
            'handlers': LOGGING_HANDLERS,
            'level': LOGGING_LEVEL,
        },
    }
})
