#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals

import os
import logging.config

# 当前目录所在路径
BASE_PATH = os.path.abspath(os.path.dirname(__file__))
# 模板路径
TEMPLATE_PATH = os.path.join(BASE_PATH, 'templates')
LOG_PATH = os.path.join(BASE_PATH, 'logs')

HOST = '127.0.0.1'
PORT = 6500

# 是否调试模式
DEBUG = True

# 中间件会按顺序执行
MIDDLEWARE_CLASSES = [
    'middleware.analytics.AnalyticsHandler',
    'middleware.auth.AuthenticateHandler',
    'middleware.encrypt.EncryptHandler',
    'middleware.auth.ParseEndpointHandler',
    'middleware.token.AuthAccessTokenHandler',
]

# api-gateway 内置的 Endpoint
BUILTIN_ENDPOINTS = [
    {
        'config': {
            'name': 'auth',
            'version': '1',
            'builtin_endpoint': True
        },
        'handlers': [
            ('/login/?', 'handlers.endpoint.AuthLoginHandler'),
            ('/logout/?', 'handlers.endpoint.AuthLogoutHandler'),
            ('/token/?', 'handlers.endpoint.AuthTokenHandler')
        ],
    }
]

# 未通过网关鉴权, 或者未能正确请求时返回的状态码
# 通过特殊的状态码, 区分后端 API Server 返回的状态码
GATEWAY_ERROR_STATUS_CODE = 600

# 可以给日志对象设置日志级别，低于该级别的日志消息将会被忽略
# CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET
LOGGING_LEVEL = 'DEBUG' if DEBUG else 'INFO'
LOGGING_HANDLERS = ['console'] if DEBUG else ['file']

DEFAULT_TIMEZONE = 'Asia/Shanghai'

# 访问签名的有效时间,秒
SIGNATURE_EXPIRE_SECONDS = 3600

# 这里如果使用localhost会导致速度变慢
REDIS_HOST = '127.0.0.1'
REDIS_PORT = 6379
REDIS_DB = 0
REDIS_PASSWORD = '5iveSec0nds'
REDIS_MAX_CONNECTIONS = 100

# client 配置 redis 中 key 前缀
CLIENT_CONFIG_REDIS_PREFIX = 'config'
# access_token redis 中 key 前缀
ACCESS_TOKEN_REDIS_PREFIX = 't'
# access_token redis 中 key 前缀
REFRESH_TOKEN_REDIS_PREFIX = 'r'
# 统计分析日志的 redis key 前缀
ANALYTICS_LOG_REDIS_PREFIX = 'a'

# 分析统计日志，在 redis 中的过期时间
ANALYTICS_LOG_REDIS_EXPIRE_SECONDS = 30 * 60

# 基础配置在 redis 中的 key
# BASE_CONFIG_REDIS_KEY = 'base_config'

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
    'disable_existing_loggers': True,
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
            'backupCount': 50,
            # If delay is true,
            # then file opening is deferred until the first call to emit().
            'delay': True,
            'filename': os.path.join(LOG_PATH, 'server.log'),
            'formatter': 'verbose'
        }
    },
    'loggers': {
        '': {
            'handlers': LOGGING_HANDLERS,
            'level': LOGGING_LEVEL,
        },
    }
})
