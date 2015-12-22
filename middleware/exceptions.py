#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/22

from __future__ import unicode_literals

import logging

from tornado.web import HTTPError

logger = logging.getLogger(__name__)


class ClientErrorException(HTTPError):
    """
    由客户端的错误引发的异常
    """


class ServerErrorException(HTTPError):
    """
    由服务端的错误引发的异常
    """


class ClientBadConfigException(ServerErrorException):
    """
    Client 配置信息有误,或者不存在
    """


class AuthRequestException(ClientErrorException):
    """
    非法请求,签名错误,时间戳过期
    """
