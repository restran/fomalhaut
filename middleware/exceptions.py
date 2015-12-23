#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/22

from __future__ import unicode_literals

import logging
from settings import AUTH_FAIL_STATUS_CODE
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

    def __init__(self, log_message, *args, **kwargs):
        super(ClientBadConfigException, self).__init__(
            AUTH_FAIL_STATUS_CODE, log_message, *args, **kwargs)


class AuthRequestException(ClientErrorException):
    """
    非法请求,签名错误,时间戳过期
    """

    def __init__(self, log_message, *args, **kwargs):
        super(AuthRequestException, self).__init__(
            AUTH_FAIL_STATUS_CODE, log_message, *args, **kwargs)
