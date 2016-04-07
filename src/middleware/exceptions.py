#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/22

from __future__ import unicode_literals, absolute_import

import logging
from settings import GATEWAY_ERROR_STATUS_CODE
from tornado.web import HTTPError

logger = logging.getLogger(__name__)


class APIGatewayException(HTTPError):
    pass


class ClientErrorException(APIGatewayException):
    """
    由客户端的错误引发的异常
    """

    def __init__(self, log_message, *args, **kwargs):
        super(ClientErrorException, self).__init__(
            GATEWAY_ERROR_STATUS_CODE, log_message, *args, **kwargs)


class ServerErrorException(APIGatewayException):
    """
    由服务端的错误引发的异常
    """

    def __init__(self, log_message, *args, **kwargs):
        super(ServerErrorException, self).__init__(
            GATEWAY_ERROR_STATUS_CODE, log_message, *args, **kwargs)


class ClientBadConfigException(ServerErrorException):
    """
    Client 配置信息有误, 或者不存在
    """


class LoginAuthException(ClientErrorException):
    """
    验证 access_token 判断是否登录
    """


class AuthRequestException(ClientErrorException):
    """
    非法请求, 签名错误, 时间戳过期
    """
