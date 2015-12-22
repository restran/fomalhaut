#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/22

from __future__ import unicode_literals

import logging

from tornado.web import HTTPError

logger = logging.getLogger(__name__)


class ClientErrorException(HTTPError):
    pass


class ServerErrorException(HTTPError):
    pass


class APIException(HTTPError):
    pass


class ClientBadConfigException(ServerErrorException):
    """
    签名错误,非法的请求
    """


class AuthRequestException(ClientErrorException):
    """
    非法请求,签名错误,时间戳过期
    """
