#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/22

from __future__ import unicode_literals, absolute_import

import logging

from tornado.web import HTTPError

from ..settings import GATEWAY_ERROR_STATUS_CODE

logger = logging.getLogger(__name__)

__all__ = ['APIGatewayException', 'ClientErrorException', 'ServerErrorException']


class APIGatewayException(HTTPError):
    pass


class ClientErrorException(APIGatewayException):
    """
    由客户端的错误引发的异常
    """

    def __init__(self, result_code, log_message, *args, **kwargs):
        self.result_code = result_code
        super(ClientErrorException, self).__init__(
            GATEWAY_ERROR_STATUS_CODE, log_message, *args, **kwargs)


class ServerErrorException(APIGatewayException):
    """
    由服务端的错误引发的异常
    """

    def __init__(self, result_code, log_message, *args, **kwargs):
        self.result_code = result_code
        super(ServerErrorException, self).__init__(
            GATEWAY_ERROR_STATUS_CODE, log_message, *args, **kwargs)
