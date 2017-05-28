# -*- coding: utf-8 -*-
# created by restran on 2016/02/21
from __future__ import unicode_literals, absolute_import

import logging
import traceback

from tornado import gen
from tornado.escape import json_decode
from tornado.httpclient import HTTPRequest

from fomalhaut.handlers.base import ServerErrorException
from fomalhaut.handlers.endpoints.base import LoginRequiredHandler, APIStatusCode
from fomalhaut.i18n import PromptMessage
from fomalhaut.middleware.base import ResultCode
from fomalhaut.settings import ASYNC_HTTP_CONNECT_TIMEOUT, ASYNC_HTTP_REQUEST_TIMEOUT
from fomalhaut.utils import RedisHelper, AsyncHTTPClient

logger = logging.getLogger(__name__)


class Logout(LoginRequiredHandler):
    """
    登出，需要登录才能使用
    """

    @gen.coroutine
    def post(self, *args, **kwargs):
        RedisHelper.clear_token_info(access_token=self.client.access_token)
        self.success(msg=PromptMessage.LOGOUT_SUCCESS)


class ChangePassword(LoginRequiredHandler):
    """
    修改密码，需要登录才能使用
    """

    @gen.coroutine
    def post(self, *args, **kwargs):
        client = self.client
        change_type = self.handler.get_query_argument('change_type', 'old_password')
        if change_type == 'sms':
            change_password_url = client.config.sms_change_password_url
            if change_password_url is None or change_password_url == '':
                raise ServerErrorException(
                    ResultCode.BAD_CLIENT_CONFIG,
                    PromptMessage.NO_CHANGE_PASSWORD_SMS_URL_CONFIG)
        else:
            change_password_url = client.config.change_password_url
            if change_password_url is None or change_password_url == '':
                raise ServerErrorException(
                    ResultCode.BAD_CLIENT_CONFIG,
                    PromptMessage.NO_CHANGE_PASSWORD_URL_CONFIG)
        logger.debug(change_password_url)
        headers = self.get_required_headers()
        headers['Content-Type'] = 'application/json; charset=utf-8'
        try:
            response = yield AsyncHTTPClient().fetch(
                HTTPRequest(url=change_password_url,
                            method=self.request.method,
                            body=self.request.body,
                            headers=headers,
                            connect_timeout=ASYNC_HTTP_CONNECT_TIMEOUT,
                            request_timeout=ASYNC_HTTP_REQUEST_TIMEOUT))
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            raise ServerErrorException(
                ResultCode.ENDPOINT_REQUEST_ERROR,
                PromptMessage.ENDPOINT_UNAVAILABLE)

        try:
            json_data = json_decode(response.body)
        except:
            raise ServerErrorException(
                ResultCode.BAD_ENDPOINT_RESPONSE,
                PromptMessage.BAD_ENDPOINT_RESPONSE)

        logger.debug(json_data)
        code = json_data.get('code', APIStatusCode.FAIL)
        if code == APIStatusCode.SUCCESS:
            logger.debug('clear access_token: %s' % self.client.access_token)
            RedisHelper.clear_token_info(access_token=self.client.access_token)
            self.success(msg=PromptMessage.CHANGE_PASSWORD_SUCCESS)
        else:
            self.fail(msg=json_data.get('message', PromptMessage.CHANGE_PASSWORD_FAIL))

