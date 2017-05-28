#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals, absolute_import

import json
import logging
import traceback
from base64 import b64encode

from ..i18n import PromptMessage
from ..middleware.base import BaseMiddleware, ResultCode
from ..middleware.exceptions import ClientErrorException
from ..settings import HEADER_BACKEND_USER_JSON, HEADER_X_ACCESS_TOKEN
from ..utils import RedisHelper, utf8, to_unicode, json_dumps

logger = logging.getLogger(__name__)


class AuthAccessTokenMiddleware(BaseMiddleware):
    """
    对 access_token 信息进行验证
    """

    def process_request(self, *args, **kwargs):
        # logger.debug('process_request')
        handler = self.handler
        request = handler.request

        if HEADER_BACKEND_USER_JSON in handler.request.headers:
            del request.headers[HEADER_BACKEND_USER_JSON]

        endpoint = handler.client.request.endpoint
        require_login = endpoint.get('require_login', False)

        if not require_login:
            return

        # 默认从 headers 中获取
        access_token = request.headers.get(HEADER_X_ACCESS_TOKEN, None)
        # 如果没有获取到，再从 url 中获取
        if access_token is None:
            access_token = handler.get_query_argument('access_token', None)

        handler.client.access_token = access_token
        token_info = RedisHelper.get_token_info(access_token=access_token)

        if token_info is not None:
            if token_info.get('app_id') != handler.client.app_id:
                # logger.info('This Access Token Belongs to Another Client App')
                raise ClientErrorException(ResultCode.BAD_ACCESS_TOKEN,
                                           PromptMessage.EXPIRED_OR_INVALID_ACCESS_TOKEN)
            user_info = token_info.get('user_info', {})
            handler.client.user_info = user_info
            try:
                # 将该 App 登录的用户信息传递给后端 Web
                json_str = json_dumps(user_info)
                # 用户信息使用 json 存储，并编码为 base64
                request.headers[HEADER_BACKEND_USER_JSON] = to_unicode(b64encode(utf8(json_str)))
            except Exception as e:
                logger.error('设置 X-User-Json 失败')
                logger.error(user_info)
                logger.error(e)
                logger.error(traceback.format_exc())
        else:
            logger.debug('没有获取到用户信息，不允许访问')
            # 获取用户信息失败
            raise ClientErrorException(ResultCode.BAD_ACCESS_TOKEN,
                                       PromptMessage.EXPIRED_OR_INVALID_ACCESS_TOKEN)
