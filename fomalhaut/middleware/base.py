# -*- coding: utf-8 -*-
# created by restran on 2016/06/05
from __future__ import unicode_literals, absolute_import

import logging

from ..i18n import PromptMessage
from ..middleware.exceptions import ServerErrorException, \
    ClientErrorException
from ..settings import HEADER_X_APP_ID, DEFAULT_PUBLIC_APP_ID
from ..utils import CachedConfigHandler, ObjectDict

logger = logging.getLogger(__name__)


class ResultCode(object):
    """
    响应结果的编码
    """
    # 成功
    OK = 200
    # 请求的参数不完整，或者格式不正确，例如缺少一些参数
    BAD_REQUEST = 400
    # 登录验证失败
    BAD_ACCESS_TOKEN = 401
    # HMAC 签名鉴定失败，禁止访问
    BAD_SIGN_REQUEST = 403

    # Signature 参数已过期
    EXPIRED_SIGNATURE = 430
    # Signature 参数不正确
    INVALID_SIGNATURE = 431

    # 没有访问权限
    NO_PERMISSION = 432

    # 该 Client 已被禁用
    DISABLED_CLIENT = 421
    # 该 Endpoint 已被禁用
    DISABLED_ENDPOINT = 422
    # AES 解密失败
    AES_DECRYPT_ERROR = 423

    # --------------------------------
    # 服务器处理发生异常
    INTERNAL_SERVER_ERROR = 500
    # 访问 endpoint server 出现错误, 服务不可用
    ENDPOINT_REQUEST_ERROR = 503
    # endpoint 返回的数据格式不正确
    BAD_ENDPOINT_RESPONSE = 502
    # client 缺少配置，或配置有误
    BAD_CLIENT_CONFIG = 510

    # AES 加密失败
    AES_ENCRYPT_ERROR = 523


class Client(object):
    def __init__(self, request):
        self.app_id = request.headers.get(
            HEADER_X_APP_ID, DEFAULT_PUBLIC_APP_ID)
        self.secret_key = None
        logger.debug(self.app_id)
        self.config = ObjectDict()
        self.request = ObjectDict(endpoint=None, forward_url='', uri='')
        self.access_token = None
        self.user_info = None
        self.raw_uri = request.uri
        self.get_client_config()

    def get_client_config(self):
        config_data = CachedConfigHandler.get_client_config(self.app_id)
        if config_data is None:
            raise ServerErrorException(ResultCode.BAD_CLIENT_CONFIG,
                                       PromptMessage.NO_CLIENT_CONFIG)
        else:
            pass
            # 校验需要耗费较多的时间, 不值得
            # 校验 config 数据是否正确
            # v = Validator(self.config_schema, allow_unknown=True)
            # if not v.validate(config_data):
            #     logger.error(v.errors)
            #     raise ClientBadConfigException('Bad Client Config')

        logger.debug(config_data)
        if not config_data.get('enable', True):
            raise ClientErrorException(ResultCode.DISABLED_CLIENT,
                                       PromptMessage.DISABLED_CLIENT)

        self.secret_key = config_data.get('secret_key')

        self.config = ObjectDict(**config_data)


class BaseMiddleware(object):
    """
    中间件的基类
    """

    def __init__(self, handler):
        self.handler = handler

    """ 子类根据要处理的时机,实现对应的方法

    def process_request(self, *args, **kwargs):
        pass

    def process_response(self, *args, **kwargs):
        pass

    def process_finished(self, *args, **kwargs):
        pass
    """


class PrepareMiddleware(BaseMiddleware):
    """
    获取 client 和 endpoint
    """

    def process_request(self, *args, **kwargs):
        logger.debug('process_request')
        self.handler.client = Client(self.handler.request)

        # 在后续的 HMAC 签名校验部分，需要提前知道是哪个 endpoint，
        # 才能根据配置执行签名校验
        # 解析 uri, 获取该请求对应的 endpoint
        try:
            _, req_endpoint, version, uri = self.handler.request.uri.split('/', 3)
            self.handler.request.version = version
            if not uri.startswith('/'):
                uri = '/' + uri

            self.handler.client.request.uri = uri
        except ValueError:
            raise ClientErrorException(ResultCode.BAD_REQUEST, PromptMessage.INVALID_REQUEST_URI)

        endpoints = self.handler.client.config.get('endpoints', {})
        endpoint = endpoints.get('%s:%s' % (req_endpoint, version))
        if endpoint is None:
            raise ClientErrorException(
                ResultCode.NO_PERMISSION,
                '%s %s/%s' % (PromptMessage.NO_PERMISSION, req_endpoint, version))

        if not endpoint.get('enable', True):
            raise ClientErrorException(ResultCode.DISABLED_ENDPOINT, PromptMessage.DISABLED_ENDPOINT)

        self.handler.client.request.endpoint = endpoint
