# -*- coding: utf-8 -*-
# Created by restran on 2016/11/18
from __future__ import unicode_literals, absolute_import

import logging
import re

from future.moves.urllib.parse import urlparse

from ..handlers.proxy import BackendAPIHandler
from ..i18n import PromptMessage
from ..middleware.base import BaseMiddleware, Client, ResultCode
from ..middleware.exceptions import ClientErrorException, ServerErrorException

logger = logging.getLogger(__name__)


class ParseEndpointMiddleware(BaseMiddleware):
    """
    解析出需要访问的 Forward Url
    """

    # TODO 为了兼容性 uri 要加上 app_id
    def _parse_uri(self, client):
        """
        解析请求的 uri
        :type client: Client
        :return:
        """
        handler = self.handler
        endpoint = handler.client.request.endpoint

        if handler.client.encrypt_type == 'aes':
            # 如果是加密后的 uri，到这一步的时候已经解密完成
            # 需要重新解析 uri, 获取该请求真实的 uri
            try:
                _, _, _, uri = handler.request.uri.split('/', 3)
                if not uri.startswith('/'):
                    uri = '/' + uri

                handler.client.request.uri = uri
            except ValueError:
                raise ClientErrorException(ResultCode.BAD_REQUEST, PromptMessage.INVALID_REQUEST_URI)
        else:
            uri = handler.client.request.uri

        if endpoint.get('is_builtin', False):
            # 如果是内置的 endpoint, 就没有 forward_url
            forward_url = None

            # 寻找匹配的内置 Endpoint Handler
            key = '%s/%s' % (endpoint['name'], endpoint['version'])
            builtin_handlers = handler.builtin_endpoints.get(key, [])
            # 只匹配 uri 的 Path 部分
            # 这样 Handlers 那边的正则表达式就可以用 $ 来表示结尾
            uri_parsed = urlparse(uri)
            uri_path = uri_parsed.path
            for t in builtin_handlers:
                re_uri, _handler = t
                match = re.match(re_uri, uri_path)
                if match:
                    handler.real_api_handler = _handler
                    break
            else:
                handler.real_api_handler = None
        else:
            # 后端的 API, 需要代理访问
            handler.real_api_handler = BackendAPIHandler
            # 解析要转发的地址
            endpoint_url = endpoint.get('url')
            if endpoint_url is None:
                raise ServerErrorException(ResultCode.BAD_CLIENT_CONFIG, PromptMessage.NO_ENDPOINT_URL_CONFIG)

            endpoint_netloc = endpoint.get('netloc')
            if endpoint_netloc is None:
                url_parsed = urlparse(endpoint_url)
                endpoint['netloc'] = url_parsed.netloc

            if endpoint.get('skip_uri', False):
                # 判断是否要忽略掉用户传递的uri信息
                uri = ''
            elif endpoint_url.find('?') > 0 and uri == '/':
                # 有些后端站点，直接定位到查询参数的url，例如/?a=xx，因此后面不能再跟uri，
                # 而默认会带上/，变成/?a=xx/，因此这里要过滤掉/
                uri = ''

            # TODO uri 合法性校验和修正
            if endpoint_url.endswith('/'):
                forward_url = endpoint_url + uri[1:]
            else:
                forward_url = endpoint_url + uri

        handler.client.request.forward_url = forward_url

    def _acl_filter(self):
        """
        如果启用访问控制列表，就需要检查URI是否允许访问
        :return:
        """
        client = self.handler.client
        uri = client.request.uri
        uri_parsed = urlparse(uri)
        uri_path = uri_parsed.path

        endpoint = client.request.endpoint
        enable_acl = endpoint.get('enable_acl', False)
        if enable_acl:
            acl_rules = endpoint.get('acl_rules', [])
            # 如果都没有找到匹配的规则，默认返回Tue，放行
            for r in acl_rules:
                re_uri, is_permit = r['re_uri'], r['is_permit']
                match = re.match(re_uri, uri_path)
                if match:
                    allow_access = is_permit
                    break
            else:
                allow_access = True

            # 禁止访问该 uri
            if not allow_access:
                # logger.info('forbidden uri %s' % uri)
                raise ClientErrorException(ResultCode.NO_PERMISSION,
                                           PromptMessage.NO_PERMISSION)

    def process_request(self, *args, **kwargs):
        # logger.debug('process_request')
        # 解析 uri, 获取该请求实际要转发的地址
        self._parse_uri(self.handler.client)
        # 进行 acl 过滤
        self._acl_filter()
