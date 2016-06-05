# -*- coding: utf-8 -*-
# created by restran on 2016/06/05
from __future__ import unicode_literals, absolute_import

import logging

import settings
from middleware.exceptions import AuthRequestException, ClientBadConfigException
from utils import CacheConfigHandler

logger = logging.getLogger(__name__)


class Client(object):
    # redis 中存储的 config 数据的格式
    config_schema = {
        'secret_key': {
            'type': 'string',
            'required': True
        },
        'access_key': {
            'type': 'string',
            'required': True
        },
        'name': {
            'type': 'string',
            'required': True
        },
        'id': {
            'type': 'integer',
            'required': True
        },
        'endpoints': {
            'type': 'dict',
            'required': True,
            # 字典的 key
            'propertyschema': {
                'type': 'string'
            },
            # 字典的 value
            'valueschema': {
                'type': 'dict',
                'allow_unknown': True,
                'schema': {
                    'name': {
                        'type': 'string',
                        'required': True
                    },
                    'id': {
                        'type': 'integer',
                        'required': True
                    },
                    'version': {
                        'type': 'string',
                        'required': True
                    },
                    'url': {
                        'type': 'string',
                        'required': True
                    },
                    'netloc': {
                        'type': 'string',
                        'required': True
                    },
                    'enable_acl': {
                        'type': 'boolean',
                        'required': True
                    },
                    'enable_hmac': {
                        'type': 'boolean',
                        'required': True
                    },
                    'acl_rules': {
                        'type': 'list',
                        'required': True,
                        'allow_unknown': True,
                        'items': {
                            're_uri': {
                                'type': 'string',
                                'required': True,
                            },
                            'is_permit': {
                                'type': 'boolean',
                                'required': True,
                            }
                        }
                    },
                }
            }
        },
    }

    def __init__(self, request):
        self.access_key = request.headers.get(
            'X-Api-Access-Key', settings.DEFAULT_PUBLIC_APP_ACCESS_KEY)
        self.secret_key = None
        logger.debug(self.access_key)
        self.config = {}
        self.request = {}
        self.raw_uri = request.uri
        self.get_client_config()

    def get_client_config(self):
        config_data = CacheConfigHandler.get_client_config(self.access_key)
        if config_data is None:
            raise ClientBadConfigException('No Client Config')
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
            raise AuthRequestException('Disabled Client')

        self.secret_key = config_data.get('secret_key')
        # 内置的 endpoint 由控制台配置, 不再自动添加
        # for t in settings.BUILTIN_ENDPOINTS:
        #     endpoint = t['config']
        #     k = '%s:%s' % (endpoint['name'], endpoint['version'])
        #     config_data['endpoints'][k] = endpoint

        self.config = config_data


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
