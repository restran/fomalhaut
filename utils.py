#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals

from base64 import b64encode, b64decode
from importlib import import_module
import redis
import traceback
from Crypto.Cipher import AES
import settings
import time
import logging
import re
import os
import uuid
import json
import sys
import types
from copy import copy

logger = logging.getLogger(__name__)


# 当前进程的id
PID = os.getpid()

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY3:
    string_types = str,
    integer_types = int,
    class_types = type,
    text_type = str
    binary_type = bytes

    MAXSIZE = sys.maxsize
else:
    string_types = basestring,
    integer_types = (int, long)
    class_types = (type, types.ClassType)
    text_type = unicode
    binary_type = str

# 拷贝 list
copy_list = (lambda lb: copy(lb) if lb else [])


def import_string(dotted_path):
    """
    Import a dotted module path and return the attribute/class designated by the
    last name in the path. Raise ImportError if the import failed.
    """
    try:
        module_path, class_name = dotted_path.rsplit('.', 1)
    except ValueError:
        msg = "%s doesn't look like a module path" % dotted_path
        raise ImportError(msg)

    module = import_module(module_path)

    try:
        return getattr(module, class_name)
    except AttributeError:
        msg = 'Module "%s" does not define a "%s" attribute/class' % (
            module_path, class_name)
        raise ImportError(msg)


def get_utf8_value(value):
    """Get the UTF8-encoded version of a value."""
    if not isinstance(value, binary_type) and not isinstance(value, text_type):
        value = binary_type(value)
    if isinstance(value, text_type):
        return value.encode('utf-8')
    else:
        return value

class AESHelper(object):
    """
    AES 加密助手
    """

    @staticmethod
    def pad(s):
        """
        对明文进行填充
        :param s:
        :return:
        """
        bs = AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    @staticmethod
    def unpad(s):
        """
        去除明文的填充
        :param s:
        :return:
        """
        return s[0:-ord(s[-1])]

    @staticmethod
    def encrypt(key, message):
        """
        """
        message = bytes(message)
        # IV 使用 key 的前16个字节
        cryptor = AES.new(key, AES.MODE_CBC, key[:16])
        message = AESHelper.pad(message)
        ciphertext = cryptor.encrypt(message)
        return b64encode(ciphertext)

    @staticmethod
    def decrypt(key, b64_ciphertext):
        # logger.debug(b64_ciphertext)
        ciphertext = b64decode(b64_ciphertext)
        cryptor = AES.new(key, AES.MODE_CBC, key[:16])
        plain_text = cryptor.decrypt(ciphertext)
        return AESHelper.unpad(plain_text)

    @staticmethod
    def encrypt_b64(key, message):
        """'
        密文使用base64编码
        """
        # IV 使用 key 的前16个字节
        cryptor = AES.new(key, AES.MODE_CBC, key[:16])
        message = AESHelper.pad(message)
        ciphertext = cryptor.encrypt(message)
        return b64encode(ciphertext)

    @staticmethod
    def decrypt_b64(key, b64_ciphertext):
        ciphertext = b64decode(b64_ciphertext)
        cryptor = AES.new(key, AES.MODE_CBC, key[:16])
        plain_text = cryptor.decrypt(ciphertext)
        return AESHelper.unpad(plain_text)


def encoded_dict(in_dict):
    """
    使用 utf-8 重新编码字典
    :param in_dict:
    :return:
    """
    out_dict = {}
    for k, v in in_dict.iteritems():
        if isinstance(v, unicode):
            v = v.encode('utf8')
        elif isinstance(v, str):
            # Must be encoded in UTF-8
            v.decode('utf8')
        out_dict[k] = v
    return out_dict


class ObjectId(object):
    """
    生成唯一的id，用来存储分析统计日志
    """

    def __init__(self):
        pass

    @classmethod
    def get_new_object_id(cls):
        # uuid1 由MAC地址、当前时间戳、随机数生成。可以保证全球范围内的唯一性
        return '%s-%s' % (PID, uuid.uuid1())


class RedisHelper(object):
    """
    redis 连接助手
    """
    connection_pool = None

    def __init__(self):
        if RedisHelper.connection_pool is None:
            self.__create_redis_client()

        self.client = redis.Redis(connection_pool=RedisHelper.connection_pool)

    def get_client_config(self, access_key):
        """
        获取代理配置，这里app_config即access_agent，但是不包含backend_sites
        如果有用到需要另外获取
        :param access_key:
        :return:
        """
        config_data = self.client.get(
            '%s:%s' % (settings.PROXY_CONFIG_REDIS_PREFIX, access_key))

        # 数据全部是存json
        try:
            return json.loads(config_data) if config_data else None
        except Exception as e:
            logger.error(e.message)
            logger.error(traceback.format_exc())

        return None

    def get_site_config(self, access_key, site_name):
        """
        获取代理配置
        :param access_key:
        :return:
        """
        config_data = self.client.get(
            '%s:%s:%s' % (settings.PROXY_CONFIG_REDIS_PREFIX, access_key, site_name))

        # 数据全部是存json
        try:
            site_config = json.loads(config_data) if config_data else None

            return site_config
        except Exception as e:
            logger.error(e.message)
            logger.error(traceback.format_exc())

        return None

    def get_proxy_site_config(self, access_key, site_name):
        """
        获取代理配置，这里app_config即access_agent，但是不包含backend_sites
        如果有用到需要另外获取
        :param access_key:
        :param site_name:
        :return:
        """
        config_data = self.client.mget(
            ['%s:%s' % (settings.PROXY_CONFIG_REDIS_PREFIX, access_key),
             '%s:%s:%s' % (settings.PROXY_CONFIG_REDIS_PREFIX, access_key, site_name)])

        # 数据全部是存json
        try:
            app_config = json.loads(config_data[0]) if config_data[0] else None
            site_config = json.loads(config_data[1]) if config_data[1] else None

            return app_config, site_config
        except Exception as e:
            logger.error(e.message)
            logger.error(traceback.format_exc())

        return None, None

    def get_agent_backend_sites(self, access_key):
        """
        获取access_agent的所有后端站点
        :param access_key:
        :return:
        """
        pattern_get_backend_sites_lua = """
        local keys = redis.call('keys', ARGV[1])
        local values = {}
        for i = 1, table.getn(keys) do
            values[i] = redis.call('get', keys[i])
        end
        return values
        """
        lua = self.client.register_script(pattern_get_backend_sites_lua)
        backend_sites = lua(keys=[''], args=['%s:%s:*' % (
            settings.PROXY_CONFIG_REDIS_PREFIX, access_key)], client=self.client)
        try:
            backend_sites = [json.loads(t) for t in backend_sites]
        except Exception as e:
            logger.error(e.message)
            logger.error(traceback.format_exc())
            return []

        return backend_sites

    def add_analytics_log(self, log_item):
        """
        插入统计分析的日志到 redis 中
        :return:
        """
        try:
            json_data = json.dumps(log_item, ensure_ascii=False)
            key = '%s:%s' % (settings.ANALYTICS_LOG_REDIS_PREFIX, ObjectId.get_new_object_id())
            self.client.setex(key, json_data, settings.ANALYTICS_LOG_REDIS_EXPIRE_SECONDS)
            logger.info('add analytics log, %s' % key)
        except Exception as e:
            logger.error(e.message)
            logger.error(traceback.format_exc())
            logger.error('保存统计信息出错')

    def ping_redis(self):
        """
        测试redis能否连通
        :return:
        """
        self.client.ping()

    @classmethod
    def __create_redis_client(cls):
        """
        创建连接池
        :return:
        """
        RedisHelper.connection_pool = redis.ConnectionPool(
            host=settings.REDIS_HOST, port=settings.REDIS_PORT,
            db=settings.REDIS_DB, password=settings.REDIS_PASSWORD)

if __name__ == '__main__':
    pass
