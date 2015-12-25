#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals

from importlib import import_module
import traceback
import logging
import os
import uuid
import json
import sys
import types
from copy import copy
import base64
import hashlib

from Crypto import Random
from Crypto.Cipher import AES
import redis

import settings

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


def utf8(value):
    """Get the UTF8-encoded version of a value."""
    if not isinstance(value, binary_type) and not isinstance(value, text_type):
        value = binary_type(value)
    if isinstance(value, text_type):
        return value.encode('utf-8')
    else:
        return value


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


class AESCipher(object):
    """
    http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    """
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain = self._unpad(cipher.decrypt(enc[AES.block_size:]))
        try:
            # 如果是字节流, 比如图片, 无法用 utf-8 编码解码成 unicode 的字符串
            return plain.decode('utf-8')
        except Exception as e:
            logger.warning(e)
            return plain

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


class ObjectId(object):
    """
    生成唯一的id，用来存储分析统计日志
    """

    def __init__(self):
        pass

    @classmethod
    def new_object_id(cls):
        # uuid1 由MAC地址、当前时间戳、随机数生成。可以保证全球范围内的唯一性
        # 加上进程id, pid后, 可以保证同一台机器多进程的情况下不会出现冲突
        return '%s-%s' % (PID, uuid.uuid1())


class RedisHelper(object):
    """
    redis 连接助手
    """
    _connection_pool = None

    def __init__(self):
        if RedisHelper._connection_pool is None:
            self._create_redis_client()

    @classmethod
    def get_client(cls):
        if RedisHelper._connection_pool is None:
            cls._create_redis_client()

        return redis.Redis(connection_pool=RedisHelper._connection_pool)

    @classmethod
    def get_client_config(cls, access_key):
        """
        获取代理配置，这里app_config即access_agent，但是不包含backend_sites
        如果有用到需要另外获取
        :param access_key:
        :return:
        """
        config_data = cls.get_client().get(
            '%s:%s' % (settings.PROXY_CONFIG_REDIS_PREFIX, access_key))

        logger.debug(config_data)
        # 数据全部是存json
        try:
            return json.loads(config_data) if config_data else None
        except Exception as e:
            logger.error(e.message)
            logger.error(traceback.format_exc())

        return None

    @classmethod
    def add_analytics_log(cls, log_item):
        """
        插入统计分析的日志到 redis 中
        :return:
        """
        try:
            json_data = json.dumps(log_item, ensure_ascii=False)
            key = '%s:%s' % (settings.ANALYTICS_LOG_REDIS_PREFIX, ObjectId.new_object_id())
            cls.get_client().setex(key, json_data, settings.ANALYTICS_LOG_REDIS_EXPIRE_SECONDS)
            logger.info('add analytics log, %s' % key)
        except Exception as e:
            logger.error(e.message)
            logger.error(traceback.format_exc())
            logger.error('保存统计信息出错')

    @classmethod
    def ping_redis(cls):
        """
        测试redis能否连通
        :return:
        """
        cls.get_client().ping()

    @classmethod
    def _create_redis_client(cls):
        """
        创建连接池
        :return:
        """
        RedisHelper._connection_pool = redis.ConnectionPool(
            host=settings.REDIS_HOST, port=settings.REDIS_PORT,
            db=settings.REDIS_DB, password=settings.REDIS_PASSWORD)


if __name__ == '__main__':
    pass
