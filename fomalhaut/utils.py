#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19

from __future__ import unicode_literals, absolute_import

import base64
import hashlib
import json
import logging
import os
import random
import sys
import time
import traceback
import uuid
from base64 import urlsafe_b64encode
from concurrent.futures import ThreadPoolExecutor
from copy import copy
from importlib import import_module
import ujson
import redis
from Crypto import Random
from Crypto.Cipher import AES
from bson.objectid import ObjectId
from future.builtins import chr
from future.utils import iteritems
from tornado.escape import json_decode, utf8, to_unicode, basestring_type
from tornado.httpclient import AsyncHTTPClient

from fomalhaut import settings
from fomalhaut.settings import CONFIG_CACHE_EXPIRE_SECONDS, \
    CLIENT_CONFIG_REDIS_PREFIX, THREAD_POOL_EXECUTOR_WORKER_NUM, \
    ACCESS_TOKEN_REDIS_PREFIX, REFRESH_TOKEN_REDIS_PREFIX, \
    ASYNC_HTTP_CLIENT_MAX_CLIENTS

__all__ = ['BytesIO', 'PY2', 'PY3', 'copy_list', 'AESCipher', 'utf8', 'to_unicode',
           'utf8_encoded_dict', 'RedisHelper', 'text_type', 'binary_type',
           'json_loads', 'new_random_token', 'json_decode', 'AsyncHTTPClient',
           'CachedConfigHandler', 'thread_pool_executor']

logger = logging.getLogger(__name__)

# 当前进程的id
PID = os.getpid()

# Useful for very coarse version differentiation.
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3
PYPY = True if getattr(sys, 'pypy_version_info', None) else False

if PY3:
    from io import BytesIO

    text_type = str
    binary_type = bytes
else:
    from cStringIO import StringIO as BytesIO

    text_type = unicode
    binary_type = str

try:
    # curl_httpclient is faster than simple_httpclient
    AsyncHTTPClient.configure(
        'tornado.curl_httpclient.CurlAsyncHTTPClient',
        max_clients=ASYNC_HTTP_CLIENT_MAX_CLIENTS)
except ImportError:
    AsyncHTTPClient.configure(
        'tornado.simple_httpclient.AsyncHTTPClient',
        max_clients=ASYNC_HTTP_CLIENT_MAX_CLIENTS)

# 拷贝 list
copy_list = (lambda lb: copy(lb) if lb else [])
# 线程池，用来异步执行任务
thread_pool_executor = ThreadPoolExecutor(THREAD_POOL_EXECUTOR_WORKER_NUM)


class ObjectDict(dict):
    """Makes a dictionary behave like an object, with attribute-style access.
    """

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            return None

    def __setattr__(self, name, value):
        self[name] = value


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


def utf8_encoded_dict(in_dict):
    """
    使用 utf-8 重新编码字典
    :param in_dict:
    :return:
    """
    out_dict = {}
    for k, v in iteritems(in_dict):
        if isinstance(v, basestring_type):
            out_dict[utf8(k)] = utf8(v)
        else:
            out_dict[utf8(k)] = v
    return out_dict


def unicode_encoded_dict(in_dict):
    """
    使用 unicode 重新编码字典
    :param in_dict:
    :return:
    """
    out_dict = {}
    for k, v in iteritems(in_dict):
        if isinstance(v, basestring_type):
            out_dict[to_unicode(k)] = to_unicode(v)
        else:
            out_dict[to_unicode(k)] = v
    return out_dict


def time_elapsed(message=''):
    def decorator(func):
        # @gen.coroutine
        def wrapper(*args, **kwargs):
            timestamp = time.time() * 1000

            ret = func(*args, **kwargs)
            # if is_future(ret):
            #     ret = yield ret

            now_ts = time.time() * 1000
            elapsed = now_ts - timestamp
            logger.info('%s %s: %sms' % (message, func.__name__, elapsed))

            # raise gen.Return(ret)
            return ret

        return wrapper

    return decorator


class PKCS7Padding(object):
    def __init__(self, block_size=AES.block_size):
        self.bs = block_size

    def pad(self, s):
        return s + (self.bs - len(s) % self.bs) * utf8(chr(self.bs - len(s) % self.bs))

    def unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]


class AESCipher(object):
    """
    http://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    """

    def __init__(self, key):
        self.bs = 16
        self.key = hashlib.sha256(key.encode()).digest()
        self.padding = PKCS7Padding(self.bs)

    def encrypt(self, raw):
        raw = self.padding.pad(utf8(raw))
        # AES.block_size 长度是16
        # 每次加密都随机生成一个16个字节的IV
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # IV 保存在加密后的文本的开头
        # IV是一个随机的分组，每次会话加密时都要使用一个新的随机IV，
        # IV无须保密，但一定是不可预知的。由于IV的随机性，IV将使得后续的密文分组都因为IV而随机化
        # https://www.zhihu.com/question/26437065
        return to_unicode(base64.b64encode(iv + cipher.encrypt(raw)))

    def decrypt(self, enc):
        # logger.debug(type(enc))
        enc = base64.b64decode(utf8(enc))
        # AES.block_size 长度是16
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain = self.padding.unpad(cipher.decrypt(enc[AES.block_size:]))
        try:
            # 如果是字节流, 比如图片, 无法用 utf-8 编码解码成 unicode 的字符串
            return plain.decode('utf-8')
        except Exception as e:
            logger.debug(e)
            return plain


class UniqueId(object):
    """
    生成唯一的id，用来存储分析统计日志
    """

    def __init__(self):
        pass

    @classmethod
    def new_unique_id(cls):
        # uuid1 由MAC地址、当前时间戳、随机数生成。可以保证全球范围内的唯一性
        # 加上进程id, pid后, 可以保证同一台机器多进程的情况下不会出现冲突
        return '%s-%s' % (PID, uuid.uuid1())

    @classmethod
    def new_object_id(cls):
        # 使用 MongoDB 的 OjectId 来生成唯一的 Id，长度24字节
        return '%s' % ObjectId()


def new_random_token():
    to_hash = '%s%s' % (UniqueId.new_unique_id(), random.random())
    token = hashlib.sha1(utf8(to_hash)).digest()
    # 不能用 base64 因为有些字符不能用在 url 上, 比如 + 号会变成空格, 导致 access_token 作为 url 的参数时会出错
    token = to_unicode(urlsafe_b64encode(token).rstrip(b'='))
    logger.debug(token)
    return token


def json_loads(data):
    try:
        return ujson.loads(data) if data else None
    except Exception as e:
        logger.error(e)
        logger.error(traceback.format_exc())

    return None


def json_dumps(data, ensure_ascii=True):
    return ujson.dumps(data, ensure_ascii)


class CachedConfigHandler(object):
    """
    带有缓存的配置读取, 避免频繁访问时, 需要重复去 redis 读取配置
    """
    _cached_config = {}
    _last_clear_ts = 0
    _clear_time = 1000 * CONFIG_CACHE_EXPIRE_SECONDS

    @classmethod
    def get_client_config(cls, app_id):
        now_ts = int(time.time())

        config = cls._cached_config.get(app_id)
        if config:
            ts = config['ts']
            if now_ts - ts <= CONFIG_CACHE_EXPIRE_SECONDS:
                return config['data']
            else:
                cls._clear_expired_config(now_ts)

        config_data = RedisHelper.get_client_config(app_id)
        cls._cached_config[app_id] = {'ts': now_ts, 'data': config_data}
        return config_data

    @classmethod
    def _clear_expired_config(cls, now_ts):
        """
        避免因为 access_key 更新太多次, 导致有大量无效的数据
        :param now_ts:
        :return:
        """
        if now_ts - cls._last_clear_ts > cls._clear_time:
            cls._cached_config = {
                k: v
                for k, v in iteritems(cls._cached_config)
                if now_ts - v['ts'] <= CONFIG_CACHE_EXPIRE_SECONDS
            }
            cls._last_clear_ts = now_ts


class RedisHelper(object):
    """
    redis 连接助手
    """
    _client = None

    def __init__(self):
        if RedisHelper._client is None:
            self._create_redis_client()

    @classmethod
    def get_client(cls):
        if RedisHelper._client is None:
            cls._create_redis_client()

        return RedisHelper._client

    @classmethod
    def get_client_config(cls, app_id):
        """
        获取 client 配置
        :param app_id:
        :return:
        """
        config_data = cls.get_client().get(
            '%s:%s' % (CLIENT_CONFIG_REDIS_PREFIX, app_id))

        # logger.debug(config_data)
        # 数据全部是存json
        return json_loads(config_data)

    @classmethod
    def get_token_info(cls, access_token=None, refresh_token=None):
        """
        获取 client 配置
        :param refresh_token:
        :param access_token:
        :return:
        """
        if access_token is not None:
            token_info = cls.get_client().get(
                '%s:%s' % (ACCESS_TOKEN_REDIS_PREFIX, access_token))
        elif refresh_token is not None:
            token_info = cls.get_client().get(
                '%s:%s' % (REFRESH_TOKEN_REDIS_PREFIX, refresh_token))
        else:
            return None
        # logger.debug(token_info)
        # 数据全部是存 json
        return json_loads(token_info)

    @classmethod
    def get_access_token_ttl(cls, access_token):
        """
        获取 access_token 剩余的过期时间
        :param access_token:
        :return:
        """

        return cls.get_client().ttl(
            '%s:%s' % (ACCESS_TOKEN_REDIS_PREFIX, access_token))

    @classmethod
    def clear_token_info(cls, access_token=None, refresh_token=None):
        """
        传入一个 access_token 或者 refresh_token 就会自动删除
        相关的 access_token 和 refresh_token
        :param access_token:
        :param refresh_token:
        :return:
        """
        if access_token is not None:
            token_info = cls.get_token_info(access_token=access_token)
        elif refresh_token is not None:
            token_info = cls.get_token_info(refresh_token=refresh_token)
        else:
            return

        if token_info:
            k_a = '%s:%s' % (ACCESS_TOKEN_REDIS_PREFIX, token_info['access_token'])
            k_r = '%s:%s' % (REFRESH_TOKEN_REDIS_PREFIX, token_info['refresh_token'])
            cls.get_client().delete(k_a, k_r)

    @classmethod
    def set_token(cls, redis_prefix, token_name, token_info):
        count = 3
        while count > 0:
            token = new_random_token()
            k_a = '%s:%s' % (redis_prefix, token)
            v = cls.get_client().get(k_a)
            if v is None:
                token_info[token_name] = token
                return True
        else:
            return False

    @classmethod
    def set_token_info(cls, token_info, access_token_ex, refresh_token_ex):
        """
        插入 access_token 和 refresh_token 到 redis 中
        :return:
        """
        try:
            can_set_a = cls.set_token(ACCESS_TOKEN_REDIS_PREFIX, 'access_token', token_info)
            can_set_r = cls.set_token(REFRESH_TOKEN_REDIS_PREFIX, 'refresh_token', token_info)

            if not can_set_a or not can_set_r:
                return None

            json_data = json_dumps(token_info)
            key_a = '%s:%s' % (ACCESS_TOKEN_REDIS_PREFIX, token_info['access_token'])
            pipe = cls.get_client().pipeline()
            # 如果是用 StrictRedis, time 和 value 顺序不一样
            pipe.setex(key_a, access_token_ex, json_data)
            key_r = '%s:%s' % (REFRESH_TOKEN_REDIS_PREFIX, token_info['refresh_token'])
            pipe.setex(key_r, refresh_token_ex, json_data)
            pipe.execute()
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())
            return None

        return token_info

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
        创建连接
        :return:
        """
        # not to use the connection pooling when using the redis-py client in Tornado applications
        # http://stackoverflow.com/questions/5953786/how-do-you-properly-query-redis-from-tornado/15596969#15596969
        # 注意这里必须是 settings.REDIS_HOST
        # 否则在 runserver 中若修改了 settings.REDIS_HOST，这里就不能生效
        RedisHelper._client = redis.StrictRedis(
            host=settings.REDIS_HOST, port=settings.REDIS_PORT,
            db=settings.REDIS_DB, password=settings.REDIS_PASSWORD)


if __name__ == '__main__':
    pass
