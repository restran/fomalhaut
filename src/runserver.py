#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19
from __future__ import unicode_literals, absolute_import

import logging

from tornado import httpserver, ioloop, web
from tornado.options import define, options
import motor
from settings import MONGO_DBNAME, MONGO_HOST, MONGO_PORT, \
    MONGO_PASSWORD, MONGO_USERNAME
from utils import RedisHelper, import_string, \
    text_type, binary_type, PY2
from handlers.base import BaseHandler
import settings

logger = logging.getLogger(__name__)

define("host", default=settings.HOST, help="run on the given host", type=str)
define("port", default=settings.PORT, help="run on the given port", type=int)
define("num_processes", default=settings.NUM_PROCESSES, help="process num", type=int)


class Application(web.Application):
    def __init__(self):
        tornado_settings = {
            'autoreload': settings.AUTO_RELOAD,
            'debug': settings.DEBUG
        }
        self.middleware_list = []
        self.builtin_endpoints = {}

        self._load_middleware()
        self._load_builtin_endpoints()

        handlers = [
            (r'/.*', BaseHandler)
        ]

        super(Application, self).__init__(handlers, **tornado_settings)

    def _load_builtin_endpoints(self):
        """
        从 settings.BUILTIN_ENDPOINTS 载入内置的 endpoints
        """
        handlers = {}
        for endpoint in settings.BUILTIN_ENDPOINTS:
            c = endpoint['config']
            key = '%s/%s' % (c['name'], c['version'])
            handlers[key] = []
            for reg_uri, handler_path in endpoint['handlers']:
                h_class = import_string(handler_path)
                handlers[key].append((reg_uri, h_class))

        self.builtin_endpoints = handlers

    def _load_middleware(self):
        """
        从 settings.MIDDLEWARE_CLASSES 载入中间件
        """

        for middleware_path in settings.MIDDLEWARE_CLASSES:
            mw_class = import_string(middleware_path)
            self.middleware_list.append(mw_class)

        logger.debug('middleware_list: \n%s' %
                     '\n'.join([text_type(m) for m in self.middleware_list]))


def main():
    # 启动 tornado 之前，先测试 redis 是否能正常工作
    r = RedisHelper()
    r.ping_redis()

    # 重新设置一下日志级别，默认情况下，tornado 是 info
    # py2 下 options.logging 不能是 Unicode
    if PY2:
        options.logging = binary_type(settings.LOGGING_LEVEL)
    else:
        options.logging = settings.LOGGING_LEVEL

    # parse_command_line 的时候将 logging 的根级别设置为 info
    options.parse_command_line()

    app = Application()
    server = httpserver.HTTPServer(app, xheaders=True)

    # 如果开启了 autoreload 会出现错误
    # You cannot call IOLoop.instance() before calling start_processes()
    if settings.AUTO_RELOAD:
        server.listen(options.port, options.host)
    else:
        server.bind(options.port, options.host)
        server.start(options.num_processes)

    logger.info('api gateway server is running on %s:%s' % (options.host, options.port))

    # 因为 motor 基于 IOLoop.instance() 所以需要等创建多进程后才创建
    # 否则会出现错误 You cannot call IOLoop.instance() before calling start_processes()
    # 创建一个数据库连接池
    db_client = motor.motor_tornado.MotorClient(
        MONGO_HOST, MONGO_PORT, max_pool_size=200)
    # 验证数据库用户名和密码
    db_client[MONGO_DBNAME].authenticate(
        MONGO_USERNAME, MONGO_PASSWORD, mechanism='SCRAM-SHA-1')
    database = db_client[MONGO_DBNAME]
    app.settings['db'] = database

    # TODO gevent may improve performance

    ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
