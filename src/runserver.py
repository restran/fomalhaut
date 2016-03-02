#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19
from __future__ import unicode_literals

import logging

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.gen
import tornado.httpclient
from tornado.options import define, options
from tornado import web
import motor
from settings import MONGO_DBNAME, MONGO_HOST, MONGO_PORT, \
    MONGO_PASSWORD, MONGO_USERNAME
from utils import RedisHelper, import_string
from utils import text_type, binary_type
from handlers.proxy import BackendAPIHandler
import settings

logger = logging.getLogger(__name__)

define("host", default=settings.HOST, help="run on the given host", type=str)
define("port", default=settings.PORT, help="run on the given port", type=int)


class Application(web.Application):
    def __init__(self):
        # 创建一个数据库连接池
        self.db_client = motor.motor_tornado.MotorClient(
            MONGO_HOST, MONGO_PORT, max_pool_size=200)
        # 验证数据库用户名和密码
        self.db_client[MONGO_DBNAME].authenticate(
            MONGO_USERNAME, MONGO_PASSWORD, mechanism='SCRAM-SHA-1')
        self.database = self.db_client[MONGO_DBNAME]

        tornado_settings = dict(
            # autoreload=True, # debug 模式会自动 autoreload
            debug=settings.DEBUG,
            db=self.database
        )

        self.middleware_list = []
        self.builtin_endpoints = settings.BUILTIN_ENDPOINTS
        self._load_middleware()

        handlers = self._load_builtin_endpoints()
        handlers.extend(
            [(r'/.*', BackendAPIHandler)]
        )

        web.Application.__init__(self, handlers, **tornado_settings)

    def _load_builtin_endpoints(self):
        """
        从 settings.BUILTIN_ENDPOINTS 载入内置的 endpoints
        """
        handlers = []
        for endpoint in self.builtin_endpoints:
            c = endpoint['config']
            for url, handler_path in endpoint['handlers']:
                h_class = import_string(handler_path)
                handlers.append((r'/%s/%s%s' % (c['name'], c['version'], url), h_class))

        logger.debug('builtin_endpoints: \n%s' %
                     '\n'.join([text_type(h) for h in handlers]))
        return handlers

    def _load_middleware(self):
        """
        从 settings.MIDDLEWARE_CLASSES 载入中间件
        """

        for middleware_path in settings.MIDDLEWARE_CLASSES:
            mw_class = import_string(middleware_path)
            self.middleware_list.append(mw_class)

        logger.debug('middleware_list: \n%s' %
                     '\n'.join([text_type(m) for m in self.middleware_list]))


app = Application()


def main():
    # 启动 tornado 之前，先测试 redis 是否能正常工作
    r = RedisHelper()
    r.ping_redis()

    # 重新设置一下日志级别，默认情况下，tornado 是 info
    # options.logging 不能是 Unicode
    options.logging = binary_type(settings.LOGGING_LEVEL)
    # parse_command_line 的时候将 logging 的根级别设置为 info
    tornado.options.parse_command_line()

    http_server = tornado.httpserver.HTTPServer(app, xheaders=True)
    http_server.listen(options.port, options.host)

    logger.info('api gateway server is running on %s:%s' % (options.host, options.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
