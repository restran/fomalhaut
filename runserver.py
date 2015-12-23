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

from utils import RedisHelper, import_string
from utils import text_type, binary_type
from handlers.proxy import ProxyHandler
import settings

logger = logging.getLogger(__name__)

define("host", default=settings.HOST, help="run on the given host", type=str)
define("port", default=settings.PORT, help="run on the given port", type=int)


class Application(web.Application):
    def __init__(self):
        tornado_settings = dict(
            template_path=settings.TEMPLATE_PATH,
            # 不能设置 static 目录，否则所有以 /static/ 开头的 url 都不会去请求远端的网站
            # static_path=os.path.join(os.path.dirname(__file__), "static"),
            # autoreload=True, # debug 模式会自动 autoreload
            debug=settings.DEBUG,
        )

        self.request_middleware = []
        self.response_middleware = []
        self.finished_middleware = []
        self.load_middleware()

        handlers = [(r'/.*', ProxyHandler)]
        web.Application.__init__(self, handlers, **tornado_settings)

    def load_middleware(self):
        """
        从 settings.MIDDLEWARE_CLASSES 载入中间件
        """

        for middleware_path in settings.MIDDLEWARE_CLASSES:
            mw_class = import_string(middleware_path)

            # 将中间件对应的方法存入列表中
            if hasattr(mw_class, 'process_request'):
                self.request_middleware.append(mw_class)
            if hasattr(mw_class, 'process_response'):
                self.response_middleware.insert(0, mw_class)
            if hasattr(mw_class, 'process_finished'):
                self.finished_middleware.insert(0, mw_class)

        logger.debug(self.request_middleware)
        logger.debug(self.response_middleware)
        logger.debug(self.finished_middleware)

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

    logger.info('tornado server is running on %s:%s' % (options.host, options.port))
    tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
