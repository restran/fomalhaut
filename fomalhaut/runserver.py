#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19
from __future__ import unicode_literals, absolute_import

import logging
import sys
import signal
import tornado
import time
from tornado import httpserver, ioloop, web
from tornado.httputil import native_str
from tornado.options import define, options
from tornado.web import RequestHandler

from fomalhaut import settings
from fomalhaut.handlers.base import BaseHandler
from fomalhaut.utils import RedisHelper, import_string, text_type, PYPY

logger = logging.getLogger(__name__)

MAX_WAIT_SECONDS_BEFORE_SHUTDOWN = 1

define("host", default=settings.HOST, help="run on the given host", type=str)
define("port", default=settings.PORT, help="run on the given port", type=int)
define("gitlab_ci", default=None, help="run on gitlab-ci", type=str)


class FaviconHandler(RequestHandler):
    def get(self):
        self.write('')


class RobotsHandler(RequestHandler):
    def get(self):
        self.set_header('Content-Type', 'text/plain')
        self.write('User-agent: *\nDisallow: /*')


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

        # favicon.ico and robots.txt should be configured in nginx
        handlers = [
            # (r'/favicon.ico', FaviconHandler),
            # (r'/robots.txt', RobotsHandler),
            (r'/.*', BaseHandler),
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
                handler_path = '%s.%s' % (settings.PACKAGE_NAME, handler_path)
                h_class = import_string(handler_path)
                handlers[key].append((reg_uri, h_class))

        self.builtin_endpoints = handlers

    def _load_middleware(self):
        """
        从 settings.MIDDLEWARE_CLASSES 载入中间件
        """

        for middleware_path in settings.MIDDLEWARE_CLASSES:
            middleware_path = '%s.%s' % (settings.PACKAGE_NAME, middleware_path)
            mw_class = import_string(middleware_path)
            self.middleware_list.append(mw_class)

        logger.debug('middleware_list: \n%s' %
                     '\n'.join([text_type(m) for m in self.middleware_list]))


def sig_handler(sig, frame):
    logger.warning('caught signal: %s', sig)
    tornado.ioloop.IOLoop.instance().add_callback(shutdown)


def shutdown():
    logger.info('stopping http server')
    server.stop()

    logger.info('will shutdown in %s seconds...', MAX_WAIT_SECONDS_BEFORE_SHUTDOWN)
    io_loop = tornado.ioloop.IOLoop.instance()

    deadline = time.time() + MAX_WAIT_SECONDS_BEFORE_SHUTDOWN

    def stop_loop():
        now = time.time()
        if now < deadline and (io_loop._callbacks or io_loop._timeouts):
            io_loop.add_timeout(now + 1, stop_loop)
        else:
            io_loop.stop()
            logger.info('shutdown')

    stop_loop()


def main():
    # 重新设置一下日志级别，默认情况下，tornado 是 info
    # py2 下 options.logging 不能是 Unicode
    options.logging = native_str(settings.LOGGING_LEVEL)
    # parse_command_line 的时候将 logging 的根级别设置为 info
    options.parse_command_line()

    # 如果是在 gitlab-ci 环境下运行，redis 的主机需要设置为 redis，同时没有密码
    if options.gitlab_ci is not None:
        settings.REDIS_HOST = 'redis'
        settings.REDIS_PASSWORD = None

    # 启动 tornado 之前，先测试 redis 是否能正常工作
    RedisHelper.ping_redis()

    global server
    app = Application()
    server = httpserver.HTTPServer(app, xheaders=True)
    server.listen(options.port, options.host)
    logger.info('fomalhaut is running on %s:%s' % (options.host, options.port))

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    if sys.version_info >= (3, 5) and not PYPY:
        # python 3.5 以上版本，可以使用 uvloop 来加速
        # https://github.com/MagicStack/uvloop/issues/35
        from tornado.platform.asyncio import AsyncIOMainLoop
        import asyncio
        try:
            import uvloop
            logger.info('use uvloop as ioloop')
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
            AsyncIOMainLoop().install()
            asyncio.get_event_loop().run_forever()
        except:
            ioloop.IOLoop.instance().start()
    else:
        ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
