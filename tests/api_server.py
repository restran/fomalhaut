#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.gen
import tornado.httpclient
import tornado.concurrent
import tornado.ioloop
import logging

from tornado.options import define, options

logger = logging.getLogger(__file__)

define("host", default='127.0.0.1', help="run on the given host", type=str)
define("port", default=8000, help="run on the given port", type=int)


class APIHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("get")

    def post(self):
        self.write('post')
        self.write(self.request.body)


if __name__ == '__main__':
    tornado.options.parse_command_line()
    handlers = [
        (r'/resource', APIHandler),
    ]
    app = tornado.web.Application(handlers=handlers, debug=True)
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
    options.logging = logging.DEBUG
    tornado.options.parse_command_line()

    http_server = tornado.httpserver.HTTPServer(app, xheaders=True)
    http_server.listen(options.port, options.host)

    logger.info('api server is running on %s:%s' % (options.host, options.port))
    tornado.ioloop.IOLoop.instance().start()
