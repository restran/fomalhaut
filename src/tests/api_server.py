#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals, absolute_import

import tornado.httpserver
import tornado.ioloop
import tornado.web
from tornado.escape import json_encode
import logging
import json
from future.utils import binary_type
import tornado

from tornado.options import define, options

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__file__)

define('host', default='127.0.0.1', help='run on the given host', type=str)
define('port', default=8001, help='run on the given port', type=int)


class APIStatusCode(object):
    SUCCESS = 200  # 成功
    FAIL = 400  # 客户端的错误, 例如请求信息不正确
    ERROR = 500  # 服务端的错误, 例如出现异常


class BaseHandler(tornado.web.RequestHandler):
    def __init__(self, app, request, **kwargs):
        super(BaseHandler, self).__init__(app, request, **kwargs)
        self.post_data = {}

    def initialize(self, *args, **kwargs):
        self.set_header('Content-Type', 'application/json; charset=utf-8')

    def prepare(self):
        if self.request.method == 'POST':
            content_type = self.request.headers.get('Content-Type', '').lower()
            if content_type.startswith('application/json'):
                try:
                    self.post_data = json.loads(self.request.body)
                except Exception as e:
                    logger.error(e)
            logger.debug(content_type)
            logger.debug(self.request.body)

    def success(self, data=None, msg=''):
        json_str = json.dumps({
            'code': APIStatusCode.SUCCESS, 'data': data,
            'msg': msg}, ensure_ascii=False)
        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)

    def fail(self, data=None, msg='', code=APIStatusCode.FAIL):
        json_str = json.dumps({
            'code': code, 'data': data, 'msg': msg
        }, ensure_ascii=False)

        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)

    def error(self, data=None, msg='', code=APIStatusCode.ERROR):
        json_str = json.dumps({
            'code': code, 'data': data, 'msg': msg
        }, ensure_ascii=False)
        logger.debug(json_str)
        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)


class ResourceHandler(BaseHandler):
    def get(self):
        content_type = self.request.headers.get('Content-Type')
        if content_type:
            self.set_header('Content-Type', content_type)

        self.write('get')

    def post(self):
        content_type = self.request.headers.get('Content-Type')
        if content_type:
            self.set_header('Content-Type', content_type)

        # logger.debug(self.request.body)
        self.write(self.request.body)


class ForbiddenHandler(BaseHandler):
    """
    禁止访问
    """
    def get(self):
        self.write('forbidden get')

    def post(self):
        self.write('forbidden post')


class LoginHandler(BaseHandler):
    def post(self):
        logger.debug(self.request.body)
        name = self.post_data['name']
        password = self.post_data['password']
        if name == 'name' and password == 'password':
            user_info = {
                'id': 1,
                'name': 'name'
            }
            self.success(user_info)
        else:
            self.fail()


class ProtectedHandler(BaseHandler):
    """
    需要登录才能访问的 API
    """
    def get(self):
        self.success()

    def post(self):
        self.success(self.post_data)


if __name__ == '__main__':
    tornado.options.parse_command_line()
    handlers = [
        (r'/login/?', LoginHandler),
        (r'/protected/?', ProtectedHandler),
        (r'/forbidden/?', ForbiddenHandler),
        (r'/resource/?', ResourceHandler),
    ]
    app = tornado.web.Application(handlers=handlers, debug=True)
    options.logging = binary_type('DEBUG')
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(app, xheaders=True)
    http_server.listen(options.port, options.host)

    logger.info('api server is running on %s:%s' % (options.host, options.port))
    tornado.ioloop.IOLoop.instance().start()
