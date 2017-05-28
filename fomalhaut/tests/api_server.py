#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/21

from __future__ import unicode_literals, absolute_import

import json
import logging
import tornado.web
from tornado import ioloop, httpserver
from tornado.escape import native_str, json_decode
from tornado.options import define, options
from tornado import gen
import traceback
from base64 import b64decode

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__file__)

define('host', default='127.0.0.1', help='run on the given host', type=str)
define('port', default=8001, help='run on the given port', type=int)


class APIStatusCode(object):
    SUCCESS = 200  # 成功
    FAIL = 400  # 客户端的错误, 例如请求信息不正确
    ERROR = 500  # 服务端的错误, 例如出现异常
    FORBIDDEN = 403  # 禁止访问


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
                    self.post_data = json_decode(self.request.body)
                except Exception as e:
                    logger.error(e)
            logger.debug(content_type)
            logger.debug(self.request.body)

    def _write_json(self, code, data, msg):
        ret_data = {
            'code': code,
            'data': data,
            'msg': msg
        }
        # ensure_ascii=False，确保中文不会被转成 unicode 字符串格式
        json_str = json.dumps(ret_data, ensure_ascii=True)
        try:
            self.write(json_str)
            self.finish()
        except Exception as e:
            logger.error(e)
            logger.error(traceback.format_exc())

    def success(self, data=None, msg=''):
        self._write_json(APIStatusCode.SUCCESS, data, msg)

    def fail(self, data=None, msg='', code=APIStatusCode.FAIL):
        self._write_json(code, data, msg)

    def error(self, data=None, msg='', code=APIStatusCode.ERROR):
        self._write_json(code, data, msg)

    def forbidden(self, data=None, msg='', code=APIStatusCode.FORBIDDEN):
        self._write_json(code, data, msg)


class SleepHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        content_type = self.request.headers.get('Content-Type')
        if content_type:
            self.set_header('Content-Type', content_type)
        yield gen.sleep(1)
        self.write('get')


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

    def head(self):
        self.get()

    def options(self):
        self.get()

    def put(self):
        self.write('put')

    def delete(self):
        self.write('delete')


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


class SMSLoginHandler(BaseHandler):
    def post(self):
        logger.debug(self.request.body)
        name = self.post_data['name']
        sms_code = self.post_data['sms_code']
        if name == 'name' and sms_code == '1234':
            user_info = {
                'id': 1,
                'name': 'name'
            }
            self.success(user_info)
        else:
            self.fail()


class ChangePasswordHandler(BaseHandler):
    def post(self):
        user_info = b64decode(self.request.headers['X-User-Json'])
        user_info = json_decode(user_info)
        logger.debug(user_info)
        change_type = self.get_query_argument('change_type', 'password')
        if change_type == 'sms':
            self.success()
        else:
            old_password = self.post_data['old_password']
            new_password = self.post_data['new_password']
            if old_password != new_password:
                self.success()
            else:
                self.fail()


class SetPasswordHandler(BaseHandler):
    def post(self):
        user_info = b64decode(self.request.headers['X-User-Json'])
        user_info = json_decode(user_info)
        logger.debug(user_info)
        new_password = self.post_data['new_password']
        self.success(data=new_password)


class ProtectedHandler(BaseHandler):
    """
    需要登录才能访问的 API
    """

    def get(self):
        self.success()

    def post(self):
        self.success(self.post_data)


def main():
    options.parse_command_line()
    handlers = [
        (r'/login/?', LoginHandler),
        (r'/login/sms/?', SMSLoginHandler),
        (r'/password/change/?', ChangePasswordHandler),
        (r'/protected/?', ProtectedHandler),
        (r'/forbidden/?', ForbiddenHandler),
        (r'/resource/?', ResourceHandler),
        (r'/sleep/?', SleepHandler),
        (r'/?', ResourceHandler),
    ]
    app = tornado.web.Application(handlers=handlers, debug=True)
    options.logging = native_str('DEBUG')
    options.parse_command_line()
    http_server = httpserver.HTTPServer(app, xheaders=True)
    http_server.listen(options.port, options.host)

    logger.info('api server is running on %s:%s' % (options.host, options.port))
    ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    main()
