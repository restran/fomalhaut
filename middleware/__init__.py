#!/usr/bin/env python
# -*- coding: utf-8 -*-
# created by restran on 2015/12/19


class BaseMiddleware(object):
    """
    中间件的基类
    """

    def __init__(self, handler):
        self.handler = handler

    """ 子类根据要处理的时机,实现对应的方法

    def process_request(self, *args, **kwargs):
        pass

    def process_response(self, *args, **kwargs):
        pass

    def process_finished(self, *args, **kwargs):
        pass
    """
