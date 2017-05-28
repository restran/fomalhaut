# -*- coding: utf-8 -*-
# Created on 2016/5/27
from __future__ import unicode_literals, absolute_import

__author__ = 'restran'


class PromptMessage(object):
    """提示信息"""
    FAIL_TO_REQ_LOGIN_URL = '无法访问登录 API'
    ENDPOINT_UNAVAILABLE = '无法访问 Endpoint'

    NO_AUTH_LOGIN_URL_CONFIG = '缺失配置登录验证 URL'
    NO_AUTH_LOGIN_SMS_URL_CONFIG = '缺失配置短信登录验证 URL'
    NO_CHANGE_PASSWORD_URL_CONFIG = '缺失配置修改密码 URL'
    NO_CHANGE_PASSWORD_SMS_URL_CONFIG = '缺失配置通过短信验证码修改密码 URL'
    NO_SET_PASSWORD_SMS_URL_CONFIG = '缺失配置设置密码 URL'

    BAD_ENDPOINT_RESPONSE = 'Endpoint 返回数据格式不正确'
    BAD_LOGIN_INFO = '登录失败，用户名或密码错误'
    SAVE_ACCESS_TOKEN_ERROR = '存储 AccessToken 失败'
    INVALID_REFRESH_TOKEN = '无效或过期的 RefreshToken'
    NO_CLIENT_CONFIG = '无法获取到 Client 配置信息'
    DISABLED_CLIENT = '该 Client 已被禁用'
    DISABLED_ENDPOINT = '该 Endpoint 已被禁用'
    BAD_CLIENT_CONFIG = 'Client 配置信息不正确'

    NO_PERMISSION = '没有访问权限'
    # --------------------------------
    INVALID_SIGNATURE = 'Signature 参数不正确'
    EXPIRED_SIGNATURE = 'Signature 参数已过期'
    NO_SIGNATURE_PROVIDED = 'Signature 参数缺失'
    INVALID_TIMESTAMP = 'Timestamp 参数不正确'
    # --------------------------------
    AES_DECRYPT_ERROR = 'AES 解密失败'
    AES_ENCRYPT_ERROR = 'AES 加密失败'
    # －－－－－－－－－－－－－－－－－－－－－－
    NO_ENDPOINT_URL_CONFIG = '请求的 Endpoint 缺失配置转发 Url'

    EXPIRED_OR_INVALID_ACCESS_TOKEN = 'AccessToken 无效或已过期'
    INVALID_REQUEST_URI = 'URI 格式不正确，无法识别请求的 API'
    INVALID_REQUEST_DATA = '提交的数据格式不正确'
    LOGOUT_SUCCESS = '注销成功'
    CHANGE_PASSWORD_SUCCESS = '密码修改成功'
    CHANGE_PASSWORD_FAIL = '密码修改失败'
    SET_PASSWORD_SUCCESS = '密码设置成功'
    SET_PASSWORD_FAIL = '密码设置失败'

    SYSTEM_MAINTENANCE_TIPS = '系统维护中，部分功能无法正常使用，请稍后再访问'
