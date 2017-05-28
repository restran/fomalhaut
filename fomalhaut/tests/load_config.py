# -*- coding: utf-8 -*-
# created by restran on 2016/04/10
from __future__ import unicode_literals, absolute_import

import redis
import sys
from .. import settings

app_test = """{
    "app_id": "abcd",
    "login_auth_url": "http://127.0.0.1:8001/login/",
    "sms_login_auth_url": "http://127.0.0.1:8001/login/sms/",
    "sms_change_password_url": "http://127.0.0.1:8001/password/change/?change_type=sms",
    "change_password_url": "http://127.0.0.1:8001/password/change/",
    "access_token_ex": 864000,
    "refresh_token_ex": 1728000,
    "name": "test_client",
    "enable": true,
    "secret_key": "1234",
    "memo": "",
    "id": 3,
    "endpoints": {
        "auth:v1": {
            "unique_name": "Auth",
            "enable": true,
            "require_login": false,
            "netloc": "",
            "memo": "",
            "enable_hmac": true,
            "enable_acl": false,
            "is_builtin": true,
            "id": 4,
            "name": "auth",
            "url": "",
            "acl_rules": [],
            "async_http_connect_timeout": 20,
            "version": "v1",
            "async_http_request_timeout": 20
        },
        "account:v1": {
            "unique_name": "Account",
            "enable": true,
            "require_login": true,
            "netloc": "",
            "memo": "",
            "enable_hmac": true,
            "enable_acl": false,
            "is_builtin": true,
            "id": 5,
            "name": "account",
            "url": "",
            "acl_rules": [],
            "async_http_connect_timeout": 20,
            "version": "v1",
            "async_http_request_timeout": 20
        },
        "test_api:v1": {
            "unique_name": "TestAPI",
            "enable": true,
            "require_login": false,
            "netloc": "127.0.0.1:8001",
            "memo": "",
            "enable_hmac": true,
            "enable_acl": true,
            "is_builtin": false,
            "id": 2,
            "name": "test_api",
            "url": "http://127.0.0.1:8001",
            "acl_rules": [
                {
                    "re_uri": "^/forbidden/?",
                    "is_permit": false,
                    "id": 27,
                    "endpoint_id": 2
                },
                {
                    "re_uri": "^/resource/?",
                    "is_permit": true,
                    "id": 28,
                    "endpoint_id": 2
                }
            ],
            "skip_uri": false,
            "async_http_connect_timeout": 20,
            "version": "v1",
            "async_http_request_timeout": 20
        },
        "test_api_login:v1": {
            "unique_name": "TestAPILogin",
            "enable": true,
            "require_login": true,
            "netloc": "127.0.0.1:8001",
            "memo": "",
            "enable_hmac": true,
            "enable_acl": true,
            "is_builtin": false,
            "id": 3,
            "name": "test_api_login",
            "url": "http://127.0.0.1:8001",
            "acl_rules": [
                {
                    "re_uri": "^/login/?",
                    "is_permit": false,
                    "id": 31,
                    "endpoint_id": 3
                }
            ],
            "skip_uri": false,
            "async_http_connect_timeout": 20,
            "version": "v1",
            "async_http_request_timeout": 20
        }
    }
}
"""

app_public = """{
    "app_id": "public",
    "login_auth_url": "",
    "access_token_ex": 864000,
    "name": "public-app",
    "enable": true,
    "secret_key": "a5f45165bc1db7b4b32d98705f114a43247a63e0",
    "endpoints": {
        "public:v1": {
            "unique_name": "public-api",
            "enable": true,
            "require_login": false,
            "netloc": "127.0.0.1:8001",
            "memo": "",
            "enable_hmac": false,
            "enable_acl": false,
            "is_builtin": false,
            "id": 5,
            "name": "public",
            "url": "http://127.0.0.1:8001",
            "acl_rules": [],
            "async_http_connect_timeout": 20,
            "version": "v1",
            "async_http_request_timeout": 20
        }
    },
    "memo": "",
    "refresh_token_ex": 1728000,
    "id": 5
}
"""


def main():
    # 如果是在 gitlab-ci 环境下运行，redis 的主机需要设置为 redis，同时没有密码
    if len(sys.argv) > 1 and sys.argv[1] == 'gitlab_ci':
        settings.REDIS_HOST = 'redis'
        settings.REDIS_PASSWORD = None

    client = redis.StrictRedis(
        host=settings.REDIS_HOST, port=settings.REDIS_PORT,
        db=settings.REDIS_DB, password=settings.REDIS_PASSWORD
    )

    client.set('config:public', app_public)
    client.set('config:abcd', app_test)


if __name__ == '__main__':
    main()
