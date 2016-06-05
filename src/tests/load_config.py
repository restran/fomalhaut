# -*- coding: utf-8 -*-
# created by restran on 2016/04/10
from __future__ import unicode_literals, absolute_import

import redis

import settings

app_test = """{
    "access_key": "abcd",
    "login_auth_url": "http://127.0.0.1:8001/login/",
    "access_token_ex": 864000,
    "name": "test_client",
    "enable": true,
    "secret_key": "1234",
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
            "async_http_connect_timeout": 20,
            "version": "v1",
            "async_http_request_timeout": 20
        }
    },
    "memo": "",
    "refresh_token_ex": 1728000,
    "id": 3
}
"""

app_public = """{
    "access_key": "public",
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
    client = redis.StrictRedis(
        host=settings.REDIS_HOST, port=settings.REDIS_PORT,
        db=settings.REDIS_DB, password=settings.REDIS_PASSWORD
    )

    client.set('config:public', app_public)
    client.set('config:abcd', app_test)


if __name__ == '__main__':
    main()
