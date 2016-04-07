
## Redis 中需要先设置 client 的配置信息

可以通过导入 export_config.json 到 api-gateway-dashboard 中, 然后再同步到 Redis 中

Redis 中存储的数据如下所示:

    key: `config:abcd`

```json
{
    "access_key": "abcd",
    "login_auth_url": "http://127.0.0.1:8001/login/",
    "access_token_ex": 864000,
    "name": "test_client",
    "enable": true,
    "secret_key": "1234",
    "endpoints": {
        "test_api:v1": {
            "unique_name": "TestAPI",
            "enable": true,
            "require_login": false,
            "netloc": "127.0.0.1:8001",
            "enable_acl": true,
            "async_http_request_timeout": 20,
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
            "memo": ""
        },
        "test_api_login:v1": {
            "unique_name": "TestAPILogin",
            "enable": true,
            "require_login": true,
            "netloc": "127.0.0.1:8001",
            "enable_acl": true,
            "async_http_request_timeout": 20,
            "id": 3,
            "name": "test_api_login",
            "url": "http://127.0.0.1:8001",
            "acl_rules": [
                {
                    "re_uri": "^/login/?",
                    "is_permit": false,
                    "id": 29,
                    "endpoint_id": 3
                }
            ],
            "async_http_connect_timeout": 20,
            "version": "v1",
            "memo": ""
        }
    },
    "memo": "",
    "refresh_token_ex": 1728000,
    "id": 3
}
```

key: `config:public`

```json
{
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
```