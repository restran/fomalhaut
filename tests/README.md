
## Redis 中需要先设置 client 的配置信息

可以通过导入 export_config.json 到 api-gateway-dashboard 中, 然后再同步到 Redis 中

Redis 中存储的数据如下所示:

    key: `config:abcd`

```json
{
    "access_key": "abcd",
    "enable": true,
    "name": "test_client",
    "memo": "",
    "secret_key": "1234",
    "endpoints": {
        "test_api:v1": {
            "unique_name": "测试API",
            "enable": true,
            "memo": "",
            "netloc": "127.0.0.1:8001",
            "enable_acl": true,
            "id": 2,
            "name": "test_api",
            "url": "http://127.0.0.1:8001",
            "acl_rules": [
                {
                    "re_uri": "^/forbidden.*",
                    "is_permit": false,
                    "id": 10,
                    "endpoint_id": 2
                },
                {
                    "re_uri": "^/resource",
                    "is_permit": true,
                    "id": 11,
                    "endpoint_id": 2
                }
            ],
            "async_http_connect_timeout": 20,
            "version": "v1",
            "async_http_request_timeout": 20
        }
    },
    "id": 3
}
```