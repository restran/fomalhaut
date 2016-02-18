# API Gateway

API 是连接 App 和服务器数据库的桥梁，在 App 和各种 API 多了之后，对这些 API 的管理和保护就带来了一系列的问题。比如：

1. 如何保护 API 不被非法访问，只能由 App 发起请求？
2. 如何控制不同 App 对 多种多样 API 的访问权限？
3. API 的访问情况怎样，日志如何查看？

于是，就有了 API Gateway 这样的东西。

## 环境及依赖

当前只在 Python 2.7 环境下测试过

```
cerberus>=0.9
requests
six
tornado>=4.0
redis
pycrypto
ConcurrentLogHandler
```

## 相关项目

1. [api-gateway-dashbaord](https://github.com/restran/api-gateway-dashboard) API Gateway 的 Web 控制台
2. [api-python-sdk](https://github.com/restran/api-python-sdk)

## 设计说明

这是一个 JSON API 的网关，实际上不管背后受保护的 API 传输的是什么，都能正常传输，只是网关会在出错时，以 JSON 数据返回错误信息。

当前仅支持 `GET` 和 `POST` 方法。

![img.png](doc/design.png "")

### 特殊状态码

为了区分是网关层面执行时就出现错误返回数据，还是背后真正提供服务的 API 返回的数据，定义一个特殊的`状态码 600`，如果状态码为 600，则表示网关返回的。

### AES 加密

虽然 HTTPS 正在大多数网站中普及，但是如果仍然只能使用 HTTP，数据内容就存在泄漏的风险，因此提供了 AES 加密的功能，可以对传输数据的 URL、Headers、Body 都进行加密，并且会双向验证数据的签名，保证数据没有被篡改。AES 加密是可选的。

### 登录校验

存在这样的情况，有些 API 需要登录后才能访问，有些则无需登录。对于需要登录的 API，则需要先访问登录 API，然后获取一个长期令牌，然后由这个长期令牌生成或者获取短期的访问令牌 `access_token`。

以后访问需要登录的 API 时，就在 URL 参数中带上这个 `access_token`。API Gateway 在遇到访问需要登录的 API 时，就会根据这个 `access_token` 去配置好的 `Auth API` 验证这个 `access_token` 是否有效，并获取该用户的信息。然后将用户信息存储在 Headers 中，以 `X-Api-User-Json` 传递给后端的 API。


## TODO

1. 登录校验
