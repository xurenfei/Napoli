# web api

需要开启请先去掉 `nps.conf` 中 `auth_key` 的注释并配置密钥。密钥至少 16 位随机字符串，可用 `openssl rand -hex 16` 生成。

未配置、少于 16 位或使用 `test` 一类弱值时，web api 认证通道保持关闭，不会退化成任何人可计算的固定签名。

## webAPI验证说明

- 采用 auth_key 的验证方式
- 在提交的每个请求后面附带两个参数，`auth_key` 和 `timestamp`

签名为对时间戳的 HMAC SHA256，密钥为配置文件中的 auth_key，输出十六进制小写

```
auth_key = hex(hmac_sha256(配置文件中的auth_key, 当前时间戳))
```

```
timestamp为当前时间戳，单位秒
```

**注意：** 时间戳与服务端偏差不能超过 20 秒，每次提交请求必须重新生成。

Python 示例

```python
import hashlib
import hmac
import time

import requests

AUTH_KEY = b"替换为配置文件中的 auth_key"
timestamp = int(time.time())
signature = hmac.new(AUTH_KEY, str(timestamp).encode(), hashlib.sha256).hexdigest()

r = requests.post(
    "http://127.0.0.1:8080/client/list",
    data={"auth_key": signature, "timestamp": timestamp, "offset": 0, "limit": 10},
)
print(r.status_code, r.text)
```

## 获取服务端时间

由于服务端与 api 请求的客户端时间差异不能太大，所以提供了一个可以获取服务端时间的接口

```
POST /auth/gettime
```

## 获取服务端authKey

服务端提供获取 authKey 的接口

```
POST /auth/getauthkey
```

将返回加密后的 authKey，采用 aes cbc 加密，请使用与服务端配置文件中 auth_crypt_key 相同的密钥进行解密。

**注意：** 该接口只允许本机来源或已登录管理员调用。`auth_crypt_key` 需为 16 位，且不能使用官方示例值 `1234567812345678`，该值公开可解密。

- 解密密钥长度 128
- 偏移量与密钥相同
- 补码方式 pkcs5padding
- 解密串编码方式 十六进制

## 详细文档

- **[详见](webapi.md)** (感谢@avengexyz)
