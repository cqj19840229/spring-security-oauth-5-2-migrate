## 授权码过程

#### 1.请求code

```
http://localhost:8090/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read%20message.write&state=ZQO2qWcYdXZqdPowhhoKdi9vzmko1lIJ2-iwJSg93pI%3D&redirect_uri=http://localhost:8080/client/account/redirect
```
返回
```
https://www.baidu.com/?code=D49RxAebDfN9j_0WyCRpRj4JfDF1fzd42VTm3lyI2iU%3D&state=ZQO2qWcYdXZqdPowhhoKdi9vzmko1lIJ2-iwJSg93pI%3D
```
#### 2.请求code

```
http://localhost:8090/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read%20message.write&state=ZQO2qWcYdXZqdPowhhoKdi9vzmko1lIJ2-iwJSg93pI%3D&redirect_uri=https://www.baidu.com/
```
返回
```
https://www.baidu.com/?code=D49RxAebDfN9j_0WyCRpRj4JfDF1fzd42VTm3lyI2iU%3D&state=ZQO2qWcYdXZqdPowhhoKdi9vzmko1lIJ2-iwJSg93pI%3D
```

