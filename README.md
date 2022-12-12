# 将普通的订阅转一下

## 部署
```
docker run -d -p 8080:80 colindy/clashconv:x86_64
```

## 使用
http://localhost:8080/clashconv?url=https://aa.bb.com/subscribe?token=TOKEN

## 自编译
```
docker build -t clashconv .
docker run -d -p 8080:80 clashconv
```
