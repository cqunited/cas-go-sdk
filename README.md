# CAS Go SDK

一个用于 Go 语言的 CAS (Central Authentication Service) 客户端 SDK，支持 CAS 2.0 和 SAML 1.1 协议。

## 功能特性

- ✅ CAS 2.0 协议支持
- ✅ SAML 1.1 协议支持
- ✅ Service Ticket 验证
- ✅ Proxy Ticket 验证
- ✅ 单点登录 (SSO)
- ✅ 单点登出 (SLO)
- ✅ HTTP 中间件支持
- ✅ 会话管理 (内存/Cookie)
- ✅ 用户属性解析

## 安装

```bash
go get github.com/cqunited/cas-go-sdk
```

## 快速开始

### 基本使用

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    
    cas "github.com/cqunited/cas-go-sdk"
)

func main() {
    // 创建 CAS 客户端
    client := cas.NewClient(
        "https://ids.example.com/authserver",  // CAS 服务器地址
        "http://localhost:8080",                 // 本应用地址
    )

    http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
        // 检查是否有 ticket
        ticket := cas.GetTicketFromRequest(r)
        if ticket != "" {
            // 验证 ticket
            user, err := client.ValidateTicket(ticket)
            if err != nil {
                http.Error(w, "认证失败", http.StatusUnauthorized)
                return
            }
            fmt.Fprintf(w, "欢迎, %s!", user.User)
            return
        }
        
        // 重定向到 CAS 登录
        client.RedirectToLogin(w, r)
    })

    http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
        http.Redirect(w, r, client.GetLogoutURL(), http.StatusFound)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### 使用中间件

```go
package main

import (
    "net/http"
    
    cas "github.com/cqunited/cas-go-sdk"
)

func main() {
    client := cas.NewClient(
        "https://ids.example.com/authserver",
        "http://localhost:8080",
    )
    
    // 创建会话存储
    sessionStore := cas.NewMemorySessionStore("cas_session", 3600)
    
    // 创建中间件
    middleware := cas.NewMiddleware(client, sessionStore)
    middleware.IgnorePaths = []string{"/", "/health"}

    // 受保护的路由
    http.Handle("/protected", middleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user := cas.GetUserFromContext(r.Context())
        if user != nil {
            fmt.Fprintf(w, "Hello, %s!", user.User)
        }
    })))

    http.ListenAndServe(":8080", nil)
}
```

### SAML 1.1 验证

```go
user, err := client.ValidateSAMLTicket(ticket)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("User: %s\n", user.User)
fmt.Printf("Attributes: %v\n", user.Attributes)
```

## API 参考

### Client

```go
// 创建客户端
client := cas.NewClient(casServerURL, serviceURL)

// 获取登录 URL
loginURL := client.GetLoginURL()
loginURLWithRenew := client.GetLoginURLWithRenew()
loginURLWithGateway := client.GetLoginURLWithGateway()

// 获取登出 URL
logoutURL := client.GetLogoutURL()
logoutURLWithService := client.GetLogoutURLWithService(redirectURL)

// 验证 Ticket
user, err := client.ValidateTicket(ticket)
user, err := client.ValidateProxyTicket(ticket)
user, err := client.ValidateSAMLTicket(ticket)

// 重定向
client.RedirectToLogin(w, r)
client.RedirectToLogout(w, r)
```

### User

```go
type User struct {
    User                string                 // 用户名
    Attributes          map[string]interface{} // 用户属性
    ProxyGrantingTicket string                 // PGT (代理模式)
    Proxies             []string               // 代理链
}
```

### SessionStore

SDK 提供两种会话存储实现：

1. **MemorySessionStore** - 内存存储 (适合开发/测试)
2. **CookieSessionStore** - Cookie 存储 (适合无状态应用)

```go
// 内存存储
store := cas.NewMemorySessionStore("session_name", 3600)

// Cookie 存储
store := cas.NewCookieSessionStore("session_name", 3600, "secret-key")
```

你也可以实现自定义的 `SessionStore` 接口：

```go
type SessionStore interface {
    Get(r *http.Request) (*User, error)
    Set(w http.ResponseWriter, r *http.Request, user *User) error
    Delete(w http.ResponseWriter, r *http.Request) error
}
```

## 配置说明

### CAS 服务器 URL

根据统一身份认证平台的配置：

- 登录地址: `https://ids.example.com/authserver/login`
- 登出地址: `https://ids.example.com/authserver/logout`
- 验证地址: `https://ids.example.com/authserver/serviceValidate`

### SSL 证书

如果 CAS 服务器使用自签名证书，可以配置跳过验证（不推荐用于生产环境）：

```go
import "crypto/tls"

client := cas.NewClient(casServerURL, serviceURL)
client.HTTPClient.Transport = &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```

## 与其他框架集成

### Gin

```go
func CASMiddleware(client *cas.Client, store cas.SessionStore) gin.HandlerFunc {
    return func(c *gin.Context) {
        // 检查会话
        if user, err := store.Get(c.Request); err == nil && user != nil {
            c.Set("user", user)
            c.Next()
            return
        }
        
        // 检查 ticket
        ticket := c.Query("ticket")
        if ticket != "" {
            user, err := client.ValidateTicket(ticket)
            if err != nil {
                c.Redirect(http.StatusFound, client.GetLoginURL())
                c.Abort()
                return
            }
            store.Set(c.Writer, c.Request, user)
            c.Set("user", user)
            c.Next()
            return
        }
        
        c.Redirect(http.StatusFound, client.GetLoginURL())
        c.Abort()
    }
}
```

### Echo

```go
func CASMiddleware(client *cas.Client, store cas.SessionStore) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            // 类似实现...
        }
    }
}
```

## 许可证

MIT

## 参考资料

- [CAS Protocol Specification](https://apereo.github.io/cas/6.6.x/protocol/CAS-Protocol-Specification.html)
- [SAML 1.1 Specification](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=security)
