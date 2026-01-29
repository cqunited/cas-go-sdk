package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	cas "github.com/cqunited/cas-go-sdk"
)

// 配置 - 根据实际情况修改
const (
	// CAS 服务器地址 (统一身份认证平台)
	casServerURL = "https://ids.example.com/authserver"
	// 本应用地址
	serviceURL = "http://localhost:8080"
)

var (
	casClient    *cas.Client
	sessionStore cas.SessionStore
)

func main() {
	// 初始化 CAS 客户端
	casClient = cas.NewClient(casServerURL, serviceURL)

	// 初始化会话存储 (开发环境使用内存存储，生产环境建议使用 Redis)
	sessionStore = cas.NewMemorySessionStore("cas_session", 3600)

	// 创建中间件
	middleware := cas.NewMiddleware(casClient, sessionStore)
	middleware.IgnorePaths = []string{"/", "/logout", "/health"}

	// 路由设置
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.Handle("/protected", middleware.Handler(http.HandlerFunc(protectedHandler)))
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/health", healthHandler)

	log.Println("Server starting on :8080")
	log.Println("Login URL:", casClient.GetLoginURL())
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>CAS Demo</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>CAS 单点登录示例</h1>
    <p>这是一个使用 Go CAS SDK 的示例应用</p>
    <ul>
        <li><a href="/login">登录</a></li>
        <li><a href="/protected">受保护页面</a></li>
        <li><a href="/logout">登出</a></li>
    </ul>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, tmpl)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// 检查是否已有 ticket
	ticket := cas.GetTicketFromRequest(r)
	if ticket != "" {
		// 验证 ticket
		user, err := casClient.ValidateTicket(ticket)
		if err != nil {
			log.Printf("Ticket validation failed: %v", err)
			http.Error(w, "认证失败: "+err.Error(), http.StatusUnauthorized)
			return
		}

		// 保存会话
		if err := sessionStore.Set(w, r, user); err != nil {
			log.Printf("Failed to save session: %v", err)
			http.Error(w, "会话创建失败", http.StatusInternalServerError)
			return
		}

		// 重定向到受保护页面
		http.Redirect(w, r, "/protected", http.StatusFound)
		return
	}

	// 没有 ticket，重定向到 CAS 登录页面
	casClient.RedirectToLogin(w, r)
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// 从上下文获取用户信息
	user := cas.GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "未授权", http.StatusUnauthorized)
		return
	}

	tmpl := template.Must(template.New("protected").Parse(`<!DOCTYPE html>
<html>
<head>
    <title>受保护页面</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>欢迎, {{.User}}!</h1>
    <h2>用户属性:</h2>
    <ul>
    {{range $key, $value := .Attributes}}
        <li><strong>{{$key}}:</strong> {{$value}}</li>
    {{end}}
    </ul>
    <p><a href="/logout">登出</a></p>
    <p><a href="/">返回首页</a></p>
</body>
</html>`))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, user)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// 清除本地会话
	sessionStore.Delete(w, r)

	// 重定向到 CAS 登出页面
	logoutURL := casClient.GetLogoutURLWithService(serviceURL)
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}
