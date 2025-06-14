- 现在你可以通过以下方式设置环境变量：
- Fork本项目到你的仓库，然后deno控制台选择New Project，搜索项目spassword-deno，拉到最下面Entrypoint选择main.ts部署
- 首先去https://connect.linux.do/ 申请接入
2. **在Deno添加环境变量**：
在控制台点击KV获取连接，然后填入变量DENO_KV_URL
```env
DENO_KV_URL=https://api.deno.com/databases/xxxxxxxxxxxxxxxx/connect
OAUTH_BASE_URL=[your_oauth_base_url](https://connect.linux.do)
OAUTH_CLIENT_ID=connect.linux.do申请到的your_client_id
OAUTH_CLIENT_SECRET=connect.linux.do申请到的your_client_secret
OAUTH_REDIRECT_URI=https://修改为你的.deno.dev/api/oauth/callback
OAUTH_ID=your_authorized_user_id
```


主要改进：

1. **环境变量配置**：将 KV URL 作为环境变量 `DENO_KV_URL`，如果未设置则使用默认值
2. **错误处理**：如果远程 KV 连接失败，会自动尝试使用本地 KV
3. **连接日志**：显示正在连接的 KV URL，便于调试
4. **灵活配置**：可以通过环境变量轻松更改 KV 连接地址

