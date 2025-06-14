- 现在你可以通过以下方式设置环境变量：
- Fork本项目到你的仓库，然后deno控制台选择New Project，搜索项目spassword-deno，拉到最下面Entrypoint选择main.ts部署
- 首先去https://connect.linux.do/ 申请接入
2. **在Deno添加环境变量**：
在控制台点击KV获取连接，然后填入变量DENO_KV_URL
```env
DENOS_KV_URL=https://api.deno.com/databases/xxxxxxxxxxxxxxxx/connect
OAUTH_BASE_URL=https://connect.linux.do
OAUTH_CLIENT_ID=connect.linux.do申请到的your_client_id
OAUTH_CLIENT_SECRET=connect.linux.do申请到的your_client_secret
OAUTH_REDIRECT_URI=https://修改为你的.deno.dev/api/oauth/callback
OAUTH_ID=your_authorized_user_id
```


油猴脚本需要修改www.deno.dev为你部署的地址。有3处替换
