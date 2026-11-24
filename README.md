# 文件上传服务

基于 Python 2.7 的单文件 Web 文件上传服务，无第三方依赖、无数据库。iOS 风格 + 科技感界面，侧边导航栏；带登录遮罩与动态验证码；浏览器拖拽/多选上传，分片传输支持任意大小文件，实时显示上传速度；文件列表支持下载、删除，保存目录可在页面上热切换。

## 功能特性

- **登录鉴权**：全页面遮罩式登录，内置动态验证码（SVG 图片，点击刷新，一次性有效），会话有效期 12 小时并自动续期；所有接口均需登录后访问
- **文件大小不限**：前端按分片（默认 8MB）切片上传，服务端流式写入磁盘，不占内存、不受单请求体积限制
- **实时速度显示**：每个文件的进度条、百分比、已传/总大小、实时速度、剩余时间，以及全局总速度汇总
- **多文件并发**：支持拖拽或多选批量上传，最多 3 个文件同时传输
- **目录可定义**：启动时用 `--dir` 指定（默认 `/file`），页面侧边栏「保存目录」可热切换，切换结果持久化，重启自动恢复
- **文件列表**：实时读取目录生成（名称/大小/修改时间），支持刷新、下载、删除，无需数据库
- **界面**：iOS 设计语言（系统色板、毛玻璃、大圆角）叠加科技感动效（极光背景、网格底纹、雷达状态脉冲、流光进度条）；侧边导航栏 + 右上角实时时钟与服务状态徽标
- **零依赖**：仅用 Python 标准库，拷贝两个文件即可部署

## 环境要求

- Python 2.7（CentOS 7 等系统自带）；代码兼容 Python 3，但按 Python 2 优化了编码处理
- Linux / Windows 均可运行

## 快速开始

### 一键启动（推荐）

```bash
chmod +x start.sh
./start.sh                        # 默认目录 /file，端口 8000
```

指定目录和端口：

```bash
UPLOAD_DIR=/data/files UPLOAD_PORT=9000 ./start.sh
```

常用命令：

```bash
./start.sh stop                   # 停止
./start.sh restart                # 重启
./start.sh status                 # 查看状态
```

启动日志写入 `upload_server.log`，进程 PID 写入 `upload_server.pid`。

### 手动启动

```bash
python upload_server.py                           # 默认 /file，端口 8000
python upload_server.py --dir /data/files --port 9000
```

### 启动参数

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `--dir` | `UPLOAD_DIR` | `/file` | 上传保存目录，不存在会自动创建 |
| `--port` | `UPLOAD_PORT` | `8000` | 监听端口 |
| `--host` | — | `0.0.0.0` | 监听地址 |
| `--chunk-size` | `UPLOAD_CHUNK_MB` | `8` | 分片大小（MB） |
| `--user` | `AUTH_USER` | `admin` | 登录用户名 |
| `--password` | `AUTH_PASSWORD` | `Kingsha@2026` | 登录密码，**生产环境务必修改** |

## 登录与鉴权

- 默认账号 `admin` / `Kingsha@2026`，可通过启动参数或环境变量覆盖
- 登录需输入动态验证码：SVG 图片验证码，点击图片可刷新，验证码 5 分钟内有效且一次性使用
- 登录成功后签发随机 token，存于浏览器 localStorage，会话 12 小时有效，活跃使用自动续期
- 侧边栏「退出登录」可注销当前会话；token 失效后自动弹出登录遮罩
- 所有数据接口（列表/上传/下载/删除/切目录）均需携带 token（请求头 `X-Auth-Token` 或 URL 参数 `?token=`）

## 页面操作

- **上传**：把文件拖入虚线框（悬停有 HUD 边角点亮），或点击「选择文件」（可多选）；上传完成后文件自动出现在列表
- **速度**：上传队列卡片实时显示每个文件的进度（流光进度条）、速度、剩余时间和总速度
- **取消**：上传中点击任务右侧 × 可取消
- **切换目录**：点击侧边栏「保存目录」，输入服务器绝对路径后回车；目录不存在会自动创建，列表随之刷新
- **列表**：显示文件名、大小、修改时间；「下载」保存到本地，「删除」需二次确认
- **导航**：侧边栏「上传中心」「文件列表」点击平滑滚动定位；右上角显示实时时钟（含星期）和服务状态徽标（绿点脉冲 = 运行中，红点 = 连接失败，悬停显示已运行时长，每 30 秒自动检测）
- **账号**：侧边栏底部「修改密码」「退出登录」

## HTTP 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/` | 公开 | 上传页面（未登录显示登录遮罩） |
| GET | `/api/captcha?cid=` | 公开 | 获取动态验证码 SVG |
| POST | `/api/login` | 公开 | 登录，body `{"user":"","password":"","cid":"","captcha":""}` |
| POST | `/api/logout` | 登录 | 注销当前会话 |
| GET | `/api/info` | 登录 | 当前目录、分片大小、服务运行时长（用于右上角状态徽标） |
| GET | `/api/files` | 登录 | 文件列表（名称/大小/修改时间/总数） |
| POST | `/api/upload?name=&uid=&index=&total=` | 登录 | 分片上传，body 为二进制分片 |
| POST | `/api/delete` | 登录 | 删除文件，body `{"name":"文件名"}` |
| POST | `/api/setdir` | 登录 | 切换保存目录，body `{"dir":"/data/files"}` |
| POST | `/api/passwd` | 登录 | 修改账号密码，body `{"old_password":"","new_user":"","new_password":""}` |
| GET | `/download?name=` | 登录 | 下载文件 |

除 `/` 和验证码/登录接口外，所有接口需携带 token：请求头 `X-Auth-Token: <token>` 或 URL 参数 `?token=<token>`。

## 防火墙放行

```bash
# firewalld（CentOS 7）
firewall-cmd --permanent --add-port=8000/tcp && firewall-cmd --reload

# iptables
iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
```

云服务器还需在控制台**安全组**放行对应端口——这是"IP+端口打不开"最常见的原因。

## 注册为系统服务（可选）

创建 `/etc/systemd/system/upload-server.service`：

```ini
[Unit]
Description=File Upload Server
After=network.target

[Service]
ExecStart=/usr/bin/python2 /opt/upload/upload_server.py --dir /file --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload && systemctl enable --now upload-server
```

## 修改账号密码

登录后点击侧边栏「**修改密码**」：输入当前密码验证身份，可同时修改用户名和密码（新密码至少 6 位）。修改后立即生效并持久化，当前会话保持有效，下次登录使用新账号密码。

密码以「带盐 SHA-256 哈希」存储在状态文件 `upload_dir.json`（`pwd_hash` 字段），文件中不保存明文密码。

## 忘记密码怎么办

提供两种服务器端找回方式：

**方式一：交互式重置（推荐）**

```bash
python upload_server.py --reset-password
# 按提示输入用户名和新密码（两次确认），然后重启服务
./start.sh restart
```

**方式二：恢复默认账号**

删除状态文件（或仅删除其中的 `user` 和 `pwd_hash` 字段）后重启，账号恢复为 `admin` / `Kingsha@2026`：

```bash
rm upload_dir.json        # 注意：会同时丢失目录切换的持久化记录
./start.sh restart
```

> 两种方式都需要登录服务器操作，因此内网工具无需邮件/短信找回通道。

## 部署到其他服务器

整个服务只需 2 个文件：`upload_server.py`（服务本体）和 `start.sh`（管理脚本）。

**方式一：使用发布包**

把 `upload_server_v1.0.tar.gz` 拷贝到目标服务器任意目录：

```bash
tar xzf upload_server_v1.0.tar.gz -C /opt/upload   # 解压（目录可自定义）
cd /opt/upload
./start.sh                                          # 启动，默认 /file 目录、8000 端口
```

**方式二：仅拷贝两个文件**

```bash
scp upload_server.py start.sh user@服务器:/opt/upload/
ssh user@服务器 'cd /opt/upload && chmod +x start.sh && ./start.sh'
```

**部署后三步检查**：

```bash
./start.sh status                                  # 1. 进程与端口正常
curl http://127.0.0.1:8000/ -o /dev/null -w '%{http_code}\n'   # 2. 本机返回 200
# 3. 浏览器打开 http://服务器IP:8000/ ——打不开就是防火墙/安全组没放行
```

跨版本说明：目标服务器没有 python2 时脚本会自动回退用 python3 启动（代码双版本兼容）。注册 systemd 开机自启见上文「注册为系统服务」章节。

## 注意事项

- **务必修改默认密码**：通过 `--password` 或环境变量 `AUTH_PASSWORD` 设置强密码；有登录鉴权但无账号体系，所有使用者共享同一账号
- **同名覆盖**：上传同名文件会直接替换已有文件
- **目录切换持久化**：页面上切换的目录会写入服务所在目录的 `upload_dir.json`，重启后自动恢复；保存的目录已不存在或状态文件损坏时，回退到 `--dir` 指定的目录
- **系统目录保护**：页面切换目录时禁止 `/`、`/etc`、`/usr`、`/bin` 等系统关键目录（其子目录不受限制）
- **中断恢复**：服务启动时自动清理 12 小时前因异常中断遗留的分片临时文件（位于上传目录的 `.tmp` 子目录）

## 故障排查

| 现象 | 排查 |
|---|---|
| 页面打不开 | 服务器上 `curl http://127.0.0.1:8000/api/info` 通 → 检查防火墙/安全组；不通 → 看 `upload_server.log` |
| 返回 404/502 | 端口可能被其他程序（如 nginx、管理面板）占用，用 `netstat -tlnp` 确认后换端口启动 |
| 上传速度慢 | 属于网络带宽限制，服务端本身无额外开销 |
| 中文文件名乱码 | 服务器文件系统需为 UTF-8 编码（`locale` 查看），CentOS 7 默认满足 |

## 文件清单

```
upload_server.py    # 服务本体（含内嵌页面），单文件
start.sh            # 一键启动/停止/重启/状态脚本
upload_dir.json     # 目录切换持久化状态文件（首次切换目录后自动生成）
```
