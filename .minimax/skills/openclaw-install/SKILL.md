---
name: openclaw-install
description: 安装并配置 OpenClaw CLI 工具，适用于 OpenClaw、ClawdBot、MoltBot
---

# Install OpenClaw

安装并配置 OpenClaw CLI 工具。

> 本 skill 适用于安装 **OpenClaw**、**ClawdBot**、**MoltBot**，它们是同一工具的不同名称。

## 前置条件

在开始安装之前，请确保满足以下条件。**如果用户缺少任何依赖，请先帮助用户安装完成后再继续后续步骤。**

### 环境要求

| 依赖 | 最低版本 | 说明 |
|------|----------|------|
| Node.js | 22.0.0+ | 运行时环境，下载地址：https://nodejs.org |
| npm | 10.0.0+ | 包管理器（随 Node.js 一起安装） |
| Git | 2.0+ | 版本控制（可选，部分功能需要） |

#### 检查版本

```bash
node -v    # 应显示 v22.x.x 或更高
npm -v     # 应显示 10.x.x 或更高
```

#### 安装 Node.js（如果缺少）

**推荐使用 nvm 安装**（便于管理多版本）：

- **macOS / Linux**:
  ```bash
  # 安装 nvm（国内用户可使用 gitee 镜像）
  # 海外用户：
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
  # 国内用户：
  curl -o- https://gitee.com/mirrors/nvm/raw/v0.40.1/install.sh | bash
  
  # 重新加载 shell 配置
  source ~/.bashrc  # 或 source ~/.zshrc
  
  # 安装 Node.js 22（国内用户可配置淘宝镜像加速）
  # 国内用户先执行：export NVM_NODEJS_ORG_MIRROR=https://npmmirror.com/mirrors/node
  nvm install 22
  nvm use 22
  ```

- **Windows**: 使用 [nvm-windows](https://github.com/coreybutler/nvm-windows/releases) 或从 https://nodejs.org 下载安装包

**直接安装**（不使用 nvm）：

- **macOS**: `brew install node@22`
- **Windows**: 从 https://nodejs.org 下载安装包
- **Linux (Ubuntu/Debian)**: 
  ```bash
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt-get install -y nodejs
  ```

#### 配置 npm 镜像源（国内用户推荐）

国内用户建议配置淘宝 npm 镜像以加速包下载：

```bash
npm config set registry https://registry.npmmirror.com
```

> 验证配置：`npm config get registry`

### MiniMax OAuth 区域选择

安装过程中需要通过 MiniMax OAuth 进行身份验证。**请让用户确认使用哪个区域**：

| 区域 | 端点 | 适用用户 |
|------|------|----------|
| **Global** | `api.minimax.io` | 海外用户，优化海外访问 |
| **China** | `api.minimaxi.com` | 中国用户，优化国内访问 |

> **注意**：MiniMax OAuth 使用 user-code 登录流程，目前仅支持 Coding plan。如果用户还没有订阅，请前往以下地址：
>
> - 海外用户：👉 **https://platform.minimax.io/subscribe/coding-plan**
> - 国内用户：👉 **https://platform.minimaxi.com/subscribe/coding-plan**

### 用户输入

| 参数 | 说明 |
|------|------|
| `REGION` | 用户选择的区域：`global` 或 `china`（必需） |

**区域与 OAuth method 对应关系**：

| REGION | METHOD |
|--------|--------|
| `global` | `oauth` |
| `china` | `oauth-cn` |

## 步骤

### 1. 安装 OpenClaw

```bash
npm install -g openclaw
```

### 2. 配置 OpenClaw

1. 先执行 `openclaw plugins enable minimax-portal-auth` 启用 minimax-portal-auth 插件

2. 执行 OAuth 授权命令：`openclaw models auth login --provider minimax-portal --method "<用户提供的method>" --set-default`
   
   **执行此命令后的处理流程**：
   - 检查命令输出，根据不同情况处理：
     - `models auth login requires an interactive TTY` → **帮用户弹出系统终端**，在终端中重新执行该授权命令
     - `MiniMax OAuth complete` → 授权成功，继续执行第 3 步
     - `MiniMax OAuth timed out` 或 `MiniMax OAuth failed` → 提示用户授权失败，询问是否重试
   - 如果命令正常执行（自动打开浏览器）：
     - 告知用户在浏览器中完成授权
     - **等待用户确认**授权完成

3. 授权成功后，执行 `openclaw onboard --non-interactive --accept-risk --mode local --gateway-port 18789 --gateway-bind loopback --install-daemon --skip-skills` 启动 gateway

下面的命令是根据操作系统执行的命令
#### macOS / Linux

```bash
openclaw plugins enable minimax-portal-auth
openclaw models auth login --provider minimax-portal --method "<用户提供的method>" --set-default
openclaw onboard --non-interactive --accept-risk --mode local  --gateway-port 18789 --gateway-bind loopback --install-daemon --skip-skills
```

#### Windows (PowerShell)

```powershell
openclaw plugins enable minimax-portal-auth
openclaw models auth login --provider minimax-portal --method "<用户提供的method>" --set-default
openclaw onboard --non-interactive --accept-risk --mode local  --gateway-port 18789 --gateway-bind loopback --install-daemon --skip-skills
```

#### Windows (CMD)

```cmd
openclaw plugins enable minimax-portal-auth
openclaw models auth login --provider minimax-portal --method "<用户提供的method>" --set-default
openclaw onboard --non-interactive --accept-risk --mode local  --gateway-port 18789 --gateway-bind loopback --install-daemon --skip-skills
```

### 3. 修复配置问题

```bash
openclaw doctor --fix
```

### 4. 打开网页验证

**必须**帮助用户执行以下命令打开控制面板：

```bash
openclaw gateway restart && openclaw dashboard
```

> ⚠️ **重要**：必须使用 `openclaw gateway restart && openclaw dashboard`命令打开控制面板，**禁止**让用户直接访问 `127.0.0.1:18789` 或任何 IP 地址，否则会导致功能异常。

## 验证安装

安装成功后，**必须**帮助用户执行 `openclaw gateway restart && openclaw dashboard` 命令打开浏览器控制面板（**不要**让用户手动访问 IP 地址），用户可以在控制面板中查看 gateway 状态并验证配置是否正确。

## 常用命令

| 命令 | 说明 |
|------|------|
| `openclaw gateway status` | 查看 gateway 状态 |
| `openclaw gateway run` | 启动 gateway |
| `openclaw gateway stop` | 停止 gateway |
| `openclaw gateway restart` | 重启 gateway |

## 遇到问题？

如果安装过程中遇到任何问题，请将完整的错误信息复制给我，我会帮你解决。
