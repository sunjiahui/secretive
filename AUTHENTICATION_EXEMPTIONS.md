# Authentication exemptions (personal fork)

Secretive settings provide a Git read-operation switch and a trusted-program list.
Both start disabled/empty. Access notifications remain enabled.

Create a **new key** and choose **App-managed authentication**, then register its
public key with your Git service or SSH server. The key stays non-exportable in
the Secure Enclave. Authentication for this mode is enforced by SecretAgent,
instead of by hardware user-presence access control. Existing Touch ID keys and
smart cards keep their original authentication requirements and cannot be
converted to this mode. The default key creation option remains hardware-enforced
authentication.

The Git switch exempts direct SSH authentication from `git pull` and `git fetch`.
Push, commit signing, aliases and unknown Git options still require authentication.
Ordinary `git status` does not use SSH. Git arguments identify the local operation;
they do not constrain permissions on the remote server.

The initial Git switch supports Apple-signed Git at the system, Command Line
Tools and `/Applications/Xcode.app` locations, using `/usr/bin/ssh`. Homebrew Git
does not automatically qualify. You can explicitly trust another Git executable
using the program list; doing so exempts **all** of its requests, including push
and signing, rather than only pull/fetch.

Add applications or signed executables with **Add Program…**. Both their canonical
executable path and code-signing requirement must match at runtime. Unsigned
programs cannot be added. Moving a program, or replacing an ad hoc signed build,
can require adding it again. Removing an entry applies to the next request.
Trusting a terminal or IDE also trusts commands and helpers descended from that
application. A native program that intentionally proxies requests is trusted to
proxy those requests; its remote callers cannot be identified independently.

SSH exemptions additionally require a verified, direct OpenSSH session binding
matching the signed authentication payload. Forwarded, missing, invalid,
unsupported or repeated bindings require authentication. Unsupported host key
types (including RSA), certificate authentication and SSH connection multiplexing
that hides the invoking Git operation may still prompt. Standard `publickey`
authentication is matched through the bound session ID; host-bound authentication
also matches the complete host key.

Settings are saved in the existing shared Keychain. A save error is displayed;
unreadable or invalid settings require authentication. Exemptions authorize only
the individual request and never create a reusable authentication grant. Explicit
duration grants from the existing notification flow retain their existing behavior.

Older Secretive versions do not recognize the new key mode. Keep your existing
hardware-protected key and its server registration available when trying the fork
or rolling back. Signing identity and bundle ID must remain consistent with your
installation to preserve Keychain access.

## macOS verification

The current upstream project requires Xcode 27 / Swift 6.4 for its JSON project
format and internal packages. With that toolchain selected, run from the repository root:

```sh
./scripts/build-macos.sh
```

The script checks the selected Xcode and Swift versions, runs the package test plan
and root package tests, then compiles an unsigned Debug application. It stops on the
first failure and prints a temporary output directory containing logs, the test
result bundle, and the built app. It does not install or launch the application.

An unsigned build verifies compilation only. Use your normal development signing
configuration to run the application and check Keychain and Secure Enclave access.

## Signed local application

Use an **Apple Development** identity listed by `security find-identity -v -p codesigning`:

```sh
./scripts/build-signed-macos.sh CERTIFICATE_SHA1
```

The script looks up the selected public certificate by its SHA-1 fingerprint and
reads its actual Team ID from the subject OU field. It builds a Debug application
with automatic development signing for that Team and a separate bundle prefix,
`TEAM_ID.com.example.Secretive`. Xcode must be signed in to an account with access
to that Team so it can manage provisioning profiles. No private key is exported.

The main app, agent and XPC helpers receive the same Team and bundle prefix.
XPC connections use the identifiers of the helpers embedded in the running app,
so changing the bundle prefix does not leave connections pointing at upstream IDs.
Release signing requirements remain unchanged; this command is for local Debug use.

The script verifies the built app's signature and Team, then prints its path and
an `open` command. It does not install or launch the app. Keep the same Team and
bundle identifiers on later builds to retain Keychain access. An existing official
installation uses a different signing identity and may not expose its keys here.

After launching, enable the agent in the setup flow, create an app-managed key,
register its public key with your SSH server, and apply **Integrations → SSH** using
the socket path displayed by this build. Enable the Git exemption or program list
in **Settings**. A Debug build uses a different socket filename from a Release build.

With an app-managed test key registered on a test server, verify the following:

| Configuration / operation | Expected authentication |
| --- | --- |
| Default settings, fetch | Required |
| Git switch enabled, pull/fetch with supported Git and SSH | Exempt |
| Git switch enabled, push or commit signing | Required |
| Git switch disabled again | Required |
| Trusted native app or descendant, including signing | Exempt |
| Remove trusted app; next request | Required |
| Agent forwarding or unverified SSH binding | Required |
| Existing hardware-protected key, with exemptions enabled | Required |
| Decline authentication for a non-exempt request | Request fails |

Source-only Linux checks do not validate macOS framework types, UI behavior,
Keychain sharing, code-signing validation or real Secure Enclave authentication.

## 中文说明

在新建密钥时选择“由应用控制验证”，把新公钥登记到 Git 服务或 SSH 服务器。
密钥仍在 Secure Enclave 中且不可导出，但验证由 SecretAgent 执行，硬件不强制用户在场。
已有 Touch ID 密钥和智能卡保留原来的验证要求，不能原地转换。

设置中的 Git 开关默认关闭，只针对受支持的 Apple Git 与系统 SSH 发起的
`pull` / `fetch` 直接连接免验证；`push` 和提交签名仍需验证，普通 `status` 不使用 SSH。
Homebrew Git 不会自动命中开关。将 Git 可执行文件直接加入白名单会放行它的全部请求。

程序白名单按路径和代码签名匹配，支持添加与移除。将终端或 IDE 加入白名单，
也会信任其中运行的子进程和签名请求。SSH 转发、无效连接绑定和无法识别的来源仍需验证。
原生程序若主动代理请求，白名单意味着信任该程序代理的请求。
移动程序或替换临时签名版本后可能需要重新添加。保存失败会显示错误，规则命中仅授权当前请求。

Mac 上在仓库根目录运行 `./scripts/build-macos.sh`，无需单独下载脚本。
脚本会检查工具链版本、运行测试并编译应用，日志与构建结果保存在启动时显示的临时目录中。
实际使用前仍需在签名安装的应用中验证
Keychain 与 Secure Enclave 行为。保留已有硬件保护密钥及其服务器登记，方便回退。

实际运行时，使用 `security find-identity -v -p codesigning` 列出的 Apple Development
证书 SHA-1，执行 `./scripts/build-signed-macos.sh 证书SHA1`。脚本从证书 OU 读取真正的
Team ID，统一主程序和 helper 的签名配置，构建后校验签名并显示打开 App 的命令。
Xcode 需登录有权使用该 Team 的账户。后续构建保持相同的 Team 与 Bundle ID。
