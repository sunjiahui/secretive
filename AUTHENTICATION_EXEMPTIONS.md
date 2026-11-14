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
format and internal packages. With that toolchain selected, run:

```sh
xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme PackageTests test
swift test --build-system swiftbuild
xcrun xcodebuild -project Sources/Secretive.xcodeproj -scheme Secretive \
  -configuration Debug build CODE_SIGNING_ALLOWED=NO
```

An unsigned build verifies compilation only. Use your normal development signing
configuration to run the application and check Keychain and Secure Enclave access.

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

上面的 macOS 命令用于项目测试与编译；实际使用前仍需在签名安装的应用中验证
Keychain 与 Secure Enclave 行为。保留已有硬件保护密钥及其服务器登记，方便回退。
