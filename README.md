# TL R483G TPDDNS 二阶命令注入修复

本仓库提供一个面向 `TL-R483G V4.0` 固件 `20240514_2.2.1` 的最小修复包。漏洞位于 `usr/lib/lua/luci/controller/admin/tpddns.lua`：绑定接口把 `cloud_config.bind.username` 写入 UCI，稍后的 `ddns.get_domain_list` 操作再把该值直接拼接到 `getDomainList` 命令并交给 `/bin/sh -c`。因此，已认证管理用户能够存入 shell 元字符，并在第二个请求中触发命令执行。

- CNVD 编号：`CNVD-C-2026-506439`
- 漏洞类型：存储型（二阶）命令注入
- 受影响版本：`TL-R483G V4.0 20240514_2.2.1`

## 修复内容

修复同时覆盖写入点和执行点：

1. `bind_action` 在持久化前检查用户名类型、长度、控制字符和前导 `-`。
2. `start_get_domain_list` 从 UCI 读出用户名后再次执行相同检查，覆盖升级前已经保存的恶意配置。
3. 用户名使用 POSIX 单引号规则编码为一个 shell 参数。`;`、`$()`、反引号、重定向、管道和空格都只会作为 `getDomainList` 的普通参数内容。
4. 拒绝以 `-` 开头的用户名，避免修复命令注入后仍存在参数或选项注入。

没有修改 `luci.sys.fork_exec` 的全局行为，因而不会影响固件中其他依赖 `/bin/sh -c` 的调用方。

## 文件说明

- `src/tpddns_security.lua`：完整、可部署的 Lua 5.1 安全辅助模块。
- `patches/0001-fix-tpddns-second-order-command-injection.patch`：根据报告重建的 `tpddns.lua` 集成参考差异；新增模块部分是完整代码，目标文件部分需要在真实源码仓库中重新生成上下文。
- `tests/test_tpddns_security.py`：在真实 Lua 运行时中加载模块，并使用 POSIX shell 验证危险字符不会越过参数边界。
- `requirements-test.txt`：测试环境依赖，不进入路由器固件。

## 集成方法

1. 把 `src/tpddns_security.lua` 安装到固件源码树：

   ```text
   usr/lib/lua/luci/controller/admin/tpddns_security.lua
   ```

2. 按补丁中的两个位置修改 `tpddns.lua`。不同源码树可能经过格式化或变量重命名；应以函数名 `bind_action`、`start_get_domain_list` 和原始调用 `d.fork_exec("getDomainList " .. username)` 为定位依据。由于附件只有反编译截图，不应直接对未知仓库运行 `git apply`。
3. 确认固件打包规则包含新增 Lua 文件。
4. 在干净构建环境中重新生成固件，并完成下文的设备回归验证。

补丁没有附带厂商未公开的完整 `tpddns.lua`，也没有根据反编译截图伪造其余约 300 行代码。提交 PR 时，应将新增模块和这两处修改应用到目标仓库的真实源码文件，再从真实工作树生成最终 diff。

## 自动化验证

Python 仅作为测试驱动器；被测逻辑由 Lua 运行时实际执行。

```powershell
python -m pip install -r requirements-test.txt --target .deps
$env:PYTHONPATH = ".deps"
python -m unittest -v tests.test_tpddns_security
```

测试程序会优先使用 `TPDDNS_TEST_SHELL` 指定的 POSIX shell；没有设置时会查找 `sh` 和 Git for Windows 的默认安装路径。例如：

```powershell
$env:TPDDNS_TEST_SHELL = "C:\Program Files\Git\usr\bin\sh.exe"
```

Linux 或 macOS：

```sh
python3 -m pip install -r requirements-test.txt --target .deps
PYTHONPATH=.deps python3 -m unittest -v tests.test_tpddns_security
```

测试覆盖：

- 正常邮箱、手机号、空格和单引号；
- 空值、错误类型、控制字符、256 字节超长值和前导选项字符；
- `$()`、反引号、`;`、`&&`、管道、重定向、通配符；
- POSIX shell 中的实测参数完整性和哨兵文件未创建断言。

## 设备回归清单

在隔离网络中的测试设备上完成以下验证后再发布固件：

1. 正常 TP-LINK ID 可以绑定、解绑并获取域名列表。
2. 重启设备后仍能读取已保存账号并获取域名列表。
3. 把报告中的恶意用户名写入配置，再调用 `ddns.get_domain_list`；请求应返回参数错误，且不产生证明文件或任何子命令副作用。
4. 对包含 `;`、`$()`、反引号、单引号、空格和重定向字符的值分别复测；若值通过绑定业务规则，它只能作为一个字面参数传给 `getDomainList`。
5. 检查系统日志中没有明文密码，并确认错误分支不回显用户名内容。

## PR 建议说明

标题：`security: fix CNVD-C-2026-506439 stored command injection in TPDDNS`

正文可写为：

> Fix CNVD-C-2026-506439 by validating the persisted cloud username at both the write boundary and the command execution sink. Quote it as one POSIX shell argument before invoking `getDomainList`, preventing stored values from being evaluated by `/bin/sh -c`. Reject control bytes, oversized values, and leading option characters. Add regression tests for command substitution, separators, pipelines, redirection, backticks, apostrophes, and normal TP-LINK ID values.
