# 联想云教室（NeiCloud）多媒体教学软件 逆向分析报告

> 分析对象：ZIP 中 113 个文件（教师端 + 学生端混合安装包，**文件不完整**，缺失部分已在下文标注）。
> 方法：PE 静态解析、字符串提取、Ghidra 反编译（单元级）、配置文件与日志取证、PDF 手册比对。
> 结论标注：**已证实**（代码/字符串/配置直接可见）、**推断**（由调用关系与命名得出，未能动态验证）。

---

## 1. 产品与样本概览

### 1.1 身份

| 项 | 内容 |
|---|---|
| 产品名 | 联想云教室（教师端/学生端），内部代号 **NeiCloud** |
| 厂商 | 武汉噢易云计算股份有限公司（`http://www.os-easy.com`，帮助手册与配置中可见） |
| 数字签名 | `C=CN, O=联想（北京）有限公司`，签发者 DigiCert Assured ID Code Signing CA-1（全部主程序均已签名） |
| 编译环境 | Visual Studio 2008（MSVCR90/MSVCP90/MFC90）+ VS2015 运行库混用；boost 1.54；OpenCV 2.1（`cxcore210/cv210`）；FFmpeg（`avcodec-57/avformat-57/avutil-55/swscale-4`）；VLC 2.x（`libvlc/axvlc`）；libcurl；7-Zip |
| PDB 路径 | `d:\work\branches\NeiCloud-1.0\Output\Release\*.pdb`（绝大多数模块）；`BlackSlient.exe` 来自 `e:\mmc\branches\10.4.1\Output\Release\`，属独立分支/子产品 |
| 架构 | 除 `inspect.sys`、`RCFux64.dll`、`PDelKeyB.exe` 为 x64 外，其余均为 x86 |

### 1.2 角色划分（按功能归类）

- **学生端主体**：`Student.exe`、`StudentLogic.dll`、`ProcessProtect.exe`、`Loader.exe`、`Startup.exe`、`BlackSlient.exe`、`LockKeyboard.dll`、`HookLib/HookManager/HookProcDll/InlineHook.dll`、`PDelKeyB.exe`、`ScreenMonitorLib.dll`
- **教师端主体**：`Teacher.exe`、`MainLogic.dll`、`ScreenSender.exe`、`ScreenPen.exe`、`ScreenRecord.exe`、`SharedDesktop.exe`、`Multi*.exe`、`Audio*/VideoMultiStream.exe`、`MmcFtpServer.exe`、`transfer_*`、`FileTranferServer.dll`
- **网络限制驱动**：`inspect.sys` + `inspect.inf`
- **辅助**：`GetHardwareInfo.dll`、`MD5Lib.dll`、`EncryptImpLib`（包内未单列）、`FT_ET99_API.dll`（ET99 加密狗）、`RCFu/RCFux64/RcfInterfaceLib`（远程调用框架）、`SocketUDP*.dll`、`MessageMultiCast.dll`、`TechMediaMessageControl.dll`
- **Python 运行时**：`python27.dll`、`pywintypes27.dll`、`win32*.pyd`、`select.pyd`、`library.zip`（PyInstaller/嵌入式 Python 支撑，本包内未发现对应主脚本 exe，属残留或缺失组件）

### 1.3 版本时间线

- 2017 年一批（NeiCloud 1.0 主线，PDB 与 x86 组件）
- 2022 年一批（`inspect.sys` 及其 PDB：`C:\Users\admin\Desktop\WFP-Traffic-Redirection-Driver-master\...\inspect.pdb`，WFP 重定向示例改造）
- `BlackSlient.exe` 来自 10.4.1 分支；`uninst.exe` 为 NSIS 卸载器（2025-06 构建，与主体非同一代）

---

## 2. 部署与通信

### 2.1 关键配置（`general.config`，GBK）

```
/ConnectPort/9003/          /FileTransferPort/9100/     /RcfPort/8444/
/SharedDeskTopAppBindPort/9101/
/RemoteIp/192.168.2.199/    /LocalIp/192.168.2.6/
/TransferType/udpSingle/    /UDPSendInternal/1/
/UDPPicUploadRate/1024/     /UDPPenUploadRate/30/       /UDPAudioUploadRate/1/
/ShowPicRate/0/             /WaitSeconds/30/
/LimitUSB/0/  /LimitNet/0/  /NetLock/0/  /Limit/1/
/BlackSlient/0/  /EnableDisconnectLock/1/  /UnLockByPassWord/0/  /TeaPassword//
```

- `mmc.cfg`：`/connectip/192.168.2.199/`、`/filterip/192.168.2.6/`（教师机地址过滤）
- `ftppath.cache`：`C:\MmcFtp\`（文件分发/收集的 FTP 根目录，`MmcFtpServer.exe` 提供）
- `RemoteCommand.cache`：远程命令模板 —— `shutdown -r -t 1`（远程重启）、`shutdown -f -l`（远程注销）、以及“远程关闭应用程序”占位项
- `protect.map`：`Student.exe`（看门狗保护名单）
- `student.log`：`[StudentLogic][GetDataFromTeacher][ip][id][type]` 等协议日志
- `chs.config`：功能名中文映射（`/Lock/黑屏安静`、`/RemoteMonitor/监控`、`/ScreenBroadCast/教师演示`、`/DisconnectLock/断网锁定`、`/RemoteCommand/远程命令`、`/FileTransfer/文件分发` 等）

### 2.2 端口汇总

| 端口 | 用途 | 依据 |
|---|---|---|
| TCP **9003** | 主控制连接（连接、命令、状态） | `ConnectPort` |
| TCP **9100** | 文件传输 | `FileTransferPort` |
| TCP **8444** | RCF 远程调用 | `RcfPort` + `RCFu.dll` |
| TCP **9101** | 共享桌面应用绑定 | `SharedDeskTopAppBindPort` |
| 动态 UDP | 屏幕/笔迹/音频上传（`udpSingle`，另有 `verfityPort` 校验端口） | `ScreenSender` 参数、`SocketUDP*.dll` |
| TCP 443 | **网络使用限制**策略拦截点（内核 WFP 过滤） | `inspect.sys` 分类函数硬编码 `0x1BB` |

---

## 3. 自我保护机制

### 3.1 ProcessProtect.exe —— 进程看门狗（学生端）

- 控制台程序，运行时隐藏窗口；读取同目录 `protect.map`（当前仅 `Student.exe`）。
- 工作线程循环 `Sleep(3000)`：
  - `CreateToolhelp32Snapshot` + `Process32First/NextW` 按**进程名**扫描；
  - 发现目标不存在 → `ShellExecuteW` 重新拉起（`FUN_00404870/FUN_00404af0/FUN_00404940`）。
- 特点与弱点：
  - 轮询周期 3 秒，存在最长约 3 秒的“空窗”；
  - 仅按名称匹配，不校验路径、签名、父进程；
  - 本身无服务/驱动保护，可被同等权限终止。

### 3.2 Loader.exe —— 看门狗“重启器”

- `FUN_004029f0` 查找 `ProcessProtect.exe`；`FUN_00402ab0` 调 `TerminateProcess` 结束旧实例；`FUN_00402bb0` 再 `ShellExecuteW` 启动新实例。
- 用途：安装/升级后让新看门狗接管，或强制刷新保护。
- `DeleteFileW/RemoveDirectoryW` 来自 MSVC `std::filesystem`，**不是**自删除/自更新逻辑（避免误判）。

### 3.3 Startup.exe —— RUN 键注册器

- 静态 CRT，`__setargv` 把 `argc-1/argv` 存入全局，`FUN_00401670(argc, argv)`：
  - `argc==3`：`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 写入 `RegSetValueExA(argv[1], argv[2])`；
  - `argc==2`：`RegDeleteValueA(argv[1])`。
- 即“命令行注册/删除自启动项”的小工具，安装器与卸载器共用。

### 3.4 黑屏安静 / 断网锁屏（BlackSlient.exe + StudentLogic.dll）

- `StudentLogic.dll` 导出 `LockComputer(BYTE)` → `FUN_1001d4f0`：
  - 参数 `0`：`TerminateProcess(BlackSlient)` 并关闭句柄（解锁）；
  - 非 0：构造消息 `断网锁屏中，联网后恢复！`，以 `BlackSlient.exe "<消息>"` 方式启动（`FUN_10018780`，`"%s %s"` 拼接，boost lexical_cast）。连不上教师机且 `EnableDisconnectLock=1` 时即进入此模式。
- `BlackSlient.exe`（x86 MFC + **DuiLib** 界面库）：
  - 窗口类 `CStuLockDlg`，构造时加载 `StuLockWnd.xml`（DuiLib 皮肤，**本包未提供**），读取 `password`、`numberonly`、`xmlfile`、`timer`、`count` 等属性；
  - 全屏置顶窗口 + 定时器 + 密码框；导入表仅 KERNEL32/USER32/GDI32/ole32/OLEAUT32/MFC90/gdiplus/IMM32，**没有** `SetWindowsHookEx`、`BlockInput`、`ClipCursor`；
  - 因此按键/鼠标屏蔽不在此进程内，而由 `HookManager/HookLib/LockKeyboard` 完成（见下）。
  - 密码来源与校验细节依赖缺失的 `StuLockWnd.xml` 与配置项（`TeaPassword`、`UnLockByPassWord`），本报告只能确认“密码由界面 XML 配置 + 本地校验”，无法还原具体算法。

### 3.5 LockKeyboard.dll —— 键盘设备级禁用

- 导出 `DisableKeyboard`(0x10001000)、`EnableKeyboard`(0x10001010)，实现 `FUN_10001030`/`FUN_10001420`。
- 流程：
  1. `DefineDosDeviceW(DDD_RAW_TARGET_PATH, "Kbd", "\Device\KeyboardClass0")`；
  2. `CreateFileW("\\.\Kbd", GENERIC_WRITE, FILE_SHARE_READ|WRITE, ...)`；
  3. `DeviceIoControl(0xB2004)`（启用时 `0xB2008`），失败逐项 `GetLastError` 并写日志；
  4. 再 `DefineDosDeviceW(..., "Kbd", "\Device\KeyboardClass1")` 切换目标。
- IOCTL 解码：`CTL_CODE(FILE_DEVICE_KEYBOARD(0xB), 0x801/0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)`。这是 kbdclass 的非公开/厂商扩展控制码，利用键盘类设备栈直接“拔键盘”，比用户态钩子更彻底。

### 3.6 全局低级钩子三件套

| 模块 | 导出 | 机制 |
|---|---|---|
| `HookManager.dll` | `CreateInstance/SetHook/SetHookState/UnHook` | `SetWindowsHookExW(WH_KEYBOARD_LL=0xD, ...)`，全局线程钩子 |
| `HookLib.dll` | `Lock/SetMouseFilter` | `Lock` 建线程，线程内 `SetWindowsHookExW(WH_MOUSE_LL=0xE, ...)`；回调对 `nCode==0 && lParam->dwExtraInfo==0x12452` 之外的所有鼠标事件返回 1（吞掉），保留自身注入事件 |
| `HookProcDll.dll` | `SetMsgHookOn/SetMsgHookOff` | `SetWindowsHookExW(WH_GETMESSAGE=3, ...)`，向 `UIStudentMainFrame` 窗口 `SendMessageW(hWnd, 0, 1, GetCurrentProcessId())` 上报进程；对 `iexplore/IEXPLORE/chrome` 特判 |

- `HookManager` 键盘回调（`0x1000B200`）在 `SetHookState(1)` 生效时拦截：
  - 左/右 **Win** 键（VK 0x5B/0x5C）、**Applications** 键（0x5D）；
  - **Ctrl+Esc**、**Alt+Tab**、**Alt+Esc**、**Ctrl+Alt+Esc**、**Ctrl+Shift+Esc**（任务管理器）、**Ctrl+Delete**；
  - 其余键放行 `CallNextHookEx`。
- 作用：防止学生切屏、开任务管理器、呼出开始菜单；配合全屏锁屏窗口形成“锁死”体验。
- 说明：钩子为 32 位全局钩子，只能影响同为 32 位/可注入的进程；对 64 位进程（如 64 位任务管理器、浏览器）覆盖有限——这与 `PDelKeyB.exe` 为 x64 的设计形成互补。

### 3.7 PDelKeyB.exe —— x64 Python 钩子组件（PyInstaller）

- x64 PE，PyInstaller 打包的 **Python 3.7** 程序；内嵌 `python37.dll`、`PYZ-00.pyz`、`pyWinhook`、`pyWinhook.HookManager`、`pyWinhook.cpyHook`、`pythoncom37.dll`。
- 能力（由依赖推断）：使用 pyWinhook（SetWindowsHookEx 封装）做全局键鼠钩子/按键屏蔽，x64 侧补齐 32 位 HookManager 覆盖不到的 64 位进程。
- 限制：主脚本为 3.7 bytecode（本机无 3.7 且无网络），未还原具体屏蔽键表；压缩归档的 TOC 带有非标准布局，未强行解析。名称 `PDelKeyB` 与 pyWinhook 依赖表明其职责是“删除/屏蔽按键”（推断）。

### 3.8 自启动、卸载与登录集成

- `Startup.exe` 写/删 Run 键（见 3.3）。
- `Register.reg` 注册凭据提供者：
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{75A22DF0-B81D-46ed-B119-CD30507BD615}` = `BatchLoginProvider`
  - `HKCR\CLSID\{75A22DF0-...}\InprocServer32` = `BatchLoginProvider.dll`（Apartment）
  - **注意**：包内 `BatchLogin.dll` 导出的是 `Load/LoadFor/UnLoad`，并非 COM 凭据提供者；真正的 `BatchLoginProvider.dll` **未随包提供**，无法确认其是否自动填充/提交学生账号，或仅做“批量登录”外壳。
- `Unregister.reg` 为对应反注册。
- `uninst.exe` 为 NSIS 卸载器（2025-06），`UnInstall.exe` 为产品自带卸载程序（PDB 在 NeiCloud 分支）。

### 3.9 其他保护/反分析线索

- `InlineHook.dll`：无导出、无字符串，仅链接 CRT；用途不明（推断为内联 hook 引擎，供其他模块动态加载）。
- `GetHardwareInfo.dll`：采集硬件指纹（机器码），配合加密狗/授权。
- `FT_ET99_API.dll`：ET99 加密狗 API；`chs.config` 含“未找到加密狗，请与厂家联系!”“产品试用时间还剩%d天”。
- `ProcessProtect/Loader/Startup` 三者均无服务、无驱动、无签名校验，属“轻量级看门狗”而非安全产品级防护。

### 3.10 保护强度评价（用于检测/处置）

1. **可按名杀死**：看门狗只查进程名，改名/复制即可绕过；先杀 `ProcessProtect` 再杀 `Student` 是最短路径。
2. **3 秒窗口**：`Sleep(3000)` 轮询，重启有延迟，可被脚本化反复击杀。
3. **无交叉保护**：看门狗不保护自己，也没有第二个进程互保；`Loader` 只用于刷新，不常驻。
4. **用户态钩子可卸载**：`UnHook/SetMsgHookOff/EnableKeyboard` 均为导出函数，任何进程可调用；`LockKeyboard` 依赖设备符号链接 `\\.\Kbd`，删除符号链接/恢复 `KeyboardClass0` 即可。
5. **锁屏密码在本地**：校验与配置均在客户端，离线可绕过（具体取决于缺失的 XML/配置）。
6. **驱动仅做网络过滤**，不参与进程/文件保护，不提供内核级自我保护。

---

## 4. 屏幕控制与远程管控

### 4.1 抓屏 — 编码 — 发送（学生端 → 教师端）

`ScreenSender.exe`（x86，依赖 FFmpeg、OpenCV、GDI32、WS2_32）是屏幕采集/编码/上传核心：

- 命令行格式（`StudentLogic.dll` 字符串 `0x886B0`）：
  ```
  --mouse %d --protocol %s --bindip %s --bindport %d --remote %s --port %d
  --encoderType %s --quality %d --waitseconds %d --width %d --height %d
  ```
- 编码器可选：
  - `h264`（OpenH264/FFmpeg，失败日志 `Open H264 encode failed`、`not found h264`）；
  - `jpeg`（FFmpeg MJPEG，含完整 libjpeg 错误串）；
  - 其他格式报 `not support Encoder format:`。
- 传输模式：`udpSingle`（单包/单流 UDP），也支持其他 `TransferType`（否则 `not Support this TransferType`）；`verfityPort` 为校验/握手端口，`outer_port` 为对外端口。
- `MainLogic.dll`（教师/学生共用逻辑库）`FUN_1001E2E0` 负责拼接 `ScreenSender.exe` 命令行并启动；`StudentLogic` 在收到教师端“监控/演示”命令后触发。
- 抓屏本身由 GDI（`BitBlt/CreateDIBSection/GetDIBits`）或 OpenCV 完成，再送入编码器；未见 DXGI/Desktop Duplication，属传统 GDI 抓屏（兼容性好、性能一般）。

### 4.2 教师端显示链路

- `ScreenMonitorLib.dll`（导出 `Load/Start/End/ChangeConnectState/GetAttachIp/GetAttention/UnLoad`）依赖 `RCFu.dll`（RCF 远程调用）+ gdiplus + WS2_32：接收学生画面、解码、显示。
- `MainLogic.dll` 导出：
  - `StartScreenMonitor` → `FUN_1002A680`
  - `ChangeScreenMonitorState` → `FUN_1002A7F0`
  - `BlackSilent(消息)` → `FUN_10029F40`：把文本存入全局，组包（`type=0xC`，长度 `msg_len*2`，`memcpy` 到 `+0x10`）经 `FUN_1001C970` 下发到学生端（用于“黑屏安静”提示语）。
- 多屏/多显示器：
  - `Multi.exe`（纯 Win32 + MFC）、`MultiRender.exe`、`MultiWindowsRender.exe`（FFmpeg/gdiplus）
  - `MainLogic` 引用 `MultiWindowsRender`（`StartMultiWindowsRenderMain/Attach`、`StopMultiWindowsRenderAttach`）
  - `SharedDesktop.exe`（FFmpeg + OpenCV）：共享桌面/应用窗口广播。
- 教师演示 `ScreenBroadCast`：教师端抓屏编码后以组播/多播下发（`MessageMultiCast.dll`），学生端 `VideoMultiStream.exe`/`AudioOrVideoBroadcast.exe` 接收播放。

### 4.3 电子教鞭 / 录屏 / 视频直播 / 音频

- `ScreenPen.exe`：屏幕笔（学生端 `Student.exe` 以 `WinExec(..., SW_SHOWMAXIMIZED)` 启动），笔迹经 UDP 上传（`UDPPenUploadRate=30`）。
- `ScreenRecord.exe`：屏幕录制，支持 `revcutscreen.bmp`/`revencodecutscreen.7z` 等回放/截图缓存。
- `VideoMultiStream.exe`/`AudioOrVideoBroadcast.exe`/`AudioSender.exe`/`AudioRender.exe`：视频直播与语音广播（FFmpeg + SDL2/VLC）。
- `vlc.exe/libvlc/axvlc`：网络影院（播放教师指定的视频源）。
- `MmcFtpServer.exe` + `filetransfer.dll`/`ftpclientlib.dll`/`FileTranferServer.dll`/`transfer_go.dll`：文件分发与一键收集（`C:\MmcFtp\`）。

### 4.4 断网锁定（DisconnectLock）与“黑屏安静”区别

- `EnableDisconnectLock=1` 时，学生端与教师机断连会进入 `断网锁屏中，联网后恢复！`，由 `StudentLogic::LockComputer` 启动 `BlackSlient.exe`。
- “黑屏安静”（教师端功能 `/Lock/黑屏安静`）同样复用 `BlackSlient.exe`，但由教师命令触发，消息文本不同。
- 锁屏期间键鼠由 `HookManager`（热键）+ `HookLib`（鼠标）+ `LockKeyboard`（键盘设备）共同压制；网络恢复/教师解锁后调用 `LockComputer(0)` 结束进程。

---

## 5. 网络使用限制与内核驱动 inspect.sys

### 5.1 驱动形态

- x64 KMDF + **WFP callout** 驱动（PDB 指向 `WFP-Traffic-Redirection-Driver-master`，由微软 WFP 示例改造）。
- 设备：`\Device\Inspect`，符号链接 `\DosDevices\Inspect`。
- 注册：`FwpsCalloutRegister3`、`FwpmEngineOpen0/SubLayerAdd0/CalloutAdd0/FilterAdd0`，callout 名 `WfpSampleEstablishedCalloutName`。
- `inspect.inf` 为微软示例模板（`ServiceName=Inspect`，`%12%\Inspect.sys`），安装后以系统服务加载。

### 5.2 过滤逻辑

- 分类函数 `FUN_140001A50`：
  - 默认 `FWP_ACTION_PERMIT (0x1002)`；
  - 当全局开关 `DAT_140004318 != 0` 且远端端口 == **443**（`0x1BB`）时，按模式 `DAT_140004319` 查 IP 规则表（`FUN_140001214`）：
    - 模式 0 = 白名单：未命中 → `FWP_ACTION_BLOCK (0x1001)`；
    - 模式 1 = 黑名单：命中 → 阻断；
  - 日志：`remote ip is %x : %u`。
- 只针对 443 端口设计，即“限制/放行 HTTPS 网站”，与教师端“网络使用限制”功能对应（`chs.config` 中 `/DefineWnd.cpp_NetworkUsageControl/网络使用限制`）。

### 5.3 IOCTL 接口（`FUN_140001950` 分发）

设备控制码为自定义 `CTL_CODE(FILE_DEVICE_UNKNOWN(0x22), 0x830..0x834, METHOD_BUFFERED, FILE_ANY_ACCESS)`：

| IOCTL | 行为 |
|---|---|
| `0x22E0C0` | 添加/更新 IP 规则（输入 ≥0x1A 字节；若 `buf+0x14` 的 word==1 则先清空全部规则，`FUN_140001294`），回写命中计数 |
| `0x22E0C4` | 切换黑名单模式 |
| `0x22E0C8` | 切换白名单模式 |
| `0x22E0CC` | 启用拦截 |
| `0x22E0D0` | 清空规则并关闭拦截 |

日志串：`Stop info`、`AddNetRuleInfo times: %d`、`WRITE_CTL_CODE m_uTimes: %d out:%d in:%d ulInformation:%d`。

### 5.4 学生端策略下发链路（Student.exe）

- `CreateFileW(L"\\\\.\\Inspect", 0xC0000000, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)`，五个 `DeviceIoControl` 封装：
  - `FUN_00435110` → `0x22E0D0`（清空+禁用）
  - `FUN_00435180` → `0x22E0CC`（启用）
  - `FUN_004351F0` → `0x22E0C8`（白名单）
  - `FUN_00435260` → `0x22E0C4`（黑名单）
  - `FUN_0043D710` → `0x22E0C0`（对 `gethostbyname` 解析出的每个 IP 下发规则，buf 0x1C 字节，IP 位于偏移 8）
- 调用者 `FUN_0043D960`（1758 字节）解析策略 XML 节点：
  - `PolicySetForIE` / `PolicySetForProgram`，属性含 `Black`、`Selected`、主机名等；
  - 批量下发到驱动；`FUN_00438CA0/FUN_0043B480/FUN_004353C0` 为 UI/开关入口。
- 完整链路：**教师端策略 → 学生端解析 XML → DNS 解析域名 → 内核 WFP 按 443 端口 IP 黑白名单放行/阻断**。
- 旁证：`Student.exe` 字符串含 `SetNetrafficFunc`、`http://www.baidu.com`（连通性检测）、`ecr_http.exe`、`http://%s:%d/client/?grade_name=%s&class_name=%s&student_name=%s`（班级/学生信息上报）。

---

## 6. 关键配置文件与取证点

| 文件 | 内容/用途 |
|---|---|
| `protect.map` | 看门狗保护的进程名（`Student.exe`） |
| `general.config` | 端口、IP、限速、锁屏/断网开关、密码策略 |
| `mmc.cfg` | 教师机连接 IP / 过滤 IP |
| `RemoteCommand.cache` | 远程重启/注销/关闭应用模板（JSON，文件为 GBK 编码） |
| `ftppath.cache` | FTP 根目录 `C:\MmcFtp\` |
| `Register.reg` / `Unregister.reg` | 凭据提供者 CLSID `{75A22DF0-B81D-46ED-B119-CD30507BD615}` 注册/反注册 |
| `student.log` | 学生端与教师端消息收发日志（IP/ID/type） |
| `multi.log`、`AudioDevice.cache` | 多屏/音频设备缓存 |
| `chs.config` | 全部界面中文文案（可据此还原功能菜单） |
| `Help.pdf` | 《联想云教室安装及使用手册》1140 行，功能与部署说明 |

---

## 7. 检测与处置建议（蓝队/运维视角）

### 7.1 主机检测

- 进程：`Student.exe`、`ProcessProtect.exe`、`BlackSlient.exe`、`ScreenSender.exe`、`ScreenPen.exe`、`ScreenRecord.exe`、`Multi*.exe`、`MmcFtpServer.exe`、`PDelKeyB.exe`。
- 自启动：`HKCU\...\Run` 中由 `Startup.exe` 写入的项；`HKLM\...\Credential Providers\{75A22DF0-...}`；`Inspect` 内核服务。
- 驱动：`inspect.sys`（服务名 `Inspect`，设备 `\Device\Inspect`）；`fltmc`/`sc query Inspect`。
- 设备符号链接：`\\.\Kbd` → `\Device\KeyboardClass0/1`（`DefineDosDevice` 痕迹）。
- 全局钩子：32 位 `WH_KEYBOARD_LL/WH_MOUSE_LL/WH_GETMESSAGE`，模块来自 `HookManager/HookLib/HookProcDll`。
- 网络：TCP 9003/9100/8444/9101；UDP 屏幕流；443 出站被驱动按 IP 名单阻断（表现为“部分网站打不开”）。
- 文件：`C:\MmcFtp\`、`protect.map`、`general.config`、`RemoteCommand.cache`。

### 7.2 处置/卸载

1. 先停 `ProcessProtect`（否则 3 秒内重启 `Student.exe`），再停 `Student`；
2. 停止并删除 `Inspect` 服务/驱动，恢复被拦截的 443 访问；
3. 删除 `Run` 键与凭据提供者 CLSID，注销 `BatchLoginProvider`；
4. 恢复键盘设备（删除 `\\.\Kbd` 符号链接或重启），卸载全局钩子；
5. 使用官方 `uninst.exe`/`UnInstall.exe` 清理，检查 `C:\MmcFtp\` 残留。

### 7.3 合法使用提示

该软件为商用教学管理产品，具备集中管控、屏幕广播、锁屏与上网限制等**教学管理**功能。上述分析仅用于资产梳理、兼容性排查与安全评估；在非授权设备上部署/绕过管控可能违反使用协议或当地法律。

---

## 8. 证据强度与未完成项

**已证实（代码/字符串/配置直接支持）**

- 看门狗 3 秒轮询与 `ShellExecuteW` 重启、`Loader` 杀进程重启、`Startup` 读写 Run 键；
- `LockKeyboard` 的 `DefineDosDevice` + `0xB2004/0xB2008` IOCTL；
- `HookManager` 的 `WH_KEYBOARD_LL` 与热键屏蔽表；`HookLib` 的 `WH_MOUSE_LL` + `dwExtraInfo==0x12452` 过滤；`HookProcDll` 的 `WH_GETMESSAGE` 与 `UIStudentMainFrame` 上报；
- `inspect.sys` 的 WFP callout、443 端口、五种 IOCTL、黑白名单模式；
- `Student.exe` 的策略 XML 解析与 IOCTL 下发链路；
- `ScreenSender` 命令行参数、h264/jpeg 编码、`udpSingle` 传输；
- `BlackSlient` 为 DuiLib 锁屏窗口、`LockComputer` 启停逻辑；
- 签名、PDB、端口、配置文件。

**推断（未动态验证）**

- `PDelKeyB.exe` 的具体按键屏蔽表（PyInstaller 3.7 主脚本未还原）；
- `BatchLoginProvider.dll` 的登录自动化行为（DLL 缺失）；
- `StuLockWnd.xml` 的密码校验细节（资源缺失）；
- `InlineHook.dll` 的具体 hook 目标（无导出/无字符串）。

**限制**

- 样本不完整：缺少 `BatchLoginProvider.dll`、`StuLockWnd.xml`、部分策略 XML、Python 主脚本及若干资源；
- PE 解析为自研脚本；反编译结果可能与源码存在命名/类型偏差；
- 未进行动态运行（无 Windows 环境，在linux (ubuntu) 上进行逆向），所有“行为”结论来自静态调用链与字符串。

---

*报告生成：静态逆向分析；地址均为 反编译工具 载入基址（x86 DLL 多为 0x10000000，驱动为 0x140000000）。*
