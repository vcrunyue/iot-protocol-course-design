# 轻量级物联网加密通信协议

模拟物联网设备与服务器之间的轻量级加密通信流程。

## 项目内容

- C++ 控制台程序：`main.cpp`
- 单元测试：`test_iot_protocol.cpp`
- 网页版终端：`web/index.html`

## C++ 编译运行

```bash
g++ -std=c++11 -Wall -o iot_protocol main.cpp
./iot_protocol
```

## C++ 测试

```bash
g++ -std=c++11 -Wall -o /tmp/test_iot_protocol_plan_check test_iot_protocol.cpp
/tmp/test_iot_protocol_plan_check
```

## 网页版终端

网页版终端使用原生 HTML、CSS 和 JavaScript 实现，不需要后端或第三方依赖。

本地预览：

```bash
python3 -m http.server 5173
```

然后访问 `http://localhost:5173/web/`。

网页功能对应控制台菜单：

- `1. 发送数据`：输入文本，选择 XOR 或凯撒加密，显示加密载荷、发送帧、接收帧和解密结果。
- `2. 查看历史`：显示当前浏览器会话中的通信历史。
- `3. 协议说明`：显示协议帧格式。
- `4. 退出`：清空当前网页会话状态并显示退出提示。

## Vercel 部署

仓库可直接通过 Vercel 的 GitHub 集成导入部署。项目包含 `vercel.json`，生产访问 `/` 时会展示网页版终端。
