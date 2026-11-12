# 第三方软件声明

本文件列出 ARTEX 默认镜像新增的上游组件，以及对应许可证和源码/NOTICE 的镜像内位置。

## OWASP ZAP 与 MCP Integration

- 上游项目：[zaproxy/zaproxy](https://github.com/zaproxy/zaproxy)、[zaproxy/zap-extensions](https://github.com/zaproxy/zap-extensions)
- 固定版本：ZAP `2.17.0`、MCP Integration add-on `0.4.0`
- 上游许可：Apache License 2.0
- 镜像内上游发行文件：`/opt/zap/`
- Apache 2.0 许可证全文：`/opt/zap/ApacheLicense-2.0.txt`
- ZAP 2.17.0 上游法律声明：`/opt/zap/LEGALNOTICE.md`

## ffuf

- 上游项目：[ffuf/ffuf](https://github.com/ffuf/ffuf)
- 固定版本：`2.3.0`
- 上游许可：MIT
- 运行文件：`/usr/local/bin/ffuf`
- 许可证全文：`/usr/share/doc/ffuf/copyright`
- 内置小型 Web 路径字典：`/opt/artex/wordlists/web-common.txt`

## Puppeteer Core

- 上游项目：[puppeteer/puppeteer](https://github.com/puppeteer/puppeteer)
- 固定版本：`23.11.1`
- 上游许可：Apache License 2.0
- 包目录：`/usr/lib/node_modules/puppeteer-core/`
- 许可证全文：`/usr/share/doc/puppeteer-core/LICENSE`
- Chromium 复用镜像中 Playwright 已安装的浏览器，不另行下载。

## sqlmap

- 上游项目：[sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap)
- 固定源码提交：`eca9ff2e134f66a69fa64b1715b9cfcf9a1164bc`（运行版本 `1.10.11.9#dev`）
- 上游许可：GNU GPL version 2 or later，含上游 LICENSE 中的说明与例外
- 命令：`/usr/local/bin/sqlmap`
- 未修改的完整源码及许可证：`/opt/sqlmap/`
- ARTEX 仅提供独立命令行程序，不解析或转换其输出。
