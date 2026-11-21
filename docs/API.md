# 接口

模块GET使用仓内样例，模块POST可传csv或rows与context，直接计算当前规则。/api/runs使用完整流水线并原子保存。每个阶段返回rows、quarantine、metrics；后续阶段还返回累计隔离。/api/upload接收multipart文件file。/api/runs/<id>/archive只导出一份带清单与证据的CSV。

## 到期证据包

`GET /api/runs/<id>/retention` 返回该批次唯一的到期证据包：每篇文档的 `action`（`PURGE_BODY`/`RETAIN_BODY`/`HOLD`）、原因、保留期、可清理字段、来源行、原始删改关系和正文摘要，以及 `package_sha256`。`POST` 同一路径按该包执行清理，只清 `PURGE_BODY` 文档的正文，返回同一 `package_sha256` 的凭据；重复调用不新增、不减少证据。

`GET /api/runs/<id>/archive` 导出的CSV逐行带同一 `package_sha256`，只含证据字段，不含正文；清理前后导出内容一致（清理后再多一行 `cleanup` 凭据）。仍在检索、删除未确认、版本不一致或隔离中的文档保持 `HOLD`，正文不清理。

保留参数：`retention_days`（默认1天）、`retention_as_of`（默认2026-11-21T00:00:00Z，取事件源时刻与可见时刻的较晚者加保留期比较）。
