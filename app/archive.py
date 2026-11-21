import csv,io,json
from app import retention
ARCHIVE_COLUMNS=["run_id","input_sha256","rule_version","kind","source_lines","reason","evidence","package_sha256"]
def build_archive(run):
    """导出唯一证据包：工作台展示与下载使用同一 package_sha256。

    只写身份、版本、操作、时间、来源行、原始删改关系和正文摘要；不写正文。
    到期清理前后导出同一份证据，故撤下范围可复核。
    """
    package=retention.build(run);stream=io.StringIO(newline="");writer=csv.writer(stream)
    writer.writerow(ARCHIVE_COLUMNS)
    meta=run.get("manifest") or {}
    sha=package["package_sha256"]
    head={"policy_version":package["policy_version"],"as_of":package["as_of"],"retention_days":package["retention_days"],"summary":package["summary"],"package_sha256":sha}
    writer.writerow([run.get("run_id"),meta.get("input_sha256"),meta.get("rule_version"),"manifest","",json.dumps(package["summary"],ensure_ascii=False,sort_keys=True),json.dumps(head,ensure_ascii=False,sort_keys=True),sha])
    for doc in package["documents"]:
        evidence={key:doc[key] for key in retention.EVIDENCE_FIELDS}
        evidence.update({"action":doc["action"],"reason":doc["reason"],"body_retained_by_policy":doc["body_retained_by_policy"],"cleanable_fields":doc["cleanable_fields"],"retention_expires_at":doc["retention_expires_at"]})
        writer.writerow([run.get("run_id"),meta.get("input_sha256"),meta.get("rule_version"),"document",json.dumps(doc["source_lines"]),doc["reason"],json.dumps(evidence,ensure_ascii=False,sort_keys=True),sha])
        for item in doc["quarantine"]:
            writer.writerow([run.get("run_id"),meta.get("input_sha256"),meta.get("rule_version"),"quarantine",json.dumps(item.get("sources",[])),item.get("reason",""),json.dumps(item,ensure_ascii=False,sort_keys=True),sha])
    attached={doc["doc_id"] for doc in package["documents"]}
    seen={(tuple(item.get("sources") or []),item.get("reason")) for doc in package["documents"] for item in doc["quarantine"]}
    for stage in run["stages"]:
        for item in stage.get("cumulative_quarantine",[]):
            lines=retention._lines([item.get("_sources") or item.get("_line")])
            if (tuple(lines),item.get("reason")) in seen:continue
            seen.add((tuple(lines),item.get("reason")))
            evidence={"reason":item.get("reason"),"detail":item.get("detail"),"source_lines":lines}
            writer.writerow([run.get("run_id"),meta.get("input_sha256"),meta.get("rule_version"),"quarantine",json.dumps(lines),item.get("reason",""),json.dumps(evidence,ensure_ascii=False,sort_keys=True),sha])
    receipt=run.get("retention_cleanup")
    if isinstance(receipt,dict):
        writer.writerow([run.get("run_id"),meta.get("input_sha256"),meta.get("rule_version"),"cleanup",json.dumps(receipt.get("purged_docs",[])),"PURGED",json.dumps(receipt,ensure_ascii=False,sort_keys=True),receipt.get("package_sha256",sha)])
    return "﻿"+stream.getvalue()
