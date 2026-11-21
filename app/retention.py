"""到期保留裁决与证据包。

删除/修改事件和文档正文到达保留期后，需要在不保留敏感正文的前提下，留下足
以证明“撤下了哪些文档、撤下到哪个版本”的证据。本模块按文档裁决：

- ``PURGE_BODY``：双端删除已确认且已过保留期，正文可清理，证据必须留下；
- ``RETAIN_BODY``：删除已确认但仍在保留期内，正文暂不清理；
- ``HOLD``：仍在检索、删除未确认、版本不一致或尚未裁决，正文和证据都不清理。

证据包只保存身份、版本、操作、时间、来源行、原始删改关系和正文摘要，不保存
正文本身。包摘要只覆盖证据字段，因此重复构建或重复清理不会新增、减少证据。
"""

import hashlib
import json
from copy import deepcopy
from datetime import timedelta

from app.errors import DomainError
from app.values import instant, number

POLICY_VERSION = "2026.11.21-r1"
DEFAULT_RETENTION_DAYS = "1"
DEFAULT_AS_OF = "2026-11-21T00:00:00Z"

PURGE_BODY = "PURGE_BODY"
RETAIN_BODY = "RETAIN_BODY"
HOLD = "HOLD"

CLEANABLE_FIELDS = ["payload", "note", "document", "_raw"]
EVIDENCE_FIELDS = [
    "doc_id",
    "source_version",
    "index_version",
    "source_op",
    "index_op",
    "visibility_state",
    "gate",
    "tombstone",
    "source_at",
    "visible_at",
    "source_lines",
    "relations",
    "body_sha256",
    "quarantine",
]


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _lines(values):
    found = set()
    stack = list(values)
    while stack:
        value = stack.pop(0)
        if isinstance(value, (list, tuple)):
            stack[:0] = list(value)
            continue
        if value is None or value == "":
            continue
        try:
            found.add(int(value))
        except (TypeError, ValueError):
            found.add(str(value))
    return sorted(found, key=lambda item: (isinstance(item, str), item))


def _policy(params=None):
    params = params or {}
    days = number(params.get("retention_days", DEFAULT_RETENTION_DAYS))
    as_of = instant(params.get("retention_as_of", DEFAULT_AS_OF))
    if days < 0:
        raise DomainError("BAD_RETENTION", "保留期不能为负")
    return days, as_of


def _expiry(row, days, as_of):
    stamps = [instant(row[key]) for key in ("source_at", "visible_at") if row.get(key)]
    if not stamps:
        return None, False
    expires = max(stamps) + timedelta(seconds=float(days) * 86400)
    return expires.isoformat(), as_of >= expires


def _body_items(run):
    """按文档收集清理前的所有正文形态，用于生成正文摘要。"""
    bodies = {}
    for index in (0, 1):
        stage = run["stages"][index]
        for row in list(stage.get("rows", [])) + list(stage.get("quarantine", [])):
            doc = row.get("doc_id")
            if not doc:
                continue
            item = {
                "lines": _lines([row.get("_sources") or row.get("_line")]),
                "event_id": row.get("event_id"),
                "side": row.get("side"),
                "version": row.get("version"),
                "op": row.get("op"),
                "payload": row.get("payload"),
                "note": row.get("note"),
                "document": row.get("document"),
                "raw": row.get("_raw"),
            }
            bodies.setdefault(doc, {})[_canonical(item)] = item
    return {doc: _sha([items[key] for key in sorted(items)]) for doc, items in bodies.items()}


def _relations(run):
    """逐事件保留原始删改关系，正文清理后仍可追回。"""
    grouped = {}
    for index in (0, 1):
        stage = run["stages"][index]
        for row in list(stage.get("rows", [])) + list(stage.get("quarantine", [])):
            doc = row.get("doc_id")
            if not doc:
                continue
            event = {
                "event_id": row.get("event_id"),
                "side": row.get("side"),
                "version": row.get("version"),
                "op": row.get("op"),
                "tombstone": row.get("op") == "delete",
                "source_lines": _lines([row.get("_sources") or row.get("_line")]),
            }
            grouped.setdefault(doc, {})[_canonical(event)] = event
    return {doc: [items[key] for key in sorted(items)] for doc, items in grouped.items()}


def _quarantine(run):
    grouped = {}
    for stage in run["stages"]:
        for row in stage.get("cumulative_quarantine", []):
            doc = row.get("doc_id")
            if not doc:
                continue
            grouped.setdefault(doc, {})[_canonical(row)] = {
                "reason": row.get("reason"),
                "detail": row.get("detail"),
                "event_id": row.get("event_id"),
                "side": row.get("side"),
                "version": row.get("version"),
                "op": row.get("op"),
                "sources": _lines([row.get("_sources") or row.get("_line")]),
            }
    return {doc: [rows[key] for key in sorted(rows)] for doc, rows in grouped.items()}


def _decide(row, expired):
    state = row.get("visibility_state")
    source_op = row.get("source_op")
    index_op = row.get("index_op")
    still_searchable = index_op == "upsert"
    deletion_confirmed = source_op == "delete" and index_op == "delete" and state == "CONSISTENT"
    if still_searchable:
        return HOLD, "STILL_SEARCHABLE", still_searchable, deletion_confirmed
    if deletion_confirmed:
        if expired:
            return PURGE_BODY, "RETENTION_EXPIRED", still_searchable, deletion_confirmed
        return RETAIN_BODY, "RETENTION_ACTIVE", still_searchable, deletion_confirmed
    if source_op == "delete" and index_op == "delete":
        return HOLD, "VERSION_MISMATCH", still_searchable, deletion_confirmed
    if state == "MISSING_INDEX":
        return HOLD, "TARGET_ABSENT", still_searchable, deletion_confirmed
    if state == "DELETE_NOT_CONFIRMED":
        return HOLD, "DELETE_UNCONFIRMED", still_searchable, deletion_confirmed
    if state == "ORPHAN_INDEX":
        return HOLD, "ORPHAN_TARGET", still_searchable, deletion_confirmed
    return HOLD, "UNRESOLVED_STATE", still_searchable, deletion_confirmed


def _document(doc_id, row, days, as_of, bodies, relations, quarantine):
    if row is None:
        return {
            "doc_id": doc_id,
            "action": HOLD,
            "reason": "QUARANTINED",
            "expired": False,
            "retention_expires_at": None,
            "still_searchable": False,
            "deletion_confirmed": False,
            "tombstone": False,
            "source_version": None,
            "index_version": None,
            "source_op": None,
            "index_op": None,
            "visibility_state": None,
            "gate": None,
            "source_at": None,
            "visible_at": None,
            "source_lines": _lines([q.get("sources") for q in quarantine.get(doc_id, [])]),
            "body_sha256": bodies.get(doc_id),
            "body_retained_by_policy": True,
            "cleanable_fields": [],
            "retained_evidence": list(EVIDENCE_FIELDS),
            "relations": relations.get(doc_id, []),
            "quarantine": quarantine.get(doc_id, []),
        }
    expires_at, expired = _expiry(row, days, as_of)
    action, reason, still_searchable, confirmed = _decide(row, expired)
    lines = _lines([
        row.get("_sources"),
        [q.get("sources") for q in quarantine.get(doc_id, [])],
        [rel.get("source_lines") for rel in relations.get(doc_id, [])],
    ])
    return {
        "doc_id": doc_id,
        "action": action,
        "reason": reason,
        "expired": expired,
        "retention_expires_at": expires_at,
        "still_searchable": still_searchable,
        "deletion_confirmed": confirmed,
        "tombstone": row.get("source_op") == "delete" and row.get("index_op") == "delete",
        "source_version": row.get("source_version"),
        "index_version": row.get("index_version"),
        "source_op": row.get("source_op"),
        "index_op": row.get("index_op"),
        "visibility_state": row.get("visibility_state"),
        "gate": row.get("gate"),
        "source_at": row.get("source_at"),
        "visible_at": row.get("visible_at"),
        "source_lines": lines,
        "body_sha256": bodies.get(doc_id),
        "body_retained_by_policy": action != PURGE_BODY,
        "cleanable_fields": list(CLEANABLE_FIELDS) if action == PURGE_BODY else [],
        "retained_evidence": list(EVIDENCE_FIELDS),
        "relations": relations.get(doc_id, []),
        "quarantine": quarantine.get(doc_id, []),
    }


def build(run):
    """构建（或读取）稳定的到期证据包。纯函数，结果只取决于已保存的批次。"""
    stored = run.get("retention")
    if isinstance(stored, dict) and stored.get("package_sha256"):
        return stored
    if len(run.get("stages", [])) < 7:
        raise DomainError("INCOMPLETE_RUN", "批次尚未完成全部阶段")

    days, as_of = _policy(run.get("parameters"))
    bodies = _body_items(run)
    relations = _relations(run)
    quarantine = _quarantine(run)
    final_rows = run["stages"][6].get("rows", [])
    by_doc = {row.get("doc_id"): row for row in final_rows if row.get("doc_id")}

    docs = []
    for doc_id in sorted(set(by_doc) | set(quarantine) | set(bodies), key=str):
        docs.append(_document(doc_id, by_doc.get(doc_id), days, as_of, bodies, relations, quarantine))

    summary = {
        "documents": len(docs),
        "purge_body": sum(doc["action"] == PURGE_BODY for doc in docs),
        "retain_body": sum(doc["action"] == RETAIN_BODY for doc in docs),
        "hold": sum(doc["action"] == HOLD for doc in docs),
        "evidence_retained": len(docs),
        "cleanable_documents": sum(bool(doc["cleanable_fields"]) for doc in docs),
    }
    sealed = {
        "policy_version": POLICY_VERSION,
        "as_of": as_of.isoformat(),
        "retention_days": str(days),
        "documents": docs,
    }
    return {
        "run_id": run.get("run_id"),
        "input_sha256": (run.get("manifest") or {}).get("input_sha256"),
        "rule_version": (run.get("manifest") or {}).get("rule_version"),
        "generated_at": (run.get("manifest") or {}).get("generated_at"),
        **sealed,
        "summary": summary,
        "package_sha256": _sha(sealed),
    }


def _redact(row, digest):
    for key in CLEANABLE_FIELDS:
        if key in row:
            row[key] = None
    row["body_purged"] = True
    row["body_sha256"] = digest


def cleanup(run, package=None):
    """按证据包清理可清理正文。重复调用返回同一凭据，不新增或减少证据。"""
    package = package or build(run)
    receipt = run.get("retention_cleanup")
    if isinstance(receipt, dict) and receipt.get("package_sha256") == package["package_sha256"]:
        return None, receipt

    purged = sorted((doc["doc_id"] for doc in package["documents"] if doc["action"] == PURGE_BODY), key=str)
    digests = {doc["doc_id"]: doc["body_sha256"] for doc in package["documents"]}
    updated = {key: deepcopy(value) for key, value in run.items() if key not in {"version", "decision"}}
    targets = set(purged)
    for stage in updated.get("stages", []):
        for key in ("rows", "quarantine", "cumulative_quarantine"):
            for row in stage.get(key, []):
                if isinstance(row, dict) and row.get("doc_id") in targets:
                    _redact(row, digests.get(row.get("doc_id")))
    updated["retention"] = package
    updated["retention_cleanup"] = {
        "package_sha256": package["package_sha256"],
        "purged_docs": purged,
        "purged_count": len(purged),
        "purge_version": POLICY_VERSION,
    }
    return updated, updated["retention_cleanup"]
