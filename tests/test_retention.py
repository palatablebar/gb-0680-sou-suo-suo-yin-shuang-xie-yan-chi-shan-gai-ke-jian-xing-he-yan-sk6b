import csv,io,json
from app.pipeline import calculate,load_sample
from app import retention,store


def package(run): return retention.build(run)


def test_purge_retain_hold_classes(result):
    p=package(result)
    assert p["summary"]["purge_body"]==8
    assert p["summary"]["hold"]==5
    assert p["summary"]["evidence_retained"]==p["summary"]["documents"]==13
    by_doc={d["doc_id"]:d for d in p["documents"]}
    assert by_doc["0001"]["action"]=="PURGE_BODY" and by_doc["0001"]["cleanable_fields"]
    assert by_doc["0090"]["action"]=="HOLD" and by_doc["0090"]["reason"]=="TARGET_ABSENT"
    assert by_doc["0091"]["action"]=="HOLD" and not by_doc["0091"]["cleanable_fields"]
    assert by_doc["0093"]["action"]=="HOLD" and by_doc["0093"]["reason"]=="QUARANTINED"


def test_active_retention_retains_body(result):
    p=retention.build({**result,"parameters":{"retention_days":"0.001","retention_as_of":"2026-11-16T10:00:00Z"}})
    by_doc={d["doc_id"]:d for d in p["documents"]}
    assert by_doc["0001"]["action"]=="RETAIN_BODY"
    assert by_doc["0001"]["body_retained_by_policy"] and not by_doc["0001"]["cleanable_fields"]


def test_evidence_survives_cleanup(result):
    "TRAP-27 清理正文不能丢证据"
    p=package(result);updated,receipt=retention.cleanup(result,p)
    assert receipt["purged_docs"]==["0001","0002","0003","0004","0005","0006","0007","0008"]
    again=retention.build(updated)
    assert again["package_sha256"]==p["package_sha256"]
    before={d["doc_id"]:d for d in p["documents"]};after={d["doc_id"]:d for d in again["documents"]}
    for doc_id in receipt["purged_docs"]:
        assert after[doc_id]["source_lines"]==before[doc_id]["source_lines"]
        assert after[doc_id]["relations"]==before[doc_id]["relations"]
        assert after[doc_id]["body_sha256"]==before[doc_id]["body_sha256"]
        assert after[doc_id]["source_version"]==before[doc_id]["source_version"]


def test_body_removed_only_for_purged(result):
    p=package(result);updated,_=retention.cleanup(result,p)
    final=updated["stages"][6]["rows"]
    for row in final:
        if row["doc_id"] in {"0001","0002","0003","0004","0005","0006","0007","0008"}:
            assert row["payload"] is None and row["document"] is None and row["note"] is None
            assert row["body_purged"] is True and row["body_sha256"]
        else:
            assert "body_purged" not in row


def test_still_searchable_holds_body(result):
    "TRAP-28 仍在检索不得先清依据"
    doc=next(d for d in package(result)["documents"] if d["doc_id"]=="0091")
    assert doc["still_searchable"] is True and doc["action"]=="HOLD" and doc["reason"]=="STILL_SEARCHABLE"


def test_cleanup_is_idempotent(result):
    "TRAP-29 重跑清理不新增也不减少证据"
    p=package(result);first,receipt=retention.cleanup(result,p)
    second=None
    assert retention.cleanup(first,retention.build(first))==(None,receipt)
    again=retention.build(first)
    assert again["package_sha256"]==p["package_sha256"]
    assert again["summary"]==p["summary"]


def test_relations_recover_original_edits(result):
    doc=next(d for d in package(result)["documents"] if d["doc_id"]=="0001")
    versions=sorted((rel["side"],rel["version"],rel["op"]) for rel in doc["relations"])
    assert ("source","4","upsert") in versions and ("source","5","delete") in versions
    assert ("index","5","delete") in versions and ("index","4","upsert") in versions


def test_archive_uses_same_package(result):
    from app.archive import build_archive
    p=package(result)
    rows=list(csv.reader(io.StringIO(build_archive(result).lstrip("﻿"))))
    assert rows[0][-1]=="package_sha256"
    assert all(row[-1]==p["package_sha256"] for row in rows[1:])


def test_archive_unchanged_by_cleanup(result):
    p=package(result);updated,_=retention.cleanup(result,p)
    from app.archive import build_archive
    before=build_archive(result).splitlines()
    after=[line for line in build_archive(updated).splitlines() if ",cleanup," not in line]
    assert before==after


def test_archive_has_no_body_text(result):
    from app.archive import build_archive
    text=build_archive(result)
    assert "货品" not in text and "迟到" not in text
    rows=list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    evidence=json.loads(next(row for row in rows if row[3]=="document")[6])
    assert set(evidence).issuperset({"doc_id","relations","body_sha256","source_lines"})


def test_rerun_sample_keeps_purge_and_receipt(sample):
    "重跑同一来源只复用批次，不把已清理正文带回来"
    from app.pipeline import execute
    run=execute(sample);p=package(run);updated,receipt=retention.cleanup(run,p)
    store.replace(run["run_id"],updated)
    again=execute(sample)
    assert again["run_id"]==run["run_id"]
    assert again["retention_cleanup"]==receipt
    assert retention.build(again)["package_sha256"]==p["package_sha256"]
    assert retention.cleanup(again,retention.build(again))==(None,receipt)


def test_retention_api_roundtrip(client):
    run=client.post("/api/runs",json={"sample":"dirty.csv"}).get_json()
    p=client.get(f"/api/runs/{run['run_id']}/retention").get_json()
    assert p["summary"]["purge_body"]==8
    cleaned=client.post(f"/api/runs/{run['run_id']}/retention",json={}).get_json()
    assert cleaned["package_sha256"]==p["package_sha256"]
    assert cleaned["cleanup"]["purged_count"]==8
    again=client.post(f"/api/runs/{run['run_id']}/retention",json={}).get_json()
    assert again["cleanup"]==cleaned["cleanup"]
    assert client.get(f"/api/runs/{run['run_id']}").get_json()["stages"][6]["rows"][0]["body_purged"] is True
    review=client.post(f"/api/runs/{run['run_id']}/review",json={"version":1,"decision":"已复核"})
    assert review.status_code==200 and review.get_json()["decision"]=="已复核"
