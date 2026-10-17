"""逐条实测"控制台在用的 API 路径"（控制台↔后端契约收口验证）。

为什么要它：平台 API 的真实路由与 `apps/web/src/api/client.ts` 的调用曾经大面积对不上（404 / 形状不符 / 恒空）。本脚本把这份契约变成**可复跑**的检查：路径、形状（裸数组 vs 分页信封）、以及"列表必须有数据"。\n\n用法（compose 栈已起；走 nginx 同源，即浏览器真实路径）：
    $env:AGF_LIVE_PASSWORD=<.env 里的 AGF_BOOTSTRAP_ADMIN_PASSWORD>\n    $env:AGF_LIVE_NEW_PASSWORD=<首登要改成的口令>\n    python scripts/verify-console-paths.py http://127.0.0.1:8081

做的事：
 1. 登录（自动处理"首登强制改密"：用 change_token 改密后再登一次）；
 2. 打一遍**列表**端点，打印状态码与 total（期望全部 200 且 total > 0）；
 3. 从列表里取真实 id，再打一遍**带 {id} 的**端点与新端点
    （`/mcp-servers/{id}/tools` 例外：遍历列表挑一个**真有 tools** 的记录再断言，
     避免断言强度被"列表第一条是谁"这种数据状态绑定，见 `mcp_server_with_tools`）；
 4. 汇总 PASS/FAIL，FAIL 时给出响应体片段。

生产核对请加 `--read-only`：仅登录并检查 GET 路由，不执行状态回写，允许无业务记录的空列表。
若还要断言演示数据完整，另加 `--require-demo-data`。
不加参数的完整模式包含写操作，只用于隔离测试环境。
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import uuid

BASE = next((arg for arg in sys.argv[1:] if not arg.startswith("--")), "http://127.0.0.1:8080").rstrip("/")
READ_ONLY = "--read-only" in sys.argv[1:]
REQUIRE_DATA = not READ_ONLY or "--require-demo-data" in sys.argv[1:]
PASSWORD = os.environ.get("AGF_LIVE_PASSWORD", "")
NEW_PASSWORD = os.environ.get("AGF_LIVE_NEW_PASSWORD", "")
TOKEN: str | None = None

PASS: list[str] = []
FAIL: list[tuple[str, str]] = []
UNCONFIGURED_SOURCES = {"/api/v1/sources", "/api/v1/ingest/sources"}


def call(method: str, path: str, body: object | None = None, token: str | None = None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            text = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(text) if text else None), text
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(text) if text else None, text
        except json.JSONDecodeError:
            return e.code, None, text
    except Exception as e:  # noqa: BLE001
        return 0, None, str(e)


def login() -> bool:
    global TOKEN
    for pw in (NEW_PASSWORD, PASSWORD):
        if not pw:
            continue
        status, data, _ = call("POST", "/api/v1/auth/login", {"username": "admin", "password": pw})
        if status != 200 or not isinstance(data, dict):
            continue
        if data.get("must_change_password"):
            if READ_ONLY:
                print("!! 只读模式发现首登强制改密；请先由管理员在控制台完成改密")
                return False
            change = data.get("change_token", "")
            st, _, body = call(
                "POST",
                "/api/v1/auth/change-password",
                {"new_password": NEW_PASSWORD},
                token=change,
            )
            if st != 200:
                print(f"!! 改密失败 HTTP {st}: {body[:200]}")
                return False
            status, data, _ = call("POST", "/api/v1/auth/login", {"username": "admin", "password": NEW_PASSWORD})
            if status != 200:
                return False
        tokens = (data or {}).get("tokens") or {}
        TOKEN = tokens.get("access_token")
        if TOKEN:
            print("登录成功")
            return True
    print("!! 登录失败（检查 AGF_LIVE_PASSWORD / 账号是否被锁定）")
    return False


def total_of(payload) -> str:
    if isinstance(payload, list):
        return f"count={len(payload)}"
    if isinstance(payload, dict):
        if "total" in payload:
            extra = f" items={len(payload.get('items') or [])}"
            return f"total={payload['total']}{extra}"
        return f"obj keys={len(payload)}"
    return "n/a"


def check(method: str, path: str, body: object | None = None, *, expected: int = 200):
    status, data, text = call(method, path, body, TOKEN)
    label = f"{method:<4} {path}"
    if status == expected:
        PASS.append(label)
        print(f"  OK   {label:<52} {status}  {total_of(data)}")
        return data
    if status == 501 and "501" in text:
        FAIL.append((label, f"501 未实现: {text[:120]}"))
        print(f"  501  {label:<52} 501  {text[:100]}")
        return None
    FAIL.append((label, f"HTTP {status}: {text[:160]}"))
    print(f"  FAIL {label:<52} {status}  {text[:120]}")
    return None


def contract(label: str, valid: bool, why: str) -> bool:
    if valid:
        PASS.append(label)
        print(f"  OK   {label}")
    else:
        FAIL.append((label, why))
        print(f"  FAIL {label}: {why}")
    return valid


def canonical_uuid(value) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def check_mock_route() -> None:
    """完整隔离巡检注册真实 Mock 配置，不拿演示资产冒充可发布端点。"""
    if READ_ONLY:
        return
    name = "console-smoke-" + uuid.uuid4().hex
    endpoint = check("POST", "/api/v1/gateway/endpoints", {
        "name": name, "provider": "mock", "model": name, "base_url": "http://127.0.0.1:9/v1",
        "local_deployment": True, "enabled": True,
    }, expected=201)
    if not contract("本场 Mock 端点已配置", isinstance(endpoint, dict) and canonical_uuid(endpoint.get("id"))
                    and endpoint.get("provider") == "mock" and endpoint.get("mocked") is True
                    and endpoint.get("credential_configured") is False, "须返回真实 UUID/Mock/无凭据配置"):
        return
    endpoint_id = endpoint["id"]
    policy = check("POST", "/api/v1/models/route-policies", {
        "name": name, "primaryEndpointId": endpoint_id, "fallbackEndpointIds": [],
        "enabled": True, "expectedVersion": 0,
    })
    if not contract("本场策略创建引用真实端点", isinstance(policy, dict) and canonical_uuid(policy.get("id"))
                    and type(policy.get("version")) is int and policy["version"] == 1
                    and policy.get("primary_endpoint_id") == endpoint_id and policy.get("fallback_endpoint_ids") == [],
                    "策略须使用本场已配置端点及新建版本1"):
        return
    saved = check("PUT", "/api/v1/models/route-policies/" + policy["id"], {
        "name": name + "-saved", "expectedVersion": policy["version"],
    })
    valid = isinstance(saved, dict) and saved.get("id") == policy["id"] and saved.get("version") == policy["version"] + 1
    if not contract("本场策略版本 CAS 保存", valid, "保存须返回相同 ID 和递增版本"):
        return
    rows = check("GET", "/api/v1/models/route-policies")
    found = [row for row in rows if row.get("id") == policy["id"]] if isinstance(rows, list) else []
    contract("本场策略持久读回", len(found) == 1 and found[0].get("version") == saved["version"]
             and found[0].get("name") == name + "-saved" and found[0].get("primary_endpoint_id") == endpoint_id
             and found[0].get("fallback_endpoint_ids") == [] and found[0].get("enabled") is True,
             "读回须保留本场端点/新版本/启用状态")


def skill_detail(payload, skill_id: str):
    """GET 详情只接受真实 skill 包装；POST 审核仍按裸 SkillView 检查。"""
    skill = payload.get("skill") if isinstance(payload, dict) and set(payload) == {"skill"} else None
    review = skill.get("review") if isinstance(skill, dict) else None
    valid = (isinstance(skill, dict) and skill.get("id") == skill_id and isinstance(review, dict)
             and isinstance(review.get("lifecycle"), str) and bool(review["lifecycle"])
             and isinstance(review.get("allowedNext"), list)
             and all(isinstance(value, str) for value in review["allowedNext"])
             and isinstance(review.get("updatedAt"), str) and bool(review["updatedAt"].strip()))
    if not contract("Skill 详情包装及当前修订", valid, "详情须为 skill 包装、相同 ID 和完整审核状态/修订"):
        return None
    return skill


def check_skill_review(skill_id: str) -> None:
    """按实际允许边和修订审核，不以同状态或无审核备注的请求冒充动作验收。"""
    if READ_ONLY:
        return
    skill = skill_detail(check("GET", "/api/v1/skills/" + skill_id), skill_id)
    if skill is None:
        return
    review = skill["review"]
    allowed = review.get("allowedNext", [])
    target = next((value for value in ("under-review", "trial", "changing", "rejected", "archived") if value in allowed), None)
    revision = review.get("updatedAt")
    if not contract("Skill 有合法非生产审核边", target is not None and isinstance(revision, str) and bool(revision),
                    "当前 Skill 无合法非生产下一状态或缺修订；不得算通过"):
        return
    saved = check("POST", "/api/v1/skills/" + skill_id + "/status", {
        "to": target, "note": "隔离控制台契约巡检：按真实允许边审核", "expectedUpdatedAt": revision,
    })
    after = saved.get("review") if isinstance(saved, dict) else None
    after = after if isinstance(after, dict) else {}
    if not contract("Skill 审核状态及修订已提交", isinstance(saved, dict) and saved.get("id") == skill_id
                    and after.get("lifecycle") == target and isinstance(after.get("updatedAt"), str)
                    and after["updatedAt"] != revision, "审核须返回目标生命周期和新的真实修订"):
        return
    reread = skill_detail(check("GET", "/api/v1/skills/" + skill_id), skill_id)
    if reread is None:
        return
    current = reread["review"]
    contract("Skill 审核持久读回", isinstance(reread, dict) and reread.get("id") == skill_id
             and current.get("lifecycle") == target and current.get("updatedAt") == after["updatedAt"],
             "读回生命周期/修订须与成功审核一致")


def expect_positive(path: str, data) -> None:
    """演示数据应非空；只读路由核验不要求用户先创建业务记录。"""
    n = None
    if isinstance(data, list):
        n = len(data)
    elif isinstance(data, dict) and "total" in data:
        n = data["total"]
    if n == 0:
        if path in UNCONFIGURED_SOURCES:
            print(f"  EMPTY {path}: 尚未添加数据源，空列表有效")
            return
        if not REQUIRE_DATA:
            print(f"  EMPTY {path}: 尚无业务记录，空列表有效")
            return
        FAIL.append((f"GET  {path}", "200 但 total=0（灌库未生效？）"))
        print(f"  EMPTY {path}: 200 但 total=0")


def first_id(data) -> str | None:
    items = data
    if isinstance(data, dict):
        items = data.get("items")
    if isinstance(items, list) and items:
        return str(items[0].get("id") or items[0].get("key") or "")
    return None


#: 扫候选 MCP 记录的上限（避免列表异常大时把脚本拖成 N 次请求）。
MAX_TOOL_CANDIDATES = 10


def mcp_server_with_tools() -> tuple[str | None, str]:
    """挑一个**真的有工具**的 MCP 记录，返回 `(id, 说明)`。

    为什么不再固定取 `items[0]`：列表顺序由后端排序决定，且库里可能混入
    历史压测/验证遗留的记录（例如 `persist-proof-final`，其 `attributes.tools` 为空）。
    原先"取第一条再断言必须有工具"把**断言强度**绑在**数据状态 + 排序**上，
    于是同一条端点会因为一条无关的遗留记录而假失败（实测 54/1）。
    这里改为遍历候选、找到真正带 tools 的记录再断言：
    断言仍然是"必须有工具"（total>0），只是不再赌第一条是谁。
    """
    status, data, _ = call("GET", "/api/v1/mcp-servers", None, TOKEN)
    if status != 200:
        return None, f"列表端点 HTTP {status}"
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        return None, "列表为空或形状异常"
    tried: list[str] = []
    for entry in items[:MAX_TOOL_CANDIDATES]:
        sid = str(entry.get("id") or "")
        if not sid:
            continue
        st, tools, _ = call("GET", f"/api/v1/mcp-servers/{sid}/tools", None, TOKEN)
        n = len(tools) if isinstance(tools, list) else -1
        name = entry.get("name") or sid
        tried.append(f"{name}: HTTP {st} tools={n}")
        if st == 200 and n > 0:
            return sid, f"{name}（tools={n}）"
    return None, "；".join(tried)


def main() -> int:
    if not login():
        return 2

    print("\n== 1. 列表端点：必须 200；未配置工作流可为空 ==")
    lists = [
        "/api/v1/assets",
        "/api/v1/findings",
        "/api/v1/alerts",
        "/api/v1/cases",
        "/api/v1/policies",
        "/api/v1/agents",
        "/api/v1/skills",
        "/api/v1/models/endpoints",
        "/api/v1/mcp-servers",
        "/api/v1/reports",
        "/api/v1/scans",
        "/api/v1/redteam/campaigns",
        "/api/v1/quotas",
        "/api/v1/rules",
        "/api/v1/redteam/cases",
        "/api/v1/parsers",
        "/api/v1/sources",
        "/api/v1/audit",
    ]
    ids: dict[str, str | None] = {}
    for p in lists:
        data = check("GET", p)
        expect_positive(p, data)
        ids[p] = first_id(data)

    print("\n== 2. 新端点（GET） ==")
    cloud_checks = None
    for p in [
        "/api/v1/overview",
        "/api/v1/search?q=MCP",
        "/api/v1/topology",
        "/api/v1/users",
        "/api/v1/tenants",
        "/api/v1/api-keys",
        "/api/v1/settings/password-policy",
        "/api/v1/runtime/blacklists",
        "/api/v1/runtime/events",
        "/api/v1/runtime/intercept-points",
        "/api/v1/runtime/quotas",
        "/api/v1/agents/onboarding-plan",
        "/api/v1/alerts/escalation-routes",
        "/api/v1/models/route-policies",
        "/api/v1/models/usage",
        "/api/v1/models/usage/aggregate",
        "/api/v1/integrations/adapters",
        "/api/v1/alicloud/agentteams",
        "/api/v1/alicloud/agentteams/audit-sources",
        "/api/v1/alicloud/agentteams/audit-events",
        "/api/v1/alicloud/agentteams/worker-quotas",
        "/api/v1/alicloud/agentteams/team-management",
        "/api/v1/alicloud/cross-team-calls",
        "/api/v1/alicloud/service-bindings",
        "/api/v1/alicloud/self-check",
        "/api/v1/ingest/sources",
        "/api/v1/ingest/parsers",
    ]:
        data = check("GET", p)
        if p == "/api/v1/alicloud/self-check":
            cloud_checks = data
        # 演示栈应有种子数据；生产只读验收允许尚未配置的数据源和凭据为空。
        if p not in ("/api/v1/api-keys",):
            expect_positive(p, data)
    if isinstance(cloud_checks, list):
        false_checks = [item.get("id") for item in cloud_checks
                        if item.get("category") in ("least-privilege", "quota")
                        and (item.get("result") != "warn" or item.get("checkedAt") is not None)]
        if false_checks:
            FAIL.append(("云自检记录真实性", f"未验证的权限/配额显示已检查：{false_checks}"))
            print(f"  FAIL 云自检记录真实性：{false_checks}")
        else:
            PASS.append("云自检记录真实性")
            print("  OK   云最小权限与配额保持待核对，未编造检查时间")
    preview = check("GET", "/api/v1/ingest/replay?sourceId=codex-read-only-smoke-no-source&limit=1")
    if (isinstance(preview, dict) and preview.get("preview_only") is True
            and preview.get("replayed") == 0 and isinstance(preview.get("raw_logs"), list)):
        PASS.append("日志 GET 仅预览")
        print("  OK   日志 GET 标记为只读预览；实际回放要求 POST")
    else:
        FAIL.append(("日志 GET 仅预览", f"响应缺少只读预览标记：{str(preview)[:120]}"))
        print("  FAIL 日志 GET 没有只读预览标记")
    print("  （/api/v1/api-keys 刻意保持空：演示环境不预置凭据）")

    print("\n== 3. 别名 / 带 {id} 的端点 ==")
    # `/mcp-servers/{id}/tools` 的 id 由"扫到真正带 tools 的记录"决定（见 mcp_server_with_tools）：
    # 断言强度不变（必须真有工具），只是不再依赖列表第一条是谁。
    tools_id, tools_pick = mcp_server_with_tools()
    if tools_id:
        print(f"  选用 MCP 记录：{tools_pick}")
    elif REQUIRE_DATA:
        FAIL.append(("GET  /api/v1/mcp-servers/{id}/tools", f"没有任何 MCP 记录带 tools（{tools_pick}）"))
        print(f"  FAIL 未找到带 tools 的 MCP 记录：{tools_pick}")
    else:
        print("  EMPTY 尚未登记带 tools 的 MCP；只读巡检无需演示记录")
    pairs = [
        ("/api/v1/mcp-servers/{id}/tools", tools_id, True, "GET"),
        ("/api/v1/rules/{id}", first_id(check("GET", "/api/v1/rules")), False, "GET"),
        ("/api/v1/redteam/campaigns/{id}/results", ids.get("/api/v1/redteam/campaigns"), True, "GET"),
        ("/api/v1/cases/{id}/soar-runs", ids.get("/api/v1/cases"), True, "GET"),
        ("/api/v1/integrations/adapters/{id}", None, False, "GET"),
    ]
    for tmpl, rid, need_data, method in pairs:
        if READ_ONLY and method != "GET":
            print(f"  SKIP {tmpl}（只读模式）")
            continue
        if tmpl == "/api/v1/integrations/adapters/{id}":
            adapters = check("GET", "/api/v1/integrations/adapters")
            rid = first_id(adapters if isinstance(adapters, list) else None)
        if not rid:
            print(f"  SKIP {tmpl}（没有可用 id，说明上游列表是空的）")
            continue
        data = check(method, tmpl.replace("{id}", rid))
        if need_data:
            expect_positive(tmpl, data)

    if READ_ONLY:
        print("\n== 4. 动作类端点：只读模式跳过 ==")
    else:
        print("\n== 4. 动作类端点（仅隔离测试环境） ==")
        check_mock_route()
        if ids.get("/api/v1/findings"):
            check("POST", f"/api/v1/findings/{ids['/api/v1/findings']}/status", {"status": "pending"})
        if ids.get("/api/v1/alerts"):
            check("POST", f"/api/v1/alerts/{ids['/api/v1/alerts']}/status", {"status": "open"})
        if ids.get("/api/v1/skills"):
            check("PUT", f"/api/v1/skills/{ids['/api/v1/skills']}/whitelist", {"domains": [], "paths": []})
            check_skill_review(ids["/api/v1/skills"])

    print("\n" + "=" * 78)
    print(f"结果：PASS {len(PASS)} / FAIL {len(FAIL)}")
    if FAIL:
        print("\n失败清单：")
        for label, why in FAIL:
            print(f"  - {label}: {why}")
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
