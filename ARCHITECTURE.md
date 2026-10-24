# SafetyWebbing — Kiến trúc

> Dự án khoa học cấp trường. Agent AI đóng vai **tổng hợp kết quả scan thành báo cáo**,
> **không** tự quyết định hay tự viết mã tấn công. Thời lượng: 1 tuần.
>
> Tài liệu này đóng băng các quyết định kiến trúc đã chốt qua thảo luận. Mọi quyết định đều đã
> được kiểm chứng trên code thật của PentestGPT (`../PentestGPT`) và target Juice Shop
> (`../juice-shop`, `http://127.0.0.1:3000`).

## 1. Mục tiêu & phạm vi

- **Input:** người dùng nhập một URL web **local** (vd `http://127.0.0.1:3000`) và chọn loại scan.
- **Xử lý:** một engine quét thật (PentestGPT agent) chạy trong môi trường cô lập → xuất kết quả có
  cấu trúc.
- **Output:** báo cáo lỗ hổng (bảng Finding: severity, CWE/OWASP, bằng chứng, khuyến nghị) xuất
  markdown/PDF.
- **Ngoài phạm vi tuần này:** đa người dùng/auth, database riêng, scheduler, tự viết exploit mới,
  scan target ngoài whitelist.

## 2. Ràng buộc an toàn (bất biến)

1. **Whitelist cứng (hard gate):** backend chỉ chấp nhận `localhost` / `127.0.0.1` / `[::1]`. Mọi URL
   khác bị từ chối **trước khi** spawn bất cứ thứ gì. Agent không bao giờ tự chọn target.
2. **Scope cố định:** khi nhập URL, backend truyền một **goal template viết sẵn** cho agent. Tính tự
   động bị chặn bằng *code*, không phải bằng thiện chí của LLM.
3. **Cô lập agent:** agent pentest chạy với `SandboxPolicy.FULL_ACCESS` (toàn quyền shell), nên nó
   **bắt buộc chạy trong Docker container**, không chạy in-process trên máy host. Ranh giới an toàn
   thật nằm ở container, không phải ở whitelist URL.
4. **LLM không khẳng định điều không có bằng chứng:** tầng LLM chỉ *diễn giải*, mọi khẳng định phải
   trích dẫn evidence từ output của engine.
5. **Ghi log mọi lần scan** (target, goal, thời điểm, run_id).

## 3. Quyết định kiến trúc (đã chốt)

| # | Quyết định | Lý do |
|---|---|---|
| Phạm vi | Agent = report-writer, không tự viết exploit | Đúng tinh thần dự án; khả thi trong 1 tuần |
| Luồng | Nhập URL local → agent kiểm tra → báo cáo | Đúng mô tả ban đầu |
| Engine | PentestGPT trước, ZAP sau — **interface pluggable** | Tận dụng agent có sẵn; mở rộng được |
| Extract | **Vendor 10 file** `pentestgpt_agent` + `unified-agent` qua **git source** | Self-contained, không lấy cả repo |
| Cô lập | Chạy agent **trong Docker**, mount `runs/` | Agent FULL_ACCESS cần container làm ranh giới |
| Goal scope | **Menu 3–4 loại** → goal template | Hẹp, rẻ, tất định hơn; UI đẹp |
| Finding | **Join `summary.json` ⨝ `traces/`** | Báo cáo cần request→response→tác động |
| Demo mode | **Replay engine** đọc summary đã lưu | Demo không sợ fail/đắt trên sân khấu |
| Fact/narrative | Tách **fact tất định** vs **diễn giải LLM** | Chống LLM bịa severity; truy vết được |

## 4. Kết quả kiểm chứng trên code thật

| # | Việc kiểm chứng | Kết quả |
|---|---|---|
| 1 | `uv sync` kéo được `unified-agent` từ git repo ngoài | ✅ Được → **không cần** vendor thêm `unified_agent` |
| 2 | `traces/` có chứa request/payload (không chỉ response) | ✅ Có → schema `Finding` join được |
| 3 | Auth backend chạy được | ✅ Dùng **Claude Code session** |

Bằng chứng tham chiếu (trong `../PentestGPT`):
- Seam lập trình: `pentestgpt_agent/src/pentestgpt_agent/trial.py` →
  `async run_trial(config: TrialConfig) -> dict` ("persists a summary even on failure").
- Dependency git: `pentestgpt_agent/pyproject.toml` → `[tool.uv.sources] unified-agent = { git =
  "...UnifedAgentWrapper.git", rev = "acff8ee..." }`.
- Output mẫu thành công: `pentestgpt_agent/runs/sqli-claude-03/summary.json` (SQLi login-bypass
  Juice Shop, lấy được JWT admin; cost $0.87; 113s).

## 5. Sơ đồ luồng

```
[Frontend React]
  form URL local + dropdown loại scan
        │  POST /scan { target, scan_type }
        ▼
[Backend FastAPI]
  1) Hard-gate whitelist localhost  ──(URL ngoài)──► 400 Rejected
  2) Map scan_type → goal template cố định
  3) Tạo job async → trả job_id
        │
        ▼
[Engine (interface)]  cùng trả về RunResult(summary, traces)
  ├── LiveAgentEngine   → docker run (pentestgpt_agent) → runs/<id>/summary.json + traces/
  └── ReplayEngine      → đọc runs/<id>/ đã lưu (demo mode, không cần auth)
        │
        ▼
[Adapter]  summary.json ⨝ traces/  →  list[Finding]        ← FACT (tất định, không LLM)
        │     Finding = { task_kind, request, response, evidence_seq, raw_status }
        ▼
[LLM layer]  gán nhãn lỗ hổng + severity + CWE                ← NARRATIVE (LLM, phải trích evidence)
        │     CWE → OWASP Top 10 bằng BẢNG TĨNH (không LLM)
        │     + giải thích dễ hiểu + khuyến nghị khắc phục
        ▼
[Report]  markdown → HTML (hiển thị) → export PDF

Frontend poll GET /scan/{job_id} để hiện progress (scan live ~1–2 phút).
```

## 6. Thành phần & trách nhiệm

### Engine (interface pluggable)
- Hợp đồng chung: `run(target, goal) -> RunResult`. `RunResult` bọc `summary` (dict) + đường dẫn
  `traces/`.
- `LiveAgentEngine`: spawn Docker container chạy agent đã chọn (`config.AGENTS`) với target đã
  whitelist + goal template. Mount thư mục `runs/` ra host. **Chọn agent** là lựa chọn mỗi lần quét,
  tách khỏi chế độ chạy; engine chỉ đổi `image` + cách xác thực (`auth`):
  - `pentestgpt` (`safetywebbing-agent`, mặc định): `backend="claude"`, mount bản sao tạm của credential
    Claude Code trên host.
  - `hackingbuddy` (`safetywebbing-hackingbuddy`): use-case web của hackingBuddyGPT; không mount
    credential, thay vào đó chuyển tiếp API key LLM từ môi trường server (litellm). Chỉ chế độ docker.
  Mọi agent ghi **cùng** `summary.json` + `traces/`, nên adapter/labeler/report phía sau không đổi.
- `ReplayEngine`: đọc một thư mục `runs/<id>/` có sẵn. Dùng cho demo mode và test — **không cần
  auth, không tốn tiền, tất định**.
- (Tuần sau, nếu kịp) `ZapEngine`: chạy OWASP ZAP baseline → cùng trả `RunResult`.

### Adapter (tất định)
- Đọc `summary.json`: `goal`, `targets`, `status`, `cost_usd`, `tasks[]`, `observations[]`,
  `transitions[]`.
- **Join với `traces/`** qua `evidence_sequences` để lấy request/payload tương ứng với mỗi response.
- Sinh `list[Finding]` chỉ gồm fact. Không gọi LLM ở tầng này.
- **Xử lý run `failed` trung thực:** phân biệt rõ *"không tìm thấy lỗ hổng"* vs *"run lỗi, không
  kết luận được"* (đọc `status` + `error`). 3/4 run cũ fail vì auth — không được coi là "sạch".

### LLM layer (narrative)
- Nhận `list[Finding]` (fact) → gán nhãn loại lỗ hổng, severity, CWE; giải thích; gợi ý fix.
- **CWE → OWASP Top 10: bảng tra cứu tĩnh** (tất định, rẻ, không bịa). LLM chỉ chịu trách nhiệm
  "observation này là CWE nào".
- **Bắt buộc trích `evidence_sequences`** cho mỗi khẳng định.
- **Trust boundary:** request/response thô là **dữ liệu không tin cậy** đi vào prompt → đóng khung
  trong delimiter, nhắc LLM coi evidence là dữ liệu (chống prompt injection).
- Provider của tầng report tách rời với backend pentest (có thể khác nhau).

### Backend (FastAPI)
- `POST /scan { target, scan_type }` → validate whitelist → tạo job async → `job_id`.
- `GET /scan/{job_id}` → trạng thái + progress (đọc `transitions[]`/phase từ engine).
- `GET /report/{job_id}` → báo cáo đã tổng hợp.
- `GET /report/{job_id}/pdf` → export.

### Frontend (React)
- Form URL + dropdown loại scan → progress bar → bảng Finding (fact + narrative tách cột) → nút
  export PDF/markdown.

## 7. Seam tích hợp cần làm đúng

1. **Docker + Claude Code session auth:** container của `LiveAgentEngine` phải **thấy credentials**
   của Claude Code session (mount file auth read-only vào container, hoặc login trong container).
   Làm sai → container báo `not authenticated` như 3/4 run cũ. `ReplayEngine` không dính vấn đề này.
2. **`unified-agent` là git dependency, KHÔNG phải PyPI:** `pyproject.toml` của SafetyWebbing phải copy
   nguyên khối `[tool.uv.sources]` với đúng rev `acff8ee`. `pip install unified-agent==0.3.0` sẽ
   **không** ra đúng package.
3. **Join traces:** schema `Finding` phụ thuộc vào cấu trúc `traces/`. Đã xác nhận traces chứa
   request/payload; cần cố định mapping `evidence_sequences` → file trace khi dựng adapter.

## 8. Vendor từ PentestGPT

Lấy vào SafetyWebbing:
- `pentestgpt_agent/src/pentestgpt_agent/` — **10 file**: `agents.py`, `audit.py`, `execution.py`,
  `identifiers.py`, `loop.py`, `memory.py`, `plan.py`, `trace.py`, `trial.py`, `__init__.py`.
- Khai báo `unified-agent` qua git source (như §7.2).

**Không** lấy: `pentestgpt_legacy/`, Docker gốc, benchmark, và bản `unified_agent/` ở root repo
(CLAUDE.md ghi rõ là *obsolete compatibility copy*).

**License:** vendor code PentestGPT → giữ attribution theo `LICENSE.md` của họ; ghi nguồn trong
README của SafetyWebbing.

## 9. Lộ trình 7 ngày

- **Ngày 1:** Khởi tạo repo SafetyWebbing; vendor 10 file + khai báo `unified-agent` git source; dựng
  `LiveAgentEngine` (Docker) + xử lý mount credentials Claude Code; chạy ra 1 `summary.json` thật
  trên `127.0.0.1:3000`.
- **Ngày 2:** Backend FastAPI: hard-gate whitelist, `POST /scan` (job async), `GET /scan/{id}`
  progress; menu goal template.
- **Ngày 3:** Adapter `summary ⨝ traces → Finding`; xử lý cả run failed; `ReplayEngine` + demo mode.
- **Ngày 4:** LLM layer: gán nhãn/severity/CWE + bảng tĩnh OWASP + remediation; trust boundary.
- **Ngày 5:** Frontend: form URL + dropdown, progress bar, bảng findings.
- **Ngày 6:** Export PDF/markdown; polish; (nếu kịp) `ZapEngine`.
- **Ngày 7:** Test end-to-end trên run thật + demo mode; viết slide báo cáo khoa học.
