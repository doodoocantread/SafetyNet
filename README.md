# SafetyNet

Dự án khoa học cấp trường. SafetyNet nhận một URL web **local** được phép kiểm thử, cho một agent
quét chạy **trong môi trường cô lập**, rồi dùng LLM **tổng hợp kết quả thành báo cáo lỗ hổng**.

> Agent AI đóng vai tổng hợp/giải thích. Nó **không** tự chọn mục tiêu, **không** tự quyết định tấn
> công, **không** tự viết mã khai thác mới. Xem [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Thành phần

- `src/safetynet/` — app host (FastAPI, sắp tới). Chỉ orchestrate; không chạy agent in-process.
  - `config.py` — whitelist target local + goal template cố định (2 ràng buộc an toàn cứng).
  - `engines/` — interface engine + `LiveAgentEngine` (chạy agent trong Docker).
- `agent_image/` — image Docker chứa agent PentestGPT đã **vendor** (10 file) + `unified-agent`.
  Agent FULL_ACCESS chỉ chạy bên trong container này.
- `agent_image_hackingbuddy/` — image Docker cho agent thứ hai: use-case web của hackingBuddyGPT,
  bọc bởi một wrapper nói đúng hợp đồng `summary.json` của SafetyNet (xem “Chọn agent” bên dưới).
- `runs/` — kết quả scan (`summary.json` + `traces/`), bind-mount từ container ra host.

## Nguồn vendor

Agent được rút trích từ `../PentestGPT/pentestgpt_agent` (package 10 file). `unified-agent` được kéo
qua **git source** (không phải PyPI), pin đúng revision. Attribution theo `LICENSE.md` của PentestGPT.

## Chạy agent live (Ngày 1)

Cần: Docker Desktop đang chạy, target local đang chạy (vd Juice Shop ở `http://127.0.0.1:3000`), và
Claude Code đã đăng nhập trên host (`~/.claude`).

```bash
# 1. Build image (một lần)
docker build -t safetynet-agent ./agent_image

# 2. Chạy thử trực tiếp (bỏ qua backend, để kiểm tra image)
docker run --rm --add-host host.docker.internal:host-gateway \
  -v "$PWD/runs:/work/runs" \
  -v "$HOME/.claude:/root/.claude:ro" \
  safetynet-agent \
  --goal "Tim SQL injection tren web app duoc phep kiem thu." \
  --target http://host.docker.internal:3000 \
  --backend claude --run-id smoke-01 --runs-root /work/runs
```

Kết quả nằm ở `runs/smoke-01/summary.json`.

## Hai chế độ chạy

| Chế độ | Cách chạy | Cô lập | Dùng khi |
|---|---|---|---|
| `docker` (mặc định) | `docker run` image `safetynet-agent` | Có — container là ranh giới an toàn | Mặc định; demo; target không hoàn toàn tin được |
| `direct` | chạy thẳng CLI `pentestgpt-agent` như tiến trình trên máy | **Không** — agent toàn quyền trên máy bạn | Lặp nhanh trên máy dev, không có Docker |

Whitelist loopback, goal cố định, audit log, adapter và báo cáo **giống hệt** ở cả hai chế độ.
Chế độ `direct` chỉ bật được từ phía server (UI/request không tự bật được).

### Bật chế độ direct

Cần: Claude Code CLI đã đăng nhập trên máy, và agent cài trong venv **riêng** (host app không import agent).

```bash
# 1. Cài agent vào venv riêng. Lưu ý --python 3.12 (Python mới hơn có thể thiếu wheel cho pyyaml)
uv venv .agent-venv --python 3.12
uv pip install --python .agent-venv/Scripts/python.exe ./agent_image   # Linux/macOS: .agent-venv/bin/python

# 2. Khởi động server với opt-in (PowerShell: $env:SAFETYNET_ALLOW_DIRECT = "1")
SAFETYNET_ALLOW_DIRECT=1 uv run uvicorn safetynet.api:app --port 8000
```

Engine tự tìm `.agent-venv`; muốn dùng lệnh khác thì đặt `SAFETYNET_AGENT_CMD`
(ví dụ `uv run --project agent_image pentestgpt-agent`). Trên UI, ô **Chế độ chạy** sẽ mở khoá
mục “Trực tiếp trên máy”; gọi API thì thêm `"mode": "direct"` vào `POST /api/scan`.
`GET /api/modes` cho biết chế độ nào đang khả dụng và vì sao không.

Ghi chú về `direct`: `ANTHROPIC_API_KEY` của host (dùng cho bộ gán nhãn) bị loại khỏi môi trường
của agent để khớp với container; hết thời gian chờ thì cả cây tiến trình bị kill; mỗi scan được
ghi `mode` vào `runs/audit.log`.

### Tham số tuỳ chọn mỗi lần quét: `model`, `timeout_s`

`POST /api/scan` nhận thêm hai trường tuỳ chọn, cũng có trên UI:

- `model` — model id cho agent (vd `claude-sonnet-5-5`). Bỏ trống thì dùng mặc định của Claude Code
  CLI. Được kiểm tra chặt (`config.validate_model`) để không lọt cờ lệnh qua argv.
- `timeout_s` — ngân sách thời gian cho một lần quét, 30–3600 giây (mặc định 600). Vì agent
  `FULL_ACCESS`, đây cũng là một nút an toàn chứ không chỉ hiệu năng — có trần cứng 3600s dù request
  xin bao nhiêu.

Cả hai là bản sao riêng cho từng lần quét (`dataclasses.replace`), không đụng tới engine dùng chung.

### Lịch sử quét

Tab **Lịch sử** trên UI liệt kê mọi lần quét live (mới nhất trước) với URL, loại scan, chế độ chạy,
model, trạng thái, chi phí/thời gian; lọc theo URL/model/loại scan hoặc trạng thái; bấm vào một dòng để
mở lại đúng báo cáo cùng cấu hình đã dùng. Scan lỗi/hết giờ/bị gián đoạn cũng có dòng riêng kèm lý do.

Không có kho dữ liệu mới: lịch sử được dựng từ `runs/audit.log` (đã ghi sẵn target, scan_type, mode,
model, timeout) ghép với `runs/<run_id>/summary.json` (`history.py`). Khi một scan kết thúc, báo cáo đã
gán nhãn được lưu vào `runs/<run_id>/report.json` để mở lại không gọi lại LLM và không đổi lời giữa các
lần xem; scan cũ chưa có file này sẽ được dựng lại từ `summary.json` + `traces/`. API:
`GET /api/history` và `GET /api/history/{run_id}` (`{meta, report}`; `report` là `null` nếu scan không
tạo ra báo cáo). Scan ghi trước khi có `timeout_s`/`model` trong audit log sẽ hiện “—”.

### Menu và các trang

`Tổng quan` (`/`) · `Quét mới` (`/scan`) · `Lịch sử` (`/history`) · `Lỗ hổng` (`/vulns`) ·
`Phương pháp & Đóng góp` (`/about`, trang học thuật) · `Hệ thống` (`/system`).

- **Tổng quan** — số liệu gộp mọi lần quét: lỗ hổng đang mở theo mức độ, phân bố OWASP, rủi ro theo
  target, số lần quét theo ngày, và danh sách “cần chú ý” (lỗ hổng tái phát, scan lỗi/gián đoạn). Một
  scan `failed` **không** được tính là “sạch”. `GET /api/overview`.
- **Lỗ hổng** — gộp trùng finding qua nhiều scan (vân tay = target + CWE/loại + endpoint, `insights.py`),
  kèm trạng thái xử lý do bạn đặt: Mới / Đang sửa / Đã sửa / False positive / Chấp nhận rủi ro. Trạng
  thái lưu ở `runs/triage.json`, tách khỏi bằng chứng scan. Hiện gợi ý “không xuất hiện ở N lần quét
  sau” (chỉ đếm scan `completed`, cùng target + loại scan) và cờ “tái phát” khi lỗ hổng đã `Đã sửa`
  xuất hiện lại. Gộp scan cũ chưa có `report.json` dùng nhãn heuristic offline, không gọi LLM.
  `GET /api/vulns`, `PUT /api/vulns/{id}/triage`. Nút “Quét lại” mở `/scan?target=…&type=…`.
- **Hệ thống** — Docker CLI/daemon/image, agent CLI của chế độ `direct`, nhãn LLM hay heuristic (có
  cảnh báo khi có `ANTHROPIC_API_KEY` mà thiếu package `anthropic`), giới hạn đang áp dụng, phạm vi
  quét cố định và nhật ký `audit.log`. Chỉ báo có/không của secret, không bao giờ hiện giá trị.
  `GET /api/system`, `GET /api/audit`.

## Chọn agent: PentestGPT · hackingBuddyGPT

Mỗi lần quét chọn **agent nào** sẽ chạy, độc lập với **chế độ chạy** (docker/direct). Mọi agent đều
ghi **cùng một hợp đồng trên đĩa** — `runs/<run_id>/summary.json` + `traces/` — nên toàn bộ pipeline
phía sau (adapter → labeler → báo cáo) giống hệt nhau bất kể agent nào đã chạy. Chúng chỉ khác ở
image Docker và cách xác thực LLM. Khai báo trong `config.py` (`AGENTS`); UI lấy qua `GET /api/agents`.

| Agent | Image | Xác thực LLM | Chế độ | Ghi chú |
|---|---|---|---|---|
| `pentestgpt` (mặc định) | `safetynet-agent` | Phiên Claude Code OAuth của host (mount bản sao tạm) | `docker`, `direct` | Agent PentestGPT đã vendor; hành vi như trước. |
| `hackingbuddy` | `safetynet-hackingbuddy` | API key LLM qua litellm (nhập trên UI mỗi lần quét, hoặc env server) | chỉ `docker` | Use-case **web** của [hackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) (`WebTestingWithExplanation`). |

Chỉ dùng use-case **web** của hackingBuddy (nhận một URL `--host`), khớp với mô hình an toàn của
SafetyNet (whitelist loopback + cô lập container). Các use-case privesc (SSH/local-shell chạy lệnh
thật trên máy) **không** được đưa vào. hackingBuddy chỉ chạy ở chế độ `docker` (có ranh giới cô lập);
nó không có đường `direct`.

### Build image hackingBuddy

```bash
docker build -t safetynet-hackingbuddy ./agent_image_hackingbuddy
```

Wrapper (`agent_image_hackingbuddy/safetynet_hb_agent/`) nhận **đúng** bộ tham số CLI như agent
PentestGPT (`--goal --target --run-id --runs-root …`), chạy `wintermute WebTestingWithExplanation
--host <target> --hints <goal> …`, rồi dịch log JSONL của hackingBuddy sang `summary.json` + `traces/`
(`translate.py`, đã có unit test).

### Xác thực & model cho hackingBuddy

hackingBuddy dùng **litellm**, không dùng Claude Code CLI như PentestGPT. Nghĩa là nó gọi API của nhà
cung cấp (vd **Anthropic** `api.anthropic.com`, **Google Gemini**, OpenAI, OpenRouter) qua một API key,
chứ **không** dùng được phiên Claude Code OAuth mà PentestGPT dùng.

**Nhập key ở đâu** — hai cách, không loại trừ nhau:

1. **Trên UI (mỗi lần quét).** Khi chọn agent `hackingBuddyGPT`, trang **Quét mới** hiện ô **Nhà cung
   cấp LLM** (Anthropic / Gemini / OpenAI / OpenRouter) + ô **API key**. Key chỉ dùng cho lần quét đó,
   **không** ghi ra đĩa, **không** vào `audit.log`; nó được nhớ trong `localStorage` của trình duyệt bạn
   (theo từng provider) cho tiện, và gửi kèm request. `GET /api/llm-providers` liệt kê các provider.
2. **Môi trường server.** Đặt `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` / `OPENAI_API_KEY` /
   `OPENROUTER_API_KEY`. Nếu có sẵn, UI báo “đã có key ở server” và bạn để trống ô API key cũng chạy được.

Engine chuyển key vào container **theo tên** (`docker run -e NAME`) — giá trị không bao giờ lên argv:
key từ UI được tiêm vào môi trường của tiến trình `docker` dưới tên env của provider rồi forward đúng
một tên đó vào container.

**Model** là chuỗi **định dạng litellm** (`anthropic/claude-sonnet-5-5`, `gemini/gemini-1.5-pro`,
`gpt-4o`, `openrouter/…`) — khác model id của Claude Code. Thứ tự: `SAFETYNET_HB_LLM_MODEL` (ưu tiên) →
ô **Model** trên UI/`--model`: id trần `claude-…`/`gemini-…` tự map thành `anthropic/…`/`gemini/…` theo
provider, hoặc để nguyên nếu đã có `/` → mặc định theo provider. Tinh chỉnh thêm:
`SAFETYNET_HB_LLM_API_BASE`, `SAFETYNET_HB_LLM_CONTEXT_SIZE`.

> Lưu ý an toàn: key này được đưa vào container agent FULL_ACCESS (đọc nội dung web không tin cậy).
> Container là ranh giới cô lập; đây là đánh đổi cần thiết vì hackingBuddy bắt buộc phải có key LLM.

## Kết quả thử nghiệm model (chế độ `direct`, 2026-10-15)

Thử 3 model với cùng goal SQLi, khác target đúng theo kết quả quan sát ở lần trước:

| Model | Kết quả | Ghi chú |
|---|---|---|
| `claude-opus-5-5` | Bị chặn ngay (`exit 1`, 2 lần thử) | Bộ lọc an toàn của Anthropic (Opus 5) đánh dấu prompt pentest — lỗi `API Error: ... safeguards flagged this message`. Không liên quan code SafetyNet; xem [support.claude.com](https://support.claude.com/) nếu cần dùng Opus cho mục đích bảo mật hợp pháp. |
| `claude-sonnet-5-5` | `completed`, nhưng **vô nghĩa** | Target lúc đó (`:5173`, SPA tĩnh) không có API để tìm SQLi. Agent `FULL_ACCESS` không có container nên tự ý đọc mã nguồn `src/safetynet/` và gửi request thử SQLi vào chính API SafetyNet ở `:8000`. Bị `config.validate_target` chặn nên không gây hậu quả thật, nhưng là bằng chứng cụ thể rằng `direct` mode không có ranh giới an toàn — đúng như cảnh báo trên UI. |
| `claude-haiku-5-5` | `failed`, nhưng **có dữ liệu thật** | Nhắm đúng vào một app Next.js thật (`:3000`). Agent tìm ra tham số `category`, test SQLi boolean-based (`AND '1'='1'` so với `AND '1'='2'`) — hai lần cho kết quả **giống hệt nhau** (132 sản phẩm) → không có SQLi ở điểm này. Toàn bộ run vẫn bị đánh dấu `failed` vì một bản tóm tắt của Executor dài 2054 ký tự, vượt giới hạn cứng **2000 ký tự** trong code vendor (`agent_image/pentestgpt_agent/execution.py:309`), chỉ hơn 54 ký tự. Không phải lỗi SafetyNet; chưa thử lại để biết đây là ngẫu nhiên hay haiku có xu hướng viết dài hơn mức schema cho phép. |

Rút ra: chế độ `direct` thực thi đúng như thiết kế (không container, đọc được mọi thứ trên máy host),
nên chỉ nên dùng với target mà bạn chắc chắn tin tưởng. `claude-haiku-5-5` là model duy nhất trong 3
model thử không bị chặn và không đi lạc khỏi target — nhưng có rủi ro riêng (dễ vượt giới hạn độ dài
của validator vendor). Dữ liệu run nằm ở `runs/live-4f8d95f91333/` và `runs/live-067027fcf56c/` (gitignored, chỉ trên máy đã chạy thử).
