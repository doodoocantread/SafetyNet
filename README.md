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
