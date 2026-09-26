"""Local-only security-hole lab. All files and responses are simulated."""
import argparse
import json
import os
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

HTML = Path(__file__).with_name("index.html")


def make_handler(log_file: Path):
    class LabHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, status, body, content_type="application/json; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)
            return len(data)

        def record(self, status, size):
            # Intentionally uses Nginx Proxy Manager's access-log shape, so the
            # real Sentinel watcher and manager pipeline can be exercised.
            now = datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")
            ip = self.client_address[0]
            line = (f'[{now}] - - {status} - GET http lab.local "{self.path}" '
                    f'[Client {ip}] [Length {size}] [Gzip -] [Sent-to 127.0.0.1] '
                    '"Sentinel-Lab" "-"\n')
            log_file.parent.mkdir(parents=True, exist_ok=True)
            with log_file.open("a", encoding="utf-8") as f:
                f.write(line)

        def do_GET(self):
            target = urlsplit(self.path)
            if target.path == "/":
                self.respond(200, HTML.read_text(encoding="utf-8"), "text/html; charset=utf-8")
                return
            if target.path == "/health":
                self.respond(200, json.dumps({"lab": "SENTINEL-LAB-V1"}))
                return
            if target.path.startswith("/probe/"):
                payload = {"status": 404, "message": "この架空サーバーに対象はありません"}
                size = self.respond(404, json.dumps(payload, ensure_ascii=False))
                self.record(404, size)
                return
            if target.path == "/files" or target.path.startswith("/files/"):
                query = parse_qs(target.query)
                raw_path = query.get("name", [unquote(target.path[len("/files/"):])])[0]
                parts = ["srv", "lab", "public"]
                for part in raw_path.split("/"):
                    if part == "..":
                        if parts:
                            parts.pop()
                    elif part and part != ".":
                        parts.append(part)
                resolved = "/" + "/".join(parts)
                fixed = query.get("mode") == ["fixed"]
                outside = not resolved.startswith("/srv/lab/public/")
                if fixed and outside:
                    code, message = 403, "公開エリア外のため拒否しました"
                elif resolved == "/srv/lab/secrets/keys.txt":
                    code, message = 200, "模擬ファイルに到達: DEMO-KEY-ONLY"
                elif resolved == "/srv/lab/public/guide.txt":
                    code, message = 200, "公開ガイドを表示しました"
                else:
                    code, message = 404, "模擬ファイルは見つかりません"
                size = self.respond(code, json.dumps({"status": code, "resolved": resolved, "message": message}, ensure_ascii=False))
                self.record(code, size)
                return
            size = self.respond(404, json.dumps({"status": 404}))
            self.record(404, size)

    return LabHandler


def main():
    parser = argparse.ArgumentParser(description="Sentinel用の隔離されたWebログ実験室")
    parser.add_argument("--log-file", required=True, type=Path, help="エージェントが監視するログの絶対パス")
    parser.add_argument("--bind", default="127.0.0.1", help="既定はローカルのみ")
    parser.add_argument("--port", type=int, default=8899)
    args = parser.parse_args()
    if not args.log_file.is_absolute():
        parser.error("--log-file は絶対パスで指定してください")
    args.log_file.parent.mkdir(parents=True, exist_ok=True)
    args.log_file.touch(exist_ok=True)
    server = ThreadingHTTPServer((args.bind, args.port), make_handler(args.log_file))
    print(f"Sentinel Lab: http://{args.bind}:{args.port}/", flush=True)
    print(f"Access log: {args.log_file}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
