import http.server
import socketserver
import json
import os
import webbrowser

PORT = 8080
os.chdir(os.path.dirname(os.path.abspath(__file__)))

class ConfigHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="ui", **kwargs)

    def do_POST(self):
        if self.path == '/api/whitelist/add':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)
            self._update_whitelist(data.get('domain'), 'add')
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')

        elif self.path == '/api/whitelist/remove':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data)
            self._update_whitelist(data.get('domain'), 'remove')
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        elif self.path == '/api/whitelist':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            domains = []
            env_file = "config/config.env"
            if os.path.exists(env_file):
                with open(env_file, "r") as f:
                    for line in f:
                        if line.startswith("WHITELIST_DOMAINS="):
                            val = line.strip().split("=", 1)[1]
                            domains = [d.strip() for d in val.split(",") if d.strip()]
                            break
            self.wfile.write(json.dumps({"domains": domains}).encode())

        else:
            self.send_response(404)
            self.end_headers()

    def _update_whitelist(self, domains_input, action):
        if not domains_input: return
        env_file = "config/config.env"
        if not os.path.exists(env_file): return
        
        with open(env_file, "r") as f:
            lines = f.readlines()
        
        current_domains = []
        w_idx = -1
        for i, line in enumerate(lines):
            if line.startswith("WHITELIST_DOMAINS="):
                w_idx = i
                val = line.strip().split("=", 1)[1]
                current_domains = [d.strip() for d in val.split(",") if d.strip()]
                break
        
        # Accept string or list
        if isinstance(domains_input, str):
            domains_input = [d.strip() for d in domains_input.split(",") if d.strip()]
            
        modified = False
        for domain in domains_input:
            domain = domain.lower()
            if action == 'add' and domain not in current_domains:
                current_domains.append(domain)
                modified = True
            elif action == 'remove' and domain in current_domains:
                current_domains.remove(domain)
                modified = True
            
        if w_idx != -1 and modified:
            lines[w_idx] = f"WHITELIST_DOMAINS={','.join(current_domains)}\n"
            with open(env_file, "w") as f:
                f.writelines(lines)
                
        # Trigger the UI config dump
        try:
            import run
            run._dump_ui_config(run._load_env())
        except Exception:
            pass

if __name__ == "__main__":
    import threading
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), ConfigHandler) as httpd:
        print(f"DomainShield Dashboard running on http://localhost:{PORT}")
        webbrowser.open(f"http://localhost:{PORT}/index.html")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Dashboard...")
