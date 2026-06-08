import http.server, threading, os, time
os.chdir(r"C:\Users\ZhuanZ\Desktop\LynxSec")
class H(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()
    def log_message(self, f, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 9988), H)
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()
print("SERVER_READY")
time.sleep(3600)
