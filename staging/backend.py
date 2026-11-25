"""Synthetic staging app. Never use for real authentication or customer data."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

AUDIT = []

OWNER = '01234567-89ab-4cde-8123-0123456789ab'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        code = 200
        if path.startswith('/api/object/'):
            if self.headers.get('Authorization') != 'Bearer synthetic-user-a':
                code = 401
            elif path.rsplit('/', 1)[-1] != OWNER:
                code = 403
        elif path not in ('/public', '/new', '/internal', '/q'):
            code = 404
        if path == '/__audit':
            code = 200
            body = json.dumps(AUDIT).encode()
        else:
            AUDIT.append({'path': self.path, 'method': self.command, 'status': code})
            body = f'synthetic-backend:{code}'.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self.do_GET()

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
