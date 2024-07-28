from http.server import BaseHTTPRequestHandler, HTTPServer
import argparse

class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):

    def do_print(self, method):
        print('\n\n[+] {0} request: {1}'.format(method, self.path))

        print('===[HEADERS]===')
        for name, value in sorted(self.headers.items()):
            print('\t{0}={1}'.format(name, value))

        try:
            print('===[BODY]===\n' + self.rfile.read(int(self.headers.get('content-length'))).decode('utf-8'))
        except:
            pass

    def do_POST(self):
        self.do_print('POST')

        self.send_response(200)
        self.end_headers()
        return

    def do_GET(self):
        self.do_print('GET')

        self.send_response(200)

        data = open('response.bin', 'rb').read()

        self.send_header('Content-type', 'application/octet-stream')
        self.send_header('Content-length', len(data))
        self.end_headers()

        self.wfile.write(data)
        return


def run(port=80):
    print('starting fake AEM server...')

    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
    print('running server on port {}'.format(port))
    httpd.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Fake AEM server')
    parser.add_argument('--port', type=int, default=80, help='port to listen on')
    args = parser.parse_args()
    run(args.port)
