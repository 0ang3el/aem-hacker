from http.server import BaseHTTPRequestHandler, HTTPServer

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


def run():
    print('starting fake AEM server...')

    server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
    print('running server...')
    httpd.serve_forever()


if __name__ == '__main__':
    run()