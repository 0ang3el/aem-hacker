#!/usr/bin/env python3
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
    print('starting fake AEM server on port 8080...')
    try:
        server_address = ('0.0.0.0', 8080)
        httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
        print('running server...')
        httpd.serve_forever()
    except Exception as ERR:
        print (f" ERROR : Failed to start HTTP server, \n {ERR}")
        exit()


if __name__ == '__main__':
    run()