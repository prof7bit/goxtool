"""pubnub light API (only subscribe, not publish)"""

#  Copyright (c) 2013 Bernd Kreuss <prof7bit@gmail.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

import base64
from Crypto.Cipher import AES
import hashlib
import json
import socket
import uuid


class SocketError(Exception):
    """thrown internally when socket read fails"""
    pass


class _SSLSocketWrapper():
    """wrapper aroud socket to enable SSL"""
    def __init__(self, sock):
        self.sock = sock
        self.ssl = socket.ssl(sock)

    def recv(self, bufsize):
        """recv through ssl"""
        return self.ssl.read(bufsize)

    def send(self, payload):
        """send through ssl"""
        return self.ssl.write(payload)

    def shutdown(self, mode):
        """shutdown the socket"""
        self.sock.shutdown(mode)

    def close(self):
        """close the socket and clean up"""
        self.sock.close()
        self.ssl = None
        self.sock = None


class PubNub(): #pylint: disable=R0902
    """implements a simple pubnub client that tries to stay connected
    and is interruptible immediately (using socket instead of urllib2)"""
    #pylint: disable=R0913
    def __init__(self, sub, chan, auth="", cipher="", ssl=False):
        self.sock = None
        self.uuid = uuid.uuid4()
        self.timestamp = 0
        self.sub = sub
        self.chan = chan
        self.auth = auth
        self.cipher = cipher
        self.ssl = ssl
        self.connected = False
        self.killed = False

    #pylint: disable=R0913
    def reinit(self, sub, chan, auth="", cipher="", ssl=False):
        """set new subscription parameters, and and reset kill flag"""
        self.sub = sub
        self.chan = chan
        self.auth = auth
        self.cipher = cipher
        self.ssl = ssl
        self.killed = False

    def kill(self):
        """set kill flag and close socket.
        read() method will then immediately raise exception in its thread
        and also any subsequent attempt to read(). Can be reset by reinit()"""
        self.killed = True
        self.connected = False
        self.sock.shutdown(2)
        self.sock.close()

    def _send_request(self):
        """send http request, read response header and return Content-Length"""
        headers = [
            "GET /subscribe/%s/%s/0/%i?uuid=%s&auth=%s HTTP/1.1" \
                % (self.sub, self.chan, self.timestamp, self.uuid, self.auth),
            "Accept-Encoding: identity",
            "Host: pubsub.pubnub.com",
            "Connection: keep-alive"]
        str_headers = "%s\r\n\r\n" % "\r\n".join(headers)
        self.sock.send(str_headers)
        return self._read_response_header()

    def _read_response_header(self):
        """read the http response header and return value of Content-Length"""
        hdr = ""
        while True:
            char = self.sock.recv(1)
            if char == "":
                self.sock.close()
                raise SocketError
            hdr += char
            if hdr[-4:] == "\r\n\r\n":
                lines = hdr.split("\r\n")
                for line in lines:
                    if "Content-Length" in line:
                        return int(line[15:])
                self.sock.close()
                raise SocketError

    def _connect(self):
        """connect, send request, read header and return Content-Length"""
        self.sock = socket.socket()
        if self.ssl:
            self.sock.connect(("pubsub.pubnub.com", 443))
            self.sock = _SSLSocketWrapper(self.sock)
        else:
            self.sock.connect(("pubsub.pubnub.com", 80))
        return self._send_request()

    def _read_num_bytes(self, size):
        """read exactly size bytes from socket, raise SocketError if error"""
        buf = ""
        while not len(buf) == size:
            chunk = self.sock.recv(size)
            if chunk == "":
                self.sock.close()
                raise SocketError
            buf += chunk
        return buf

    def read(self):
        """read blocking and return list of messages. if disconnected
        then automatically (re)connect. Throws exception if killed or
        socket error occurs."""
        if self.killed:
            raise Exception
        if not self.connected:
            try:
                size = self._connect()
                self.connected = True
            except SocketError:
                raise Exception
        else:
            try:
                size = self._send_request()
            except SocketError:
                self.connected = False
                raise Exception

        try:
            res = self._read_num_bytes(size)
            data = json.loads(res)
            self.timestamp = int(data[1])
            msg = data[0]
            if self.cipher:
                for i in range(len(msg)):
                    msg[i] = self._decrypt(msg[i])
            return msg
        except SocketError:
            self.connected = False
            raise Exception

    def _decrypt(self, msg):
        """decrypt a single pubnub message"""
        # they must be real crypto experts at pubnub.com
        # two lines of code and two capital mistakes :-(
        # pylint: disable=E1101
        key = hashlib.sha256(self.cipher).hexdigest()[0:32]
        aes = AES.new(key, AES.MODE_CBC, "0123456789012345")
        decrypted = aes.decrypt(base64.decodestring(msg))
        return decrypted[0:-ord(decrypted[-1])]
