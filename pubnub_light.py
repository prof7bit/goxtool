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
import ssl
import uuid


class SocketClosedException(Exception):
    """raised when socket read fails. This normally happens when the
    hup() method is invoked, your thread that loops over read() should
    catch this exception and then decide whether to retry or terminate"""
    pass


class PubNub(): #pylint: disable=R0902
    """implements a simple pubnub client that tries to stay connected
    and is interruptible immediately (using socket instead of urllib2)."""
    def __init__(self):
        self.sock = None
        self.uuid = uuid.uuid4()
        self.timestamp = 0
        self.connected = False
        self.sub = ""
        self.chan = ""
        self.auth = ""
        self.cipher = ""
        self.use_ssl = False

    #pylint: disable=R0913
    def subscribe(self, sub, chan, auth="", cipher="", use_ssl=False):
        """set the subscription parameters. This is needed after __init__(),
        chan is a string containing a channel name or a comma separated list of
        multiple cannels, it will replace all previously set subscriptions."""
        self.sub = sub
        self.chan = chan
        self.auth = auth
        self.cipher = cipher
        self.use_ssl = use_ssl

        # force disconnect of currently active longpoll.
        self.hup()

    def read(self):
        """read (blocking) and return list of messages. Right after subscribe()
        you should enter a loop over this blocking read() call to read messages
        from the subscribed channels. It will raise an exception if interrupted
        (for example by hup() or by subscribe() or if something goes wrong),
        so you should catch exceptions and then decide whether to re-enter your
        loop because you merely called subscribe() again or whether you want
        to terminate because your application ends.
        """
        if not self.connected:
            self._connect()
        content_length = self._send_request()
        res = self._read_num_bytes(content_length)
        data = json.loads(res)
        self.timestamp = int(data[1])
        msg = data[0]
        if self.cipher:
            for i in range(len(msg)):
                msg[i] = self._decrypt(msg[i])
        return msg

    def hup(self):
        """close socket and force the blocking read() to exit with an Exception.
        Usually the thread in your app that does the read() will then have
        the opportunity to decide whether to re-enter the read() because you
        only set new subscription parameters or to terminate because you want
        to shut down the client completely."""
        if self.sock:
            self.connected = False
            self.sock.shutdown(2)
            self.sock.close()

    def _connect(self):
        """connect and set self.connected flag, raise exception if error.
        This method is used internally, you don't explicitly call it yourself,
        the read() method will invoke it automatically if necessary."""
        self.sock = socket.socket()
        host = "pubsub.pubnub.com"
        port = 80
        if self.use_ssl:
            self.sock = ssl.wrap_socket(self.sock)
            port = 443
        self.sock.connect((host, port))
        self.connected = True

    def _send_request(self):
        """send http request, read response header and return Content-Length."""
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
        """read the http response header and return value of Content-Length."""
        hdr = ""
        while True:
            char = self.sock.recv(1)
            if char == "":
                self.connected = False
                self.sock.close()
                raise SocketClosedException
            hdr += char
            if hdr[-4:] == "\r\n\r\n":
                lines = hdr.split("\r\n")
                for line in lines:
                    if "Content-Length" in line:
                        return int(line[15:])
                self.connected = False
                self.sock.close()
                raise SocketClosedException

    def _read_num_bytes(self, num):
        """read (blocking) exactly num bytes from socket,
        raise SocketClosedException if the socket is closed."""
        buf = ""
        while len(buf) < num:
            chunk = self.sock.recv(num - len(buf))
            if chunk == "":
                self.connected = False
                self.sock.close()
                raise SocketClosedException
            buf += chunk
        return buf

    def _decrypt(self, msg):
        """decrypt a single pubnub message"""
        # they must be real crypto experts at pubnub.com
        # two lines of code and two capital mistakes :-(
        # pylint: disable=E1101
        key = hashlib.sha256(self.cipher).hexdigest()[0:32]
        aes = AES.new(key, AES.MODE_CBC, "0123456789012345")
        decrypted = aes.decrypt(base64.decodestring(msg))
        return decrypted[0:-ord(decrypted[-1])]
