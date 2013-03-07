"""Mt.Gox API"""

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

# pylint: disable=C0302,C0301,R0902,R0903,R0912,R0913

import base64
from ConfigParser import SafeConfigParser
from Crypto.Cipher import AES
import getpass
import hashlib
import hmac
import inspect
import json
import logging
import time
import traceback
import threading
import urllib
import urllib2
import weakref
import websocket

def int2str(value_int, currency):
    """return currency integer formatted as a string"""
    if currency == "BTC":
        return ("%16.8f" % (value_int / 100000000.0))
    if currency == "JPY":
        return ("%12.3f" % (value_int / 1000.0))
    else:
        return ("%12.5f" % (value_int / 100000.0))

def start_thread(thread_func):
    """start a new thread to execute the supplied function"""
    thread = threading.Thread(None, thread_func)
    thread.daemon = True
    thread.start()
    return thread

# pylint: disable=R0904
class GoxConfig(SafeConfigParser):
    """return a config parser object with default values. If you need to run
    more Gox() objects at the same time you will also need to give each of them
    them a separate GoxConfig() object. For this reason it takes a filename
    in its constructor for the ini file, you can have separate configurations
    for separate Gox() instances"""

    _DEFAULTS = [["gox", "currency", "USD"]
                ,["gox", "use_ssl", "True"]
                ,["gox", "use_plain_old_websocket", "True"]
                ,["gox", "load_fulldepth", "True"]
                ,["gox", "load_history", "True"]
                ,["gox", "secret_key", ""]
                ,["gox", "secret_secret", ""]
                ,["goxtool", "set_xterm_title", "True"]
                ]

    def __init__(self, filename):
        self.filename = filename
        SafeConfigParser.__init__(self)
        self.load()
        for (sect, opt, default) in self._DEFAULTS:
            self._default(sect, opt, default)

    def save(self):
        """save the config to the .ini file"""
        with open(self.filename, 'wb') as configfile:
            self.write(configfile)

    def load(self):
        """(re)load the onfig from the .ini file"""
        self.read(self.filename)

    def get_safe(self, sect, opt):
        """get value without throwing exception."""
        try:
            return self.get(sect, opt)

        # pylint: disable=W0702
        except:
            for (dsect, dopt, default) in self._DEFAULTS:
                if dsect == sect and dopt == opt:
                    self._default(sect, opt, default)
                    return default
            return ""

    def get_bool(self, sect, opt):
        """get boolean value from config"""
        return self.get_safe(sect, opt) == "True"

    def get_string(self, sect, opt):
        """get string value from config"""
        return self.get_safe(sect, opt)

    def _default(self, section, option, default):
        """create a default option if it does not yet exist"""
        if not self.has_section(section):
            self.add_section(section)
        if not self.has_option(section, option):
            self.set(section, option, default)
            self.save()

class Signal():
    """callback functions (so called slots) can be connected to a signal and
    will be called when the signal is called (Signal implements __call__).
    The slots receive two arguments: the sender of the signal and a custom
    data object. Two different threads won't be allowed to send signals at the
    same time application-wide, concurrent threads will have to wait until
    the lock is releaesed again. The lock allows recursive reentry of the same
    thread to avoid deadlocks when a slot wants to send a signal itself."""

    _lock = threading.RLock()
    signal_error = None

    def __init__(self):
        self._functions = weakref.WeakSet()
        self._methods = weakref.WeakKeyDictionary()

        # the Signal class itself has a static member signal_error where it
        # will send tracebacks of exceptions that might happen. Here we
        # initialize it if it does not exist already
        if not Signal.signal_error:
            Signal.signal_error = 1
            Signal.signal_error = Signal()

    def connect(self, slot):
        """connect a slot to this signal. The parameter slot can be a funtion
        that takes exactly 2 arguments or a method that takes self plus 2 more
        arguments, or it can even be even another signal. the first argument
        is a reference to the sender of the signal and the second argument is
        the payload. The payload can be anything, it totally depends on the
        sender and type of the signal."""
        if inspect.ismethod(slot):
            if slot.__self__ not in self._methods:
                self._methods[slot.__self__] = set()
            self._methods[slot.__self__].add(slot.__func__)
        else:
            self._functions.add(slot)

    def __call__(self, sender, data, error_signal_on_error=True):
        """dispatch signal to all connected slots. This is a synchronuos
        operation, It will not return before all slots have been called.
        Also only exactly one thread is allowed to emit signals at any time,
        all other threads that try to emit *any* signal anywhere in the
        application at the same time will be blocked until the lock is released
        again. The lock will allow recursive reentry of the seme thread, this
        means a slot can itself emit other signals before it returns (or
        signals can be directly connected to other signals) without problems.
        If a slot raises an exception a traceback will be sent to the static
        Signal.signal_error() or to logging.critical()"""
        with self._lock:
            sent = False
            errors = []
            for func in self._functions:
                try:
                    func(sender, data)
                    sent = True

                # pylint: disable=W0702
                except:
                    errors.append(traceback.format_exc())

            for obj, funcs in self._methods.items():
                for func in funcs:
                    try:
                        func(obj, sender, data)
                        sent = True

                    # pylint: disable=W0702
                    except:
                        errors.append(traceback.format_exc())

            for error in errors:
                if error_signal_on_error:
                    Signal.signal_error(self, (error), False)
                else:
                    logging.critical(error)

            return sent


class BaseObject():
    """This base class only exists because of the debug() method that is used
    in many of the goxtool objects to send debug output to the signal_debug."""

    def __init__(self):
        self.signal_debug = Signal()

    def debug(self, *args):
        """send a string composed of all *args to all slots who
        are connected to signal_debug or send it to the logger if
        nobody is connected"""
        msg = " ".join([str(x) for x in args])
        if not self.signal_debug(self, (msg)):
            logging.debug(msg)


class Secret:
    """Manage the MtGox API secret. This class has methods to decrypt the
    entries in the ini file and it also provides a method to create these
    entries. The methods encrypt() and decrypt() will block and ask
    questions on the command line, they are called outside the curses
    environment (yes, its a quick and dirty hack but it works for now)."""

    S_OK            = 0
    S_FAIL          = 1
    S_NO_SECRET     = 2
    S_FAIL_FATAL    = 3

    def __init__(self, config):
        """initialize the instance"""
        self.config = config
        self.key = ""
        self.secret = ""

    def decrypt(self, password):
        """decrypt "secret_secret" from the ini file with the given password.
        This will return false if decryption did not seem to be successful.
        After this menthod succeeded the application can access the secret"""

        key = self.config.get_string("gox", "secret_key")
        sec = self.config.get_string("gox", "secret_secret")
        if sec == "" or key == "":
            return self.S_NO_SECRET

        # pylint: disable=E1101
        hashed_pass = hashlib.sha512(password).digest()
        crypt_key = hashed_pass[:32]
        crypt_ini = hashed_pass[-16:]
        aes = AES.new(crypt_key, AES.MODE_OFB, crypt_ini)
        try:
            encrypted_secret = base64.b64decode(sec.strip())
            self.secret = aes.decrypt(encrypted_secret).strip()
            self.key = key.strip()
        except ValueError:
            return self.S_FAIL

        # now test if we now have something plausible
        try:
            print("testing secret...")
            # is it plain ascii? (if not this will raise exception)
            dummy = self.secret.encode("ascii")
            # can it be decoded? correct size afterwards?
            if len(base64.b64decode(self.secret)) != 64:
                raise Exception("decrypted secret has wrong size")

            print("testing key...")
            # key must be only hex digits and have the right size
            if len(self.key.replace("-", "").decode("hex")) != 16:
                raise Exception("key has wrong size")

            print "ok :-)"
            return self.S_OK

        # pylint: disable=W0703
        except Exception as exc:
            # this key and secret do not work :-(
            self.secret = ""
            self.key = ""
            print "### Error occurred while testing the decrypted secret:"
            print "    '%s'" % exc
            print "    This does not seem to be a valid MtGox API secret"
            return self.S_FAIL

    def prompt_decrypt(self):
        """ask the user for password on the command line
        and then try to decrypt the secret."""
        if self.know_secret():
            return self.S_OK

        key = self.config.get_string("gox", "secret_key")
        sec = self.config.get_string("gox", "secret_secret")
        if sec == "" or key == "":
            return self.S_NO_SECRET

        password = getpass.getpass("enter passphrase for secret: ")
        result = self.decrypt(password)
        if result != self.S_OK:
            print
            print "secret could not be decrypted"
            answer = raw_input("press any key to continue anyways " \
                + "(trading disabled) or 'q' to quit: ")
            if answer == "q":
                result = self.S_FAIL_FATAL
            else:
                result = self.S_NO_SECRET
        return result

    # pylint: disable=R0201
    def prompt_encrypt(self):
        """ask for key, secret and password on the command line,
        then encrypt the secret and store it in the ini file."""
        print "Please copy/paste key and secret from MtGox and"
        print "then provide a password to encrypt them."
        print
        key =    raw_input("             key: ").strip()
        secret = raw_input("          secret: ").strip()
        while True:
            password1 = getpass.getpass("        password: ").strip()
            if password1 == "":
                print "aborting"
                return
            password2 = getpass.getpass("password (again): ").strip()
            if password1 != password2:
                print "you had a typo in the password. try again..."
            else:
                break

        # pylint: disable=E1101
        hashed_pass = hashlib.sha512(password1).digest()
        crypt_key = hashed_pass[:32]
        crypt_ini = hashed_pass[-16:]
        aes = AES.new(crypt_key, AES.MODE_OFB, crypt_ini)

        # since the secret is a base64 string we can just just pad it with
        # spaces which can easily be stripped again after decryping
        secret += " " * (len(secret) % 16)
        secret = base64.b64encode(aes.encrypt(secret))

        self.config.set("gox", "secret_key", key)
        self.config.set("gox", "secret_secret", secret)
        self.config.save()

        print "encrypted secret has been saved in %s" % self.config.filename

    def know_secret(self):
        """do we know the secret key? The application must be able to work
        without secret and then just don't do any account related stuff"""
        return (self.secret != "") and (self.key != "")


class OHLCV():
    """represents a chart candle. tim is POSIX timestamp of open time,
    prices and volume are integers like in the other parts of the gox API"""

    def __init__(self, tim, opn, hig, low, cls, vol):
        self.tim = tim
        self.opn = opn
        self.hig = hig
        self.low = low
        self.cls = cls
        self.vol = vol

    def update(self, price, volume):
        """update high, low and close values and add to volume"""
        if price > self.hig:
            self.hig = price
        if price < self.low:
            self.low = price
        self.cls = price
        self.vol += volume


class History(BaseObject):
    """represents the trading history"""

    def __init__(self, gox, timeframe):
        BaseObject.__init__(self)

        self.signal_changed = Signal()

        self.gox = gox
        self.candles = []
        self.timeframe = timeframe

        gox.signal_trade.connect(self.slot_trade)
        gox.signal_fullhistory.connect(self.slot_fullhistory)

    def add_candle(self, candle):
        """add a new candle to the history"""
        self._add_candle(candle)
        self.signal_changed(self, (self.length()))

    def slot_trade(self, dummy_sender, (date, price, volume, dummy_typ, own)):
        """slot for gox.signal_trade"""
        if not own:
            time_round = int(date / self.timeframe) * self.timeframe
            candle = self.last_candle()
            if candle:
                if candle.tim == time_round:
                    candle.update(price, volume)
                    self.signal_changed(self, (1))
                else:
                    self.debug("### opening new candle")
                    self.add_candle(OHLCV(
                        time_round, price, price, price, price, volume))
            else:
                self.add_candle(OHLCV(
                    time_round, price, price, price, price, volume))

    def _add_candle(self, candle):
        """add a new candle to the history but don't fire signal_changed"""
        self.candles.insert(0, candle)

    def slot_fullhistory(self, dummy_sender, (history)):
        """process the result of the fullhistory request"""
        self.candles = []
        new_candle = OHLCV(0, 0, 0, 0, 0, 0)
        for trade in history:
            date = int(trade["date"])
            price = int(trade["price_int"])
            volume = int(trade["amount_int"])
            time_round = int(date / self.timeframe) * self.timeframe
            if time_round > new_candle.tim:
                if new_candle.tim > 0:
                    self._add_candle(new_candle)
                new_candle = OHLCV(
                    time_round, price, price, price, price, volume)
            new_candle.update(price, volume)

        # insert current (incomplete) candle
        self._add_candle(new_candle)
        self.debug("### got %d candles" % self.length())
        self.signal_changed(self, (self.length()))

    def last_candle(self):
        """return the last (current) candle or None if empty"""
        if self.length() > 0:
            return self.candles[0]
        else:
            return None

    def length(self):
        """return the number of candles in the history"""
        return len(self.candles)


class BaseClient(BaseObject):
    """abstract base class for SocketIOClient and WebsocketClient"""

    SOCKETIO_HOST = "socketio.mtgox.com"
    WEBSOCKET_HOST = "websocket.mtgox.com"
    HTTP_HOST = "mtgox.com"

    def __init__(self, currency, secret, config):
        BaseObject.__init__(self)

        self.signal_recv        = Signal()
        self.signal_fulldepth   = Signal()
        self.signal_fullhistory = Signal()

        self.currency = currency
        self.secret = secret
        self.config = config
        self.socket = None
        self._recv_thread = None
        self._terminating = False

    def start(self):
        """start the client"""
        self._recv_thread = start_thread(self._recv_thread_func)

    def stop(self):
        """stop the client"""
        self._terminating = True
        self.socket.close()
        self._recv_thread.join()

    def send(self, json_str):
        """there exist 2 subtly different ways to send a string over a
        websocket. Each client class will override this send method"""
        raise NotImplementedError()

    def request_order_lag(self):
        """request the current order-lag"""
        self.send_signed_call("order/lag", {}, "order_lag")

    def request_fulldepth(self):
        """start the fulldepth thread"""

        def fulldepth_thread():
            """request the full market depth, initialize the order book
            and then terminate. This is called in a separate thread after
            the streaming API has been connected."""
            self.debug("requesting initial full depth")
            fulldepth = urllib2.urlopen("https://" +  self.HTTP_HOST \
                + "/api/1/BTC" + self.currency + "/fulldepth")
            self.signal_fulldepth(self, (json.load(fulldepth)))
            fulldepth.close()

        start_thread(fulldepth_thread)

    def request_history(self):
        """request trading history"""

        def history_thread():
            """request trading history"""

            # 1308503626, 218868 <-- last small transacion ID
            # 1309108565, 1309108565842636 <-- first big transaction ID

            self.debug("requesting history")
            res = urllib2.urlopen("https://" +  self.HTTP_HOST \
                + "/api/1/BTC" + self.currency + "/trades")
            history = json.load(res)
            res.close()
            if history["result"] == "success":
                self.signal_fullhistory(self, history["return"])

        start_thread(history_thread)

    def _recv_thread_func(self):
        """this will be executed as the main receiving thread, each type of
        client (websocket or socketio) will implement its own"""
        raise NotImplementedError()

    def channel_subscribe(self):
        """subscribe to the needed channels and alo initiate the
        download of the initial full market depth"""

        self.send(json.dumps({"op":"mtgox.subscribe", "type":"depth"}))
        self.send(json.dumps({"op":"mtgox.subscribe", "type":"ticker"}))
        self.send(json.dumps({"op":"mtgox.subscribe", "type":"trades"}))

        self.send_signed_call("private/info", {}, "info")
        self.send_signed_call("private/orders", {}, "orders")
        self.send_signed_call("private/idkey", {}, "idkey")

        self.request_order_lag()

        if self.config.get_bool("gox", "load_fulldepth"):
            self.request_fulldepth()

        if self.config.get_bool("gox", "load_history"):
            self.request_history()

    def http_signed_call(self, api_endpoint, params):
        """send a signed request to the HTTP API"""
        if (not self.secret) or (not self.secret.know_secret()):
            self.debug("### don't know secret, cannot call %s" % api_endpoint)
            return

        key = self.secret.key
        sec = self.secret.secret

        params["nonce"] = int(time.time() * 1000000)
        post = urllib.urlencode(params)
        # pylint: disable=E1101
        sign = hmac.new(base64.b64decode(sec), post, hashlib.sha512).digest()

        headers = {
            'User-Agent': 'goxtool.py',
            'Rest-Key': key,
            'Rest-Sign': base64.b64encode(sign)
        }

        req = urllib2.Request("https://" + self.HTTP_HOST + "/api/1/" \
            + api_endpoint, post, headers)
        res = urllib2.urlopen(req, post)
        return json.load(res)

    def send_signed_call(self, api_endpoint, params, reqid):
        """send a signed (authenticated) API call over the socket.io.
        This method will only succeed if the secret key is available,
        otherwise it will just log a warning and do nothing."""
        if (not self.secret) or (not self.secret.know_secret()):
            self.debug("### don't know secret, cannot call %s" % api_endpoint)
            return

        key = self.secret.key
        sec = self.secret.secret

        nonce = int(time.time() * 1000000)

        call = json.dumps({
            "id"       : reqid,
            "call"     : api_endpoint,
            "nonce"    : nonce,
            "params"   : params,
            "currency" : self.currency,
            "item"     : "BTC"
        })

        # pylint: disable=E1101
        sign = hmac.new(base64.b64decode(sec), call, hashlib.sha512).digest()
        signedcall = key.replace("-", "").decode("hex") + sign + call

        self.debug("### calling %s" % api_endpoint)
        self.send(json.dumps({
            "op"      : "call",
            "call"    : base64.b64encode(signedcall),
            "id"      : reqid,
            "context" : "mtgox.com"
        }))


class WebsocketClient(BaseClient):
    """this implements a connection to MtGox through the older (but faster)
    websocket protocol. Unfortuntely its just as unreliable as the socket.io."""

    def __init__(self, currency, secret, config):
        BaseClient.__init__(self, currency, secret, config)

    def _recv_thread_func(self):
        """connect to the webocket and tart receiving inan infinite loop.
        Try to reconnect whenever connection is lost. Each received json
        string will be dispatched with a signal_recv signal"""
        use_ssl = self.config.get_bool("gox", "use_ssl")
        wsp = {True: "wss://", False: "ws://"}[use_ssl]
        while not self._terminating:  #loop 0 (connect, reconnect)
            try:
                ws_url = wsp + self.WEBSOCKET_HOST \
                    + "/mtgox?Currency=" + self.currency

                self.debug("*** Hint: connection problems? try: use_plain_old_websocket=False")
                self.debug("trying plain old Websocket: %s ... " % ws_url)

                self.socket = websocket.create_connection(ws_url)
                self.debug("connected, subscribing needed channels")
                self.channel_subscribe()

                self.debug("waiting for data...")
                while not self._terminating: #loop1 (read messages)
                    str_json = self.socket.recv()
                    if str_json[0] == "{":
                        self.signal_recv(self, (str_json))


            # pylint: disable=W0703
            except Exception as exc:
                if not self._terminating:
                    self.debug(exc, "reconnecting in 5 seconds...")
                    if self.socket:
                        self.socket.close()
                    time.sleep(5)


    def send(self, json_str):
        """send the json encoded string over the websocket"""
        self.socket.send(json_str)


class SocketIOClient(BaseClient):
    """this implements a connection to MtGox using the new socketIO protocol.
    This should replace the older plain websocket API"""

    def __init__(self, currency, secret, config):
        BaseClient.__init__(self, currency, secret, config)

    def _recv_thread_func(self):
        """this is the main thread that is running all the time. It will
        connect and then read (blocking) on the socket in an infinite
        loop. SocketIO messages ('2::', etc.) are handled here immediately
        and all received json strings are dispathed with signal_recv."""
        use_ssl = self.config.get_bool("gox", "use_ssl")
        wsp = {True: "wss://", False: "ws://"}[use_ssl]
        htp = {True: "https://", False: "http://"}[use_ssl]
        while not self._terminating: #loop 0 (connect, reconnect)
            try:
                self.debug("*** Hint: connection problems? try: use_plain_old_websocket=True")
                self.debug("trying Socket.IO: %s ..." % self.SOCKETIO_HOST)

                url = urllib2.urlopen(
                    htp + self.SOCKETIO_HOST + "/socket.io/1?Currency=" +
                    self.currency, timeout=20)
                params = url.read()
                url.close()

                ws_id = params.split(":")[0]
                ws_url = wsp + self.SOCKETIO_HOST + "/socket.io/1/websocket/" \
                     + ws_id + "?Currency=" + self.currency

                self.debug("trying Websocket: %s ..." % ws_url)
                self.socket = websocket.create_connection(ws_url)

                self.debug("connected")
                self.socket.send("1::/mtgox")
                self.socket.recv() # '1::'
                self.socket.recv() # '1::/mtgox'

                self.debug("subscribing to channels")
                self.channel_subscribe()

                self.debug("waiting for data...")
                while not self._terminating: #loop1 (read messages)
                    msg = self.socket.recv()
                    if msg == "2::":
                        self.debug("### ping -> pong")
                        self.socket.send("2::")
                        continue
                    prefix = msg[:10]
                    if prefix == "4::/mtgox:":
                        str_json = msg[10:]
                        if str_json[0] == "{":
                            self.signal_recv(self, (str_json))

            # pylint: disable=W0703
            except Exception as exc:
                if not self._terminating:
                    self.debug(exc, "reconnecting in 5 seconds...")
                    if self.socket:
                        self.socket.close()
                    time.sleep(5)

    def send(self, json_str):
        """send a string to the websocket. This method will prepend it
        with the 1::/mtgox: that is needed for the socket.io protocol
        (as opposed to plain websockts) and the underlying websocket
        will then do the needed framing on top of that."""
        self.socket.send("4::/mtgox:" + json_str)


# pylint: disable=R0902
class Gox(BaseObject):
    """represents the API of the MtGox exchange. An Instance of this
    class will connect to the streaming socket.io API, receive live
    events, it will emit signals you can hook into for all events,
    it has methods to buy and sell"""

    def __init__(self, secret, config):
        """initialize the gox API but do not yet connect to it."""
        BaseObject.__init__(self)

        self.signal_depth           = Signal()
        self.signal_trade           = Signal()
        self.signal_ticker          = Signal()
        self.signal_fulldepth       = Signal()
        self.signal_fullhistory     = Signal()
        self.signal_wallet          = Signal()
        self.signal_userorder       = Signal()
        self.signal_orderlag        = Signal()

        self._idkey      = ""
        self.wallet = {}
        self.order_lag = 0
        self.msg_count = 0

        self.config = config
        self.currency = config.get("gox", "currency", "USD")

        Signal.signal_error.connect(self.signal_debug)

        self.history = History(self, 60 * 15)
        self.history.signal_debug.connect(self.signal_debug)

        self.orderbook = OrderBook(self)
        self.orderbook.signal_debug.connect(self.signal_debug)

        if self.config.get_bool("gox", "use_plain_old_websocket"):
            self.client = WebsocketClient(self.currency, secret, config)
        else:
            self.client = SocketIOClient(self.currency, secret, config)
        self.client.signal_debug.connect(self.signal_debug)
        self.client.signal_recv.connect(self.slot_recv)
        self.client.signal_fulldepth.connect(self.signal_fulldepth)
        self.client.signal_fullhistory.connect(self.signal_fullhistory)

    def start(self):
        """connect to MtGox and start receiving events."""
        self.debug("starting gox streaming API, currency=" + self.currency)
        self.client.start()

    def stop(self):
        """shutdown the client"""
        self.debug("shutdown...")
        self.client.stop()

    def order(self, typ, price, volume):
        """place pending order. If price=0 then it will be filled at market"""
        endpoint = "BTC" + self.currency + "/private/order/add"
        params = {
            "type": typ,
            "amount_int": str(volume),
            "price_int": str(price)
        }
        res = self.client.http_signed_call(endpoint, params)
        if "result" in res and res["result"] == "success":
            self.signal_userorder(self,
                (price, volume, typ, res["return"], "pending"))
            res = res["return"]
        else:
            self.debug("### WTF??? order could not be placed!")
            res = ""

        self.client.request_order_lag()
        return res

    def buy(self, price, volume):
        """new buy order, if price=0 then buy at market"""
        self.order("bid", price, volume)

    def sell(self, price, volume):
        """new sell order, if price=0 then sell at market"""
        self.order("ask", price, volume)

    def cancel(self, oid):
        """cancel order"""
        endpoint = "BTC" + self.currency + "/private/order/cancel"
        params = {
            "oid": oid
        }
        res = self.client.http_signed_call(endpoint, params)
        if "result" in res and res["result"] == "success":
            self.signal_userorder(self,
                (0, 0, "", res["return"], "removed"))
            res = True
        else:
            self.debug("### WTF??? order could not be canceled!")
            res = False

        self.client.request_order_lag()
        return res

    def cancel_by_price(self, price):
        """cancel all orders at price"""
        for i in reversed(range(len(self.orderbook.owns))):
            order = self.orderbook.owns[i]
            if order.price == price:
                if order.oid != "":
                    self.cancel(order.oid)
                else:
                    self.debug("### cannot cancel placeholder order, no oid.")

    def cancel_by_type(self, typ=None):
        """cancel all orders of type (or all orders if type=None)"""
        for i in reversed(range(len(self.orderbook.owns))):
            order = self.orderbook.owns[i]
            if typ == None or typ == order.typ:
                if order.oid != "":
                    self.cancel(order.oid)

    def slot_recv(self, dummy_sender, (str_json)):
        """Slot for signal_recv, handle new incoming JSON message. Decode the
        JSON string into a Python object and dispatch it to the method that
        can handle it."""
        try:
            msg = json.loads(str_json)
            if "ticker" in msg:
                self._on_tick(msg)
            if "depth" in msg:
                self._on_depth(msg)
            if "trade" in msg:
                self._on_trade(msg)
            if "result" in msg:
                self._on_call_result(msg)
            if "user_order" in msg:
                self._on_user_order(msg)
            if "wallet" in msg:
                self._on_wallet(msg)

            if "op" in msg and msg["op"] == "remark":
                # we should log this, helps with debugging
                self.debug(str_json)

                # Workaround: Maybe a bug in their server software,
                # I don't know whats missing. Its all poorly documented :-(
                # Sometimes these API calls that were sent right after
                # connecting fail the first time for no reason, if this
                # happens just send them again. This happens only somtimes
                # and sending them a second time will always make it work.
                if "success" in msg and "id" in msg and not msg["success"]:
                    if msg["message"] == "Invalid call":
                        if msg["id"] == "idkey":
                            self.debug("### resending private/idkey")
                            self.client.send_signed_call(
                                "private/idkey", {}, "idkey")
                        if msg["id"] == "info":
                            self.debug("### resending private/info")
                            self.client.send_signed_call(
                                "private/info", {}, "info")
                        if msg["id"] == "orders":
                            self.debug("### resending private/orders")
                            self.client.send_signed_call(
                                "private/orders", {}, "orders")

                        # resend a failed "order/add"
                        if "order_add:" in msg["id"]:
                            parts = msg["id"].split(":")
                            typ = parts[1]
                            price = int(parts[2])
                            volume = int(parts[3])
                            self.debug("### resending failed", msg["id"])
                            self.send_order_add(typ, price, volume)

                        # resend a failed "order/cancel"
                        if "order_cancel:" in msg["id"]:
                            parts = msg["id"].split(":")
                            oid = parts[1]
                            self.debug("### resending failed", msg["id"])
                            self.send_order_cancel(oid)



        # pylint: disable=W0703
        except Exception:
            self.debug(traceback.format_exc())

        self.msg_count += 1
        if (self.msg_count % 200) == 0:
            self.client.request_order_lag()

    def _on_tick(self, msg):
        """handle incoming ticker message"""
        msg = msg["ticker"]
        if msg["sell"]["currency"] != self.currency:
            return
        ask = int(msg["sell"]["value_int"])
        bid = int(msg["buy"]["value_int"])

        self.debug(" tick:  bid:", int2str(bid, self.currency),
            "ask:", int2str(ask, self.currency))
        self.signal_ticker(self, (bid, ask))

    def _on_depth(self, msg):
        """handle incoming depth message"""
        msg = msg["depth"]
        if msg["currency"] != self.currency:
            return
        type_str = msg["type_str"]
        price = int(msg["price_int"])
        volume = int(msg["volume_int"])
        total_volume = int(msg["total_volume_int"])

        self.debug(
            "depth: ", type_str+":", int2str(price, self.currency),
            "vol:", int2str(volume, "BTC"),
            "now:", int2str(total_volume, "BTC"))
        self.signal_depth(self, (type_str, price, volume, total_volume))

    def _on_trade(self, msg):
        """handle incoming trade mesage"""
        if msg["trade"]["price_currency"] != self.currency:
            return
        if msg["channel"] == "dbf1dee9-4f2e-4a08-8cb7-748919a71b21":
            own = False
        else:
            own = True
        date = int(msg["trade"]["date"])
        price = int(msg["trade"]["price_int"])
        volume = int(msg["trade"]["amount_int"])
        typ = msg["trade"]["trade_type"]

        self.debug(
            "trade:      ", int2str(price, self.currency),
            "vol:", int2str(volume, "BTC"),
            "type:", typ
        )
        self.signal_trade(self, (date, price, volume, typ, own))

    def _on_call_result(self, msg):
        """handle result of authenticated API call"""
        result = msg["result"]
        reqid = msg["id"]

        if reqid == "idkey":
            self.debug("### got key, subscribing to account messages")
            self._idkey = result
            self.client.send(json.dumps({"op":"mtgox.subscribe", "key":result}))
            return

        if reqid == "orders":
            self.debug("### got own order list")
            self.orderbook.reset_own()
            for order in result:
                if order["currency"] == self.currency:
                    self.orderbook.add_own(Order(
                        int(order["price"]["value_int"]),
                        int(order["amount"]["value_int"]),
                        order["type"],
                        order["oid"],
                        order["status"]
                    ))
            self.debug("### have %d own orders for BTC/%s" %
                (len(self.orderbook.owns), self.currency))
            return

        if reqid == "info":
            self.debug("### got account info")
            gox_wallet = result["Wallets"]
            self.wallet = {}
            for currency in gox_wallet:
                self.wallet[currency] = int(
                    gox_wallet[currency]["Balance"]["value_int"])
            self.signal_wallet(self, ())
            return

        if reqid == "order_lag":
            lag_usec = result["lag"]
            lag_text = result["lag_text"]
            self.order_lag = lag_usec
            self.signal_orderlag(self, (lag_usec, lag_text))

        if "order_add:" in reqid:
            parts = reqid.split(":")
            typ = parts[1]
            price = int(parts[2])
            volume = int(parts[3])
            oid = result
            self.orderbook.add_own(Order(price, volume, typ, oid, "pending"))

        if "order_cancel:" in reqid:
            # cancel request has been received but we won't remove it from our
            # own list now because it is still active on the server.
            # do nothing now, let things happen in the user_order message
            pass


    def _on_user_order(self, msg):
        """handle incoming user_order message"""
        order = msg["user_order"]
        oid = order["oid"]
        if "price" in order:
            if order["currency"] == self.currency:
                price = int(order["price"]["value_int"])
                volume = int(order["amount"]["value_int"])
                typ = order["type"]
                status = order["status"]
                self.signal_userorder(self,
                    (price, volume, typ, oid, status))

        else: # removed (filled or canceled)
            self.signal_userorder(self, (0, 0, "", oid, "removed"))

    def _on_wallet(self, dummy_msg):
        """handle incoming wallet message"""
        # I am lazy, just sending a new info request,
        # so it will update automatically.
        self.client.send_signed_call("private/info", {}, "info")


    def send_order_add(self, typ, price, volume):
        """send an order"""
        self.client.send_signed_call(
            "order/add",
            {"type": typ, "price_int": price, "amount_int": volume},
            "order_add:%s:%d:%d" % (typ, price, volume)
        )

    def send_order_cancel(self, oid):
        """cancel an order"""
        self.client.send_signed_call(
            "order/cancel",
            {"oid": oid},
            "order_cancel:%s" % oid
        )


class Order:
    """represents an order in the orderbook"""

    def __init__(self, price, volume, typ, oid="", status=""):
        """initialize a new order object"""
        self.price = price
        self.volume = volume
        self.typ = typ
        self.oid = oid
        self.status = status


class OrderBook(BaseObject):
    """represents the orderbook. Each Gox instance has one
    instance of OrderBook to maintain the open orders. This also
    maintains a list of own orders belonging to this account"""

    def __init__(self, gox):
        """create a new empty orderbook and associate it with its
        Gox instance"""
        BaseObject.__init__(self)
        self.gox = gox

        self.signal_changed = Signal()

        gox.signal_ticker.connect(self.slot_ticker)
        gox.signal_depth.connect(self.slot_depth)
        gox.signal_trade.connect(self.slot_trade)
        gox.signal_userorder.connect(self.slot_user_order)
        gox.signal_fulldepth.connect(self.slot_fulldepth)

        self.bids = [] # list of Order(), lowest ask first
        self.asks = [] # list of Order(), highest bid first
        self.owns = [] # list of Order(), unordered list

        self.bid = 0
        self.ask = 0

    def slot_ticker(self, dummy_sender, (bid, ask)):
        """Slot for signal_ticker, incoming ticker message"""
        self.bid = bid
        self.ask = ask
        change = False
        while len(self.asks) and self.asks[0].price < ask:
            change = True
            self.asks.pop(0)

        while len(self.bids) and self.bids[0].price > bid:
            change = True
            self.bids.pop(0)

        if change:
            self.signal_changed(self, ())

    def slot_depth(self, dummy_sender, (typ, price, dummy_voldiff, total_vol)):
        """Slot for signal_depth, process incoming depth message"""
        # pylint: disable=R0912

        def must_insert_before(existing, new, typ):
            """compare existing and new order, depending on whether it is
            a bid or an ask (bids are sorted highest first) we must do
            a different comparison to find either the first higher ask
            in the list or the first lower bid"""
            if typ == "ask":
                return (existing > new)
            else:
                return (existing < new)

        def update_list(lst, price, total_vol, typ):
            """update the list (either bids or asks), insert an order
            at that price or update the volume at that price or remove
            it if the total volume at that price reaches zero"""
            cnt = len(lst)
            if total_vol > 0:
                for i in range(cnt):
                    if lst[i].price == price:
                        lst[i].volume = total_vol
                        break
                    if must_insert_before(lst[i].price, price, typ):
                        lst.insert(i, Order(price, total_vol, typ))
                        break
                    if i == cnt - 1:
                        lst.append(Order(price, total_vol, typ))
                if cnt == 0:
                    lst.insert(0, Order(price, total_vol, typ))
            else:
                for i in range(cnt):
                    if lst[i].price == price:
                        lst.pop(i)
                        break

        if typ == "ask":
            update_list(self.asks, price, total_vol, "ask")
        if typ == "bid":
            update_list(self.bids, price, total_vol, "bid")
        self.signal_changed(self, ())

    def slot_trade(self, dummy_sender,
        (dummy_date, price, volume, typ, own)):
        """Slot for signal_trade event, process incoming trade messages.
        For trades that also affect own orders this will be called twice:
        once during the normal public trade message, affecting the public
        bids and asks and then another time with own=True to update our
        own orders list"""

        def update_list(lst, price, volume):
            """find the order in the list, update it or remove it if zero."""
            for i in range(len(lst)):
                if lst[i].price == price:
                    lst[i].volume -= volume
                    if lst[i].volume <= 0:
                        lst.pop(i)
                    break

        if own:
            self.debug("### this trade message affects only our own order")
            update_list(self.owns, price, volume)
        else:
            if typ == "bid":  # tryde_type=bid means an ask order was filled
                while len(self.asks) and self.asks[0].price < price:
                    self.asks.pop(0)
                update_list(self.asks, price, volume)
            if typ == "ask":  # trade_type=ask means a bid order was filled
                while len(self.bids) and self.bids[0].price > price:
                    self.bids.pop(0)
                update_list(self.bids, price, volume)

            if len(self.asks):
                self.ask = self.asks[0].price
            if len(self.bids):
                self.bid = self.bids[0].price

        self.signal_changed(self, ())

    def slot_user_order(self, dummy_sender, (price, volume, typ, oid, status)):
        """Slot for signal_userorder, process incoming user_order mesage"""
        if status == "removed":
            for i in range(len(self.owns)):
                if self.owns[i].oid == oid:
                    order = self.owns[i]
                    self.debug(
                        "### removing order %s " % oid,
                        "price:", int2str(order.price, self.gox.currency),
                        "type:", order.typ)
                    self.owns.pop(i)
                    break
        else:
            found = False
            for order in self.owns:
                if order.oid == oid:
                    found = True
                    self.debug(
                        "### updating order %s " % oid,
                        "volume:", int2str(volume, "BTC"),
                        "status:", status)
                    order.volume = volume
                    order.status = status
                    break

            if not found:
                self.debug(
                    "### adding order %s " % oid,
                    "volume:", int2str(volume, "BTC"),
                    "status:", status)
                self.owns.append(Order(price, volume, typ, oid, status))

        self.signal_changed(self, ())

    def slot_fulldepth(self, dummy_sender, (depth)):
        """Slot for signal_fulldepth, process received fulldepth data.
        This will clear the book and then re-initialize it from scratch."""
        self.debug("### got full depth: updating orderbook...")
        self.bids = []
        self.asks = []
        if "error" in depth:
            self.debug("### ", depth["error"])
            return
        for order in depth["return"]["asks"]:
            price = int(order["price_int"])
            volume = int(order["amount_int"])
            self.asks.append(Order(price, volume, "ask"))
        for order in depth["return"]["bids"]:
            price = int(order["price_int"])
            volume = int(order["amount_int"])
            self.bids.insert(0, Order(price, volume, "bid"))

        self.signal_changed(self, ())

    def get_own_volume_at(self, price):
        """returns the sum of the volume of own orders at a given price"""
        volume = 0
        for order in self.owns:
            if order.price == price:
                volume += order.volume
        return volume

    def have_own_oid(self, oid):
        """do we have an own order with this oid in our list already?"""
        for order in self.owns:
            if order.oid == oid:
                return True
        return False

    def reset_own(self):
        """clear all own orders"""
        self.owns = []
        self.signal_changed(self, ())

    def add_own(self, order):
        """add order to the list of own orders. This method is used
        by the Gox object only during initial download of complete
        order list, all subsequent updates will then be done through
        the event methods slot_user_order and slot_trade"""

        def insert_dummy(lst, is_ask):
            """insert an empty (volume=0) dummy order into the bids or asks
            to make the own order immediately appear in the UI, even if we
            don't have the full orderbook yet. The dummy orders will be updated
            later to reflect the true total volume at these prices once we get
            authoritative data from the server"""
            for i in range (len(lst)):
                existing = lst[i]
                if existing.price == order.price:
                    return # no dummy needed, an order at this price exists
                if is_ask:
                    if existing.price > order.price:
                        lst.insert(i, Order(order.price, 0, order.typ))
                        return
                else:
                    if existing.price < order.price:
                        lst.insert(i, Order(order.price, 0, order.typ))
                        return

            # end of list or empty
            lst.append(Order(order.price, 0, order.typ))

        if not self.have_own_oid(order.oid):
            self.owns.append(order)

            if order.typ == "ask":
                insert_dummy(self.asks, True)
            if order.typ == "bid":
                insert_dummy(self.bids, False)

            self.signal_changed(self, ())
