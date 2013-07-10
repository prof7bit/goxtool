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

# pylint: disable=C0302,C0301,R0902,R0903,R0912,R0913,R0914,R0915,W0703

import sys
PY_VERSION = sys.version_info

if PY_VERSION < (2, 7):
    print("Sorry, minimal Python version is 2.7, you have: %d.%d"
        % (PY_VERSION.major, PY_VERSION.minor))
    sys.exit(1)

from ConfigParser import SafeConfigParser
import base64
import binascii
import contextlib
from Crypto.Cipher import AES
import getpass
import gzip
import hashlib
import hmac
import inspect
import io
import json
import logging
import Queue
import time
import traceback
import threading
from urllib2 import Request as URLRequest
from urllib2 import urlopen, HTTPError
from urllib import urlencode
import weakref
import websocket

input = raw_input # pylint: disable=W0622,C0103

FORCE_PROTOCOL = ""
FORCE_NO_FULLDEPTH = False
FORCE_NO_HISTORY = False
FORCE_HTTP_API = False
FORCE_NO_HTTP_API = False

SOCKETIO_HOST = "socketio.mtgox.com"
WEBSOCKET_HOST = "websocket.mtgox.com"
HTTP_HOST = "data.mtgox.com"

USER_AGENT = "goxtool.py"

# deprecated, use gox.quote2str() and gox.base2str() instead
def int2str(value_int, currency):
    """return currency integer formatted as a string"""
    if currency in "BTC LTC NMC":
        return ("%16.8f" % (value_int / 100000000.0))
    elif currency in "JPY SEK":
        return ("%12.3f" % (value_int / 1000.0))
    else:
        return ("%12.5f" % (value_int / 100000.0))

# deprecated, use gox.quote2float() and gox.base2float() instead
def int2float(value_int, currency):
    """convert integer to float, determine the factor by currency name"""
    if currency in "BTC LTC NMC":
        return value_int / 100000000.0
    elif currency in "JPY SEK":
        return value_int / 1000.0
    else:
        return value_int / 100000.0

# deprecated, use gox.quote2int() and gox.base2int() instead
def float2int(value_float, currency):
    """convert float value to integer, determine the factor by currency name"""
    if currency in "BTC LTC NMC":
        return int(round(value_float * 100000000))
    elif currency in "JPY SEK":
        return int(round(value_float * 1000))
    else:
        return int(round(value_float * 100000))

def http_request(url, post=None, headers=None):
    """request data from the HTTP API, returns a string"""

    def read_gzipped(response):
        """read data from the response object,
        unzip if necessary, return text string"""
        if response.info().get('Content-Encoding') == 'gzip':
            with io.BytesIO(response.read()) as buf:
                with gzip.GzipFile(fileobj=buf) as unzipped:
                    data = unzipped.read()
        else:
            data = response.read()
        return data

    if not headers:
        headers = {}
    request = URLRequest(url, post, headers)
    request.add_header('Accept-encoding', 'gzip')
    request.add_header('User-Agent', USER_AGENT)
    data = ""
    try:
        with contextlib.closing(urlopen(request, post)) as res:
            data = read_gzipped(res)
    except HTTPError as err:
        data = read_gzipped(err)

    return data

def start_thread(thread_func):
    """start a new thread to execute the supplied function"""
    thread = threading.Thread(None, thread_func)
    thread.daemon = True
    thread.start()
    return thread

def pretty_format(something):
    """pretty-format a nested dict or list for debugging purposes.
    If it happens to be a valid json string then it will be parsed first"""
    try:
        return pretty_format(json.loads(something))
    except Exception:
        try:
            return json.dumps(something, indent=5)
        except Exception:
            return str(something)


# pylint: disable=R0904
class GoxConfig(SafeConfigParser):
    """return a config parser object with default values. If you need to run
    more Gox() objects at the same time you will also need to give each of them
    them a separate GoxConfig() object. For this reason it takes a filename
    in its constructor for the ini file, you can have separate configurations
    for separate Gox() instances"""

    _DEFAULTS = [["gox", "base_currency", "BTC"]
                ,["gox", "quote_currency", "USD"]
                ,["gox", "use_ssl", "True"]
                ,["gox", "use_plain_old_websocket", "True"]
                ,["gox", "use_http_api", "True"]
                ,["gox", "use_tonce", "False"]
                ,["gox", "load_fulldepth", "True"]
                ,["gox", "load_history", "True"]
                ,["gox", "history_timeframe", "15"]
                ,["gox", "secret_key", ""]
                ,["gox", "secret_secret", ""]
                ]

    def __init__(self, filename):
        self.filename = filename
        SafeConfigParser.__init__(self)
        self.load()
        self.init_defaults(self._DEFAULTS)
        # upgrade from deprecated "currency" to "quote_currency"
        # todo: remove this piece of code again in a few months
        if self.has_option("gox", "currency"):
            self.set("gox", "quote_currency", self.get_string("gox", "currency"))
            self.remove_option("gox", "currency")
            self.save()

    def init_defaults(self, defaults):
        """add the missing default values, default is a list of defaults"""
        for (sect, opt, default) in defaults:
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

        except: # pylint: disable=W0702
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

    def get_int(self, sect, opt):
        """get int value from config"""
        vstr = self.get_safe(sect, opt)
        try:
            return int(vstr)
        except ValueError:
            return 0

    def get_float(self, sect, opt):
        """get int value from config"""
        vstr = self.get_safe(sect, opt)
        try:
            return float(vstr)
        except ValueError:
            return 0.0

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

                except: # pylint: disable=W0702
                    errors.append(traceback.format_exc())

            for obj, funcs in self._methods.items():
                for func in funcs:
                    try:
                        func(obj, sender, data)
                        sent = True

                    except: # pylint: disable=W0702
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


class Timer(Signal):
    """a simple timer (used for stuff like keepalive)."""

    def __init__(self, interval, one_shot=False):
        """create a new timer, interval is in seconds"""
        Signal.__init__(self)
        self._one_shot = one_shot
        self._canceled = False
        self._interval = interval
        self._timer = None
        self._start()

    def _fire(self):
        """fire the signal and restart it"""
        if not self._canceled:
            self.__call__(self, None)
            if not (self._canceled or self._one_shot):
                self._start()

    def _start(self):
        """start the timer"""
        self._timer = threading.Timer(self._interval, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def cancel(self):
        """cancel the timer"""
        self._canceled = True
        self._timer.cancel()
        self._timer = None


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

        # pylint: disable=C0103
        self.password_from_commandline_option = None

    def decrypt(self, password):
        """decrypt "secret_secret" from the ini file with the given password.
        This will return false if decryption did not seem to be successful.
        After this menthod succeeded the application can access the secret"""

        key = self.config.get_string("gox", "secret_key")
        sec = self.config.get_string("gox", "secret_secret")
        if sec == "" or key == "":
            return self.S_NO_SECRET

        # pylint: disable=E1101
        hashed_pass = hashlib.sha512(password.encode("utf-8")).digest()
        crypt_key = hashed_pass[:32]
        crypt_ini = hashed_pass[-16:]
        aes = AES.new(crypt_key, AES.MODE_OFB, crypt_ini)
        try:
            encrypted_secret = base64.b64decode(sec.strip().encode("ascii"))
            self.secret = aes.decrypt(encrypted_secret).strip()
            self.key = key.strip()
        except ValueError:
            return self.S_FAIL

        # now test if we now have something plausible
        try:
            print("testing secret...")
            # is it plain ascii? (if not this will raise exception)
            dummy = self.secret.decode("ascii")
            # can it be decoded? correct size afterwards?
            if len(base64.b64decode(self.secret)) != 64:
                raise Exception("decrypted secret has wrong size")

            print("testing key...")
            # key must be only hex digits and have the right size
            hex_key = self.key.replace("-", "").encode("ascii")
            if len(binascii.unhexlify(hex_key)) != 16:
                raise Exception("key has wrong size")

            print("ok :-)")
            return self.S_OK

        except Exception as exc:
            # this key and secret do not work :-(
            self.secret = ""
            self.key = ""
            print("### Error occurred while testing the decrypted secret:")
            print("    '%s'" % exc)
            print("    This does not seem to be a valid MtGox API secret")
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

        if self.password_from_commandline_option:
            password = self.password_from_commandline_option
        else:
            password = getpass.getpass("enter passphrase for secret: ")

        result = self.decrypt(password)
        if result != self.S_OK:
            print("")
            print("secret could not be decrypted")
            answer = input("press any key to continue anyways " \
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
        print("Please copy/paste key and secret from MtGox and")
        print("then provide a password to encrypt them.")
        print("")


        key =    input("             key: ").strip()
        secret = input("          secret: ").strip()
        while True:
            password1 = getpass.getpass("        password: ").strip()
            if password1 == "":
                print("aborting")
                return
            password2 = getpass.getpass("password (again): ").strip()
            if password1 != password2:
                print("you had a typo in the password. try again...")
            else:
                break

        # pylint: disable=E1101
        hashed_pass = hashlib.sha512(password1.encode("utf-8")).digest()
        crypt_key = hashed_pass[:32]
        crypt_ini = hashed_pass[-16:]
        aes = AES.new(crypt_key, AES.MODE_OFB, crypt_ini)

        # since the secret is a base64 string we can just just pad it with
        # spaces which can easily be stripped again after decryping
        print(len(secret))
        secret += " " * (16 - len(secret) % 16)
        print(len(secret))
        secret = base64.b64encode(aes.encrypt(secret)).decode("ascii")

        self.config.set("gox", "secret_key", key)
        self.config.set("gox", "secret_secret", secret)
        self.config.save()

        print("encrypted secret has been saved in %s" % self.config.filename)

    def know_secret(self):
        """do we know the secret key? The application must be able to work
        without secret and then just don't do any account related stuff"""
        return(self.secret != "") and (self.key != "")


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

    def slot_trade(self, dummy_sender, data):
        """slot for gox.signal_trade"""
        (date, price, volume, dummy_typ, own) = data
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

    def slot_fullhistory(self, dummy_sender, data):
        """process the result of the fullhistory request"""
        (history) = data

        if not len(history):
            self.debug("### history download was empty")
            return

        def get_time_round(date):
            """round timestamp to current candle timeframe"""
            return int(date / self.timeframe) * self.timeframe

        #remove existing recent candle(s) if any, we will create them fresh
        date_begin = get_time_round(int(history[0]["date"]))
        while len(self.candles) and self.candles[0].tim >= date_begin:
            self.candles.pop(0)

        new_candle = OHLCV(0, 0, 0, 0, 0, 0) #this is a dummy, not actually inserted
        count_added = 0
        for trade in history:
            date = int(trade["date"])
            price = int(trade["price_int"])
            volume = int(trade["amount_int"])
            time_round = get_time_round(date)
            if time_round > new_candle.tim:
                if new_candle.tim > 0:
                    self._add_candle(new_candle)
                    count_added += 1
                new_candle = OHLCV(
                    time_round, price, price, price, price, volume)
            new_candle.update(price, volume)

        # insert current (incomplete) candle
        self._add_candle(new_candle)
        count_added += 1
        self.debug("### got %d updated candle(s)" % count_added)
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

    _last_unique_microtime = 0
    _nonce_lock = threading.Lock()

    def __init__(self, curr_base, curr_quote, secret, config):
        BaseObject.__init__(self)

        self.signal_recv        = Signal()
        self.signal_fulldepth   = Signal()
        self.signal_fullhistory = Signal()

        self._timer = Timer(60)
        self._timer.connect(self.slot_timer)

        self._info_timer = None # used when delayed requesting private/info

        self.curr_base = curr_base
        self.curr_quote = curr_quote

        self.currency = curr_quote # deprecated, use curr_quote instead

        self.secret = secret
        self.config = config
        self.socket = None
        self.http_requests = Queue.Queue()

        self._recv_thread = None
        self._http_thread = None
        self._terminating = False
        self.connected = False
        self._time_last_received = 0
        self._time_last_subscribed = 0
        self.history_last_candle = None

    def start(self):
        """start the client"""
        self._recv_thread = start_thread(self._recv_thread_func)
        self._http_thread = start_thread(self._http_thread_func)

    def stop(self):
        """stop the client"""
        self._terminating = True
        self._timer.cancel()
        if self.socket:
            self.debug("""closing socket""")
            self.socket.sock.close()
        #self._recv_thread.join()

    def _try_send_raw(self, raw_data):
        """send raw data to the websocket or disconnect and close"""
        if self.connected:
            try:
                self.socket.send(raw_data)
            except Exception as exc:
                self.debug(exc)
                self.connected = False
                self.socket.close()

    def send(self, json_str):
        """there exist 2 subtly different ways to send a string over a
        websocket. Each client class will override this send method"""
        raise NotImplementedError()

    def get_unique_mirotime(self):
        """produce a unique nonce that is guaranteed to be ever increasing"""
        with self._nonce_lock:
            microtime = int(time.time() * 1E6)
            if microtime <= self._last_unique_microtime:
                microtime = self._last_unique_microtime + 1
            self._last_unique_microtime = microtime
            return microtime

    def use_http(self):
        """should we use http api? return true if yes"""
        use_http = self.config.get_bool("gox", "use_http_api")
        if FORCE_HTTP_API:
            use_http = True
        if FORCE_NO_HTTP_API:
            use_http = False
        return use_http

    def use_tonce(self):
        """should we use tonce instead on nonce? tonce is current microtime
        and also works when messages come out of order (which happens at
        the mtgox server in certain siuations). They still have to be unique
        because mtgox will remember all recently used tonce values. It will
        only be accepted when the local clock is +/- 10 seconds exact."""
        return self.config.get_bool("gox", "use_tonce")

    def request_fulldepth(self):
        """start the fulldepth thread"""

        def fulldepth_thread():
            """request the full market depth, initialize the order book
            and then terminate. This is called in a separate thread after
            the streaming API has been connected."""
            self.debug("requesting initial full depth")
            use_ssl = self.config.get_bool("gox", "use_ssl")
            proto = {True: "https", False: "http"}[use_ssl]
            fulldepth = http_request("%s://%s/api/2/%s%s/money/depth/full" % (
                proto,
                HTTP_HOST,
                self.curr_base,
                self.curr_quote
            ))
            self.signal_fulldepth(self, (json.loads(fulldepth)))

        start_thread(fulldepth_thread)

    def request_history(self):
        """request trading history"""

        # Gox() will have set this field to the timestamp of the last
        # known candle, so we only request data since this time
        since = self.history_last_candle

        def history_thread():
            """request trading history"""

            # 1308503626, 218868 <-- last small transacion ID
            # 1309108565, 1309108565842636 <-- first big transaction ID

            if since:
                querystring = "?since=%i" % (since * 1000000)
            else:
                querystring = ""

            self.debug("requesting history")
            use_ssl = self.config.get_bool("gox", "use_ssl")
            proto = {True: "https", False: "http"}[use_ssl]
            json_hist = http_request("%s://%s/api/2/%s%s/money/trades%s" % (
                proto,
                HTTP_HOST,
                self.curr_base,
                self.curr_quote,
                querystring
            ))
            history = json.loads(json_hist)
            if history["result"] == "success":
                self.signal_fullhistory(self, history["data"])

        start_thread(history_thread)

    def _recv_thread_func(self):
        """this will be executed as the main receiving thread, each type of
        client (websocket or socketio) will implement its own"""
        raise NotImplementedError()

    def channel_subscribe(self, download_market_data=True):
        """subscribe to needed channnels and download initial data (orders,
        account info, depth, history, etc. Some of these might be redundant but
        at the time I wrote this code the socketio server seemed to have a bug,
        not being able to subscribe via the GET parameters, so I send all
        needed subscription requests here again, just to be on the safe side."""

        symb = "%s%s" % (self.curr_base, self.curr_quote)
        self.send(json.dumps({"op":"mtgox.subscribe", "channel":"depth.%s" % symb}))
        self.send(json.dumps({"op":"mtgox.subscribe", "channel":"ticker.%s" % symb}))

        # trades and lag are the same channels for all currencies
        self.send(json.dumps({"op":"mtgox.subscribe", "type":"trades"}))
        self.send(json.dumps({"op":"mtgox.subscribe", "type":"lag"}))

        self.request_idkey()
        self.request_orders()
        self.request_info()

        if download_market_data:
            if self.config.get_bool("gox", "load_fulldepth"):
                if not FORCE_NO_FULLDEPTH:
                    self.request_fulldepth()

            if self.config.get_bool("gox", "load_history"):
                if not FORCE_NO_HISTORY:
                    self.request_history()

        self._time_last_subscribed = time.time()

    def _slot_timer_info_later(self, _sender, _data):
        """the slot for the request_info_later() timer signal"""
        self.request_info()
        self._info_timer = None

    def request_info_later(self, delay):
        """request the private/info in delay seconds from now"""
        if self._info_timer:
            self._info_timer.cancel()
        self._info_timer = Timer(delay, True)
        self._info_timer.connect(self._slot_timer_info_later)

    def request_info(self):
        """request the private/info object"""
        if self.use_http():
            self.enqueue_http_request("money/info", {}, "info")
        else:
            self.send_signed_call("private/info", {}, "info")

    def request_idkey(self):
        """request the private/idkey object"""
        if self.use_http():
            self.enqueue_http_request("money/idkey", {}, "idkey")
        else:
            self.send_signed_call("private/idkey", {}, "idkey")

    def request_orders(self):
        """request the private/orders object"""
        if self.use_http():
            self.enqueue_http_request("money/orders", {}, "orders")
        else:
            self.send_signed_call("private/orders", {}, "orders")

    def _http_thread_func(self):
        """send queued http requests to the http API (only used when
        http api is forced, normally this is much slower)"""
        while not self._terminating:
            # pop queued request from the queue and process it
            (api_endpoint, params, reqid) = self.http_requests.get(True)
            translated = None
            try:
                answer = self.http_signed_call(api_endpoint, params)
                if answer["result"] == "success":
                    # the following will reformat the answer in such a way
                    # that we can pass it directly to signal_recv()
                    # as if it had come directly from the websocket
                    translated = {
                        "op": "result",
                        "result": answer["data"],
                        "id": reqid
                    }
                else:
                    if "error" in answer:
                        # these are errors like "Order amount is too low"
                        # or "Order not found" and the like, we send them
                        # to signal_recv() as if they had come from the
                        # streaming API beause Gox() can handle these errors.
                        translated = {
                            "op": "remark",
                            "success": False,
                            "message": answer["error"],
                            "token": answer["token"],
                            "id": reqid
                        }
                    else:
                        self.debug("### unexpected http result:", answer, reqid)

            except Exception as exc:
                # should this ever happen? HTTP 5xx wont trigger this,
                # something else must have gone wrong, a totally malformed
                # reply or something else. Log the error and don't retry
                self.debug("### exception in _http_thread_func:",
                    exc, api_endpoint, params, reqid)

            if translated:
                self.signal_recv(self, (json.dumps(translated)))

            self.http_requests.task_done()

    def enqueue_http_request(self, api_endpoint, params, reqid):
        """enqueue a request for sending to the HTTP API, returns
        immediately, behaves exactly like sending it over the websocket."""
        if self.secret and self.secret.know_secret():
            self.http_requests.put((api_endpoint, params, reqid))

    def http_signed_call(self, api_endpoint, params):
        """send a signed request to the HTTP API V2"""
        if (not self.secret) or (not self.secret.know_secret()):
            self.debug("### don't know secret, cannot call %s" % api_endpoint)
            return

        key = self.secret.key
        sec = self.secret.secret

        if self.use_tonce():
            params["tonce"] = self.get_unique_mirotime()
        else:
            params["nonce"] = self.get_unique_mirotime()

        post = urlencode(params)
        prefix = api_endpoint + chr(0)
        # pylint: disable=E1101
        sign = hmac.new(base64.b64decode(sec), prefix + post, hashlib.sha512).digest()

        headers = {
            'Rest-Key': key,
            'Rest-Sign': base64.b64encode(sign)
        }

        use_ssl = self.config.get_bool("gox", "use_ssl")
        proto = {True: "https", False: "http"}[use_ssl]
        url = "%s://%s/api/2/%s" % (
            proto,
            HTTP_HOST,
            api_endpoint
        )
        self.debug("### (%s) calling %s" % (proto, url))
        return json.loads(http_request(url, post, headers))

    def send_signed_call(self, api_endpoint, params, reqid):
        """send a signed (authenticated) API call over the socket.io.
        This method will only succeed if the secret key is available,
        otherwise it will just log a warning and do nothing."""
        if (not self.secret) or (not self.secret.know_secret()):
            self.debug("### don't know secret, cannot call %s" % api_endpoint)
            return

        key = self.secret.key
        sec = self.secret.secret

        call = {
            "id"       : reqid,
            "call"     : api_endpoint,
            "params"   : params,
            "currency" : self.curr_quote,
            "item"     : self.curr_base
        }
        if self.use_tonce():
            call["tonce"] = self.get_unique_mirotime()
        else:
            call["nonce"] = self.get_unique_mirotime()
        call = json.dumps(call)

        # pylint: disable=E1101
        sign = hmac.new(base64.b64decode(sec), call, hashlib.sha512).digest()
        signedcall = key.replace("-", "").decode("hex") + sign + call

        self.debug("### (socket) calling %s" % api_endpoint)
        self.send(json.dumps({
            "op"      : "call",
            "call"    : base64.b64encode(signedcall),
            "id"      : reqid,
            "context" : "mtgox.com"
        }))

    def send_order_add(self, typ, price, volume):
        """send an order"""
        reqid = "order_add:%s:%d:%d" % (typ, price, volume)
        if price > 0:
            params = {"type": typ, "price_int": price, "amount_int": volume}
        else:
            params = {"type": typ, "amount_int": volume}

        if self.use_http():
            api = "%s%s/money/order/add" % (self.curr_base , self.curr_quote)
            self.enqueue_http_request(api, params, reqid)
        else:
            api = "order/add"
            self.send_signed_call(api, params, reqid)

    def send_order_cancel(self, oid):
        """cancel an order"""
        params = {"oid": oid}
        reqid = "order_cancel:%s" % oid
        if self.use_http():
            api = "money/order/cancel"
            self.enqueue_http_request(api, params, reqid)
        else:
            api = "order/cancel"
            self.send_signed_call(api, params, reqid)

    def slot_timer(self, _sender, _data):
        """check timeout (last received, dead socket?)"""
        if self.connected:
            if time.time() - self._time_last_received > 60:
                self.debug("did not receive anything for a long time, disconnecting.")
                self.socket.close()
                self.connected = False
            if time.time() - self._time_last_subscribed > 3600:
                # sometimes after running for a few hours it
                # will lose some of the subscriptons for no
                # obvious reason. I've seen it losing the trades
                # and the lag channel channel already, and maybe
                # even others. Simply subscribing again completely
                # fixes this condition. For this reason we renew
                # all channel subscriptions once every hour.
                self.debug("### refreshing channel subscriptions")
                self.channel_subscribe(False)


class WebsocketClient(BaseClient):
    """this implements a connection to MtGox through the older (but faster)
    websocket protocol. Unfortuntely its just as unreliable as the socket.io."""

    def __init__(self, curr_base, curr_quote, secret, config):
        BaseClient.__init__(self, curr_base, curr_quote, secret, config)
        self.hostname = WEBSOCKET_HOST

    def _recv_thread_func(self):
        """connect to the websocket and start receiving in an infinite loop.
        Try to reconnect whenever connection is lost. Each received json
        string will be dispatched with a signal_recv signal"""
        reconnect_time = 1
        use_ssl = self.config.get_bool("gox", "use_ssl")
        wsp = {True: "wss://", False: "ws://"}[use_ssl]
        port = {True: 443, False: 80}[use_ssl]
        ws_origin = "%s:%d" % (self.hostname, port)
        ws_headers = ["User-Agent: %s" % USER_AGENT]
        while not self._terminating:  #loop 0 (connect, reconnect)
            try:
                # channels separated by "/", wildcards allowed. Available
                # channels see here: https://mtgox.com/api/2/stream/list_public
                # example: ws://websocket.mtgox.com/?Channel=depth.LTCEUR/ticker.LTCEUR
                # the trades and lag channel will be subscribed after connect
                sym = "%s%s" % (self.curr_base, self.curr_quote)
                ws_url = "%s%s?Channel=depth.%s/ticker.%s" % \
                    (wsp, self.hostname, sym, sym)
                self.debug("trying plain old Websocket: %s ... " % ws_url)

                self.socket = websocket.WebSocket()
                # The server is somewhat picky when it comes to the exact
                # host:port syntax of the origin header, so I am supplying
                # my own origin header instead of the auto-generated one
                self.socket.connect(ws_url, origin=ws_origin, header=ws_headers)
                self._time_last_received = time.time()
                self.connected = True
                self.debug("connected, subscribing needed channels")
                self.channel_subscribe()

                self.debug("waiting for data...")
                while not self._terminating: #loop1 (read messages)
                    str_json = self.socket.recv()
                    self._time_last_received = time.time()
                    if str_json[0] == "{":
                        self.signal_recv(self, (str_json))

            except Exception as exc:
                self.connected = False
                if not self._terminating:
                    self.debug(exc.__class__.__name__, exc,
                        "reconnecting in %i seconds..." % reconnect_time)
                    if self.socket:
                        self.socket.close()
                    time.sleep(reconnect_time)

    def send(self, json_str):
        """send the json encoded string over the websocket"""
        self._try_send_raw(json_str)


class SocketIO(websocket.WebSocket):
    """This is the WebSocket() class with added Super Cow Powers. It has a
    different connect method so that it can connect to socket.io. It will do
    the initial HTTP request with keep-alive and then use that same socket
    to upgrade to websocket"""
    def __init__(self, get_mask_key = None):
        websocket.WebSocket.__init__(self, get_mask_key)

    def connect(self, url, **options):
        """connect to socketio and then upgrade to websocket transport. Example:
        connect('wss://websocket.mtgox.com/socket.io/1', query='Currency=EUR')"""

        def read_block(sock):
            """read from the socket until empty line, return list of lines"""
            lines = []
            line = ""
            while True:
                res = sock.recv(1)
                line += res
                if res == "":
                    return None
                if res == "\n":
                    line = line.strip()
                    if line == "":
                        return lines
                    lines.append(line)
                    line = ""

        # pylint: disable=W0212
        hostname, port, resource, is_secure = websocket._parse_url(url)
        self.sock.connect((hostname, port))
        if is_secure:
            self.io_sock = websocket._SSLSocketWrapper(self.sock)

        path_a = resource
        if "query" in options:
            path_a += "?" + options["query"]
        self.io_sock.send("GET %s HTTP/1.1\r\n" % path_a)
        self.io_sock.send("Host: %s:%d\r\n" % (hostname, port))
        self.io_sock.send("User-Agent: %s\r\n" % USER_AGENT)
        self.io_sock.send("Accept: text/plain\r\n")
        self.io_sock.send("Connection: keep-alive\r\n")
        self.io_sock.send("\r\n")

        headers = read_block(self.io_sock)
        if not headers:
            raise IOError("disconnected while reading headers")
        if not "200" in headers[0]:
            raise IOError("wrong answer: %s" % headers[0])
        result = read_block(self.io_sock)
        if not result:
            raise IOError("disconnected while reading socketio session ID")
        if len(result) != 3:
            raise IOError("invalid response from socket.io server")

        ws_id = result[1].split(":")[0]
        resource = "%s/websocket/%s" % (resource, ws_id)
        if "query" in options:
            resource = "%s?%s" % (resource, options["query"])

        # now continue with the normal websocket GET and upgrade request
        self._handshake(hostname, port, resource, **options)


class SocketIOClient(BaseClient):
    """this implements a connection to MtGox using the new socketIO protocol.
    This should replace the older plain websocket API"""

    def __init__(self, curr_base, curr_quote, secret, config):
        BaseClient.__init__(self, curr_base, curr_quote, secret, config)
        self.hostname = SOCKETIO_HOST
        self._timer.connect(self.slot_keepalive_timer)

    def _recv_thread_func(self):
        """this is the main thread that is running all the time. It will
        connect and then read (blocking) on the socket in an infinite
        loop. SocketIO messages ('2::', etc.) are handled here immediately
        and all received json strings are dispathed with signal_recv."""
        use_ssl = self.config.get_bool("gox", "use_ssl")
        wsp = {True: "wss://", False: "ws://"}[use_ssl]
        while not self._terminating: #loop 0 (connect, reconnect)
            try:
                url = "%s%s/socket.io/1" % (wsp, self.hostname)

                # subscribing depth and ticker through the querystring,
                # the trade and lag will be subscribed later after connect
                sym = "%s%s" % (self.curr_base, self.curr_quote)
                querystring = "Channel=depth.%s/ticker.%s" % (sym, sym)

                self.debug("trying Socket.IO: %s?%s ..." % (url, querystring))
                self.socket = SocketIO()
                self.socket.connect(url, query=querystring)

                self._time_last_received = time.time()
                self.connected = True
                self.debug("connected")
                self.socket.send("1::/mtgox")

                self.debug(self.socket.recv())
                self.debug(self.socket.recv())

                self.debug("subscribing to channels")
                self.channel_subscribe()

                self.debug("waiting for data...")
                while not self._terminating: #loop1 (read messages)
                    msg = self.socket.recv()
                    self._time_last_received = time.time()
                    if msg == "2::":
                        self.debug("### ping -> pong")
                        self.socket.send("2::")
                        continue
                    prefix = msg[:10]
                    if prefix == "4::/mtgox:":
                        str_json = msg[10:]
                        if str_json[0] == "{":
                            self.signal_recv(self, (str_json))

            except Exception as exc:
                self.connected = False
                if not self._terminating:
                    self.debug(exc.__class__.__name__, exc, \
                        "reconnecting in 1 seconds...")
                    self.socket.close()
                    time.sleep(1)

    def send(self, json_str):
        """send a string to the websocket. This method will prepend it
        with the 1::/mtgox: that is needed for the socket.io protocol
        (as opposed to plain websockts) and the underlying websocket
        will then do the needed framing on top of that."""
        self._try_send_raw("4::/mtgox:" + json_str)

    def slot_keepalive_timer(self, _sender, _data):
        """send a keepalive, just to make sure our socket is not dead"""
        if self.connected:
            self.debug("sending keepalive")
            self._try_send_raw("2::")


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

        self.signal_order_too_fast  = Signal() # don't use that

        self.strategies = weakref.WeakValueDictionary()

        # the following are not fired by gox itself but by the
        # application controlling it to pass some of its events
        self.signal_keypress        = Signal()
        self.signal_strategy_unload = Signal()

        self._idkey      = ""
        self.wallet = {}
        self.trade_fee = 0  # percent (float, for example 0.6 means 0.6%)
        self.monthly_volume = 0 # BTC (satoshi int)
        self.order_lag = 0  # microseconds
        self.socket_lag = 0 # microseconds
        self.last_tid = 0
        self.count_submitted = 0  # number of submitted orders not yet acked
        self.msg = {} # the incoming message that is currently processed

        self.config = config
        self.curr_base = config.get_string("gox", "base_currency")
        self.curr_quote = config.get_string("gox", "quote_currency")

        self.currency = self.curr_quote # deprecated, use curr_quote instead

        # these are needed for conversion from/to intereger, float, string
        if self.curr_quote in "JPY SEK":
            self.mult_quote = 1e3
            self.format_quote = "%12.3f"
        else:
            self.mult_quote = 1e5
            self.format_quote = "%12.5f"
        self.mult_base = 1e8
        self.format_base = "%16.8f"

        Signal.signal_error.connect(self.signal_debug)

        timeframe = 60 * config.get_int("gox", "history_timeframe")
        if not timeframe:
            timeframe = 60 * 15
        self.history = History(self, timeframe)
        self.history.signal_debug.connect(self.signal_debug)

        self.orderbook = OrderBook(self)
        self.orderbook.signal_debug.connect(self.signal_debug)

        use_websocket = self.config.get_bool("gox", "use_plain_old_websocket")
        if "socketio" in FORCE_PROTOCOL:
            use_websocket = False
        if "websocket" in FORCE_PROTOCOL:
            use_websocket = True
        if use_websocket:
            self.client = WebsocketClient(self.curr_base, self.curr_quote, secret, config)
        else:
            self.client = SocketIOClient(self.curr_base, self.curr_quote, secret, config)

        self.client.signal_debug.connect(self.signal_debug)
        self.client.signal_recv.connect(self.slot_recv)
        self.client.signal_fulldepth.connect(self.signal_fulldepth)
        self.client.signal_fullhistory.connect(self.signal_fullhistory)

        self.timer_poll = Timer(120)
        self.timer_poll.connect(self.slot_poll)

        self.history.signal_changed.connect(self.slot_history_changed)

    def start(self):
        """connect to MtGox and start receiving events."""
        self.debug("starting gox streaming API, trading %s%s" %
            (self.curr_base, self.curr_quote))
        self.client.start()

    def stop(self):
        """shutdown the client"""
        self.debug("shutdown...")
        self.client.stop()

    def order(self, typ, price, volume):
        """place pending order. If price=0 then it will be filled at market"""
        self.count_submitted += 1
        self.client.send_order_add(typ, price, volume)

    def buy(self, price, volume):
        """new buy order, if price=0 then buy at market"""
        self.order("bid", price, volume)

    def sell(self, price, volume):
        """new sell order, if price=0 then sell at market"""
        self.order("ask", price, volume)

    def cancel(self, oid):
        """cancel order"""
        self.client.send_order_cancel(oid)

    def cancel_by_price(self, price):
        """cancel all orders at price"""
        for i in reversed(range(len(self.orderbook.owns))):
            order = self.orderbook.owns[i]
            if order.price == price:
                if order.oid != "":
                    self.cancel(order.oid)

    def cancel_by_type(self, typ=None):
        """cancel all orders of type (or all orders if typ=None)"""
        for i in reversed(range(len(self.orderbook.owns))):
            order = self.orderbook.owns[i]
            if typ == None or typ == order.typ:
                if order.oid != "":
                    self.cancel(order.oid)

    def base2float(self, int_number):
        """convert base currency values from mtgox integer to float. Base
        currency are the coins you are trading (BTC, LTC, etc). Use this method
        to convert order volumes (amount of coins) from int to float."""
        return float(int_number) / self.mult_base

    def base2str(self, int_number):
        """convert base currency values from mtgox integer to formatted string"""
        return self.format_base % (float(int_number) / self.mult_base)

    def base2int(self, float_number):
        """convert base currency values from float to mtgox integer"""
        return int(round(float_number * self.mult_base))

    def quote2float(self, int_number):
        """convert quote currency values from mtgox integer to float. Quote
        currency is the currency used to quote prices (USD, EUR, etc), use this
        method to convert the prices of orders, bid or ask from int to float."""
        return float(int_number) / self.mult_quote

    def quote2str(self, int_number):
        """convert quote currency values from mtgox integer to formatted string"""
        return self.format_quote % (float(int_number) / self.mult_quote)

    def quote2int(self, float_number):
        """convert quote currency values from float to mtgox integer"""
        return int(round(float_number * self.mult_quote))

    def slot_recv(self, dummy_sender, data):
        """Slot for signal_recv, handle new incoming JSON message. Decode the
        JSON string into a Python object and dispatch it to the method that
        can handle it."""
        (str_json) = data
        handler = None
        msg = json.loads(str_json)
        self.msg = msg
        if "op" in msg:
            try:
                msg_op = msg["op"]
                handler = getattr(self, "_on_op_" + msg_op)

            except AttributeError:
                self.debug("slot_recv() ignoring: op=%s" % msg_op)
        else:
            self.debug("slot_recv() ignoring:", msg)

        if handler:
            handler(msg)

    def slot_poll(self, _sender, _data):
        """poll stuff from http in regular intervals, not yet implemented"""
        if self.client.secret and self.client.secret.know_secret():
            # poll recent own trades
            # fixme: how do i do this, whats the api for this?
            pass

    def slot_history_changed(self, _sender, _data):
        """this is a small optimzation, if we tell the client the time
        of the last known candle then it won't fetch full history next time"""
        last_candle = self.history.last_candle()
        if last_candle:
            self.client.history_last_candle = last_candle.tim

    def _on_op_error(self, msg):
        """handle error mesages (op:error)"""
        self.debug("_on_op_error()", msg)

    def _on_op_subscribe(self, msg):
        """handle subscribe messages (op:subscribe)"""
        self.debug("subscribed channel", msg["channel"])

    def _on_op_result(self, msg):
        """handle result of authenticated API call (op:result, id:xxxxxx)"""
        result = msg["result"]
        reqid = msg["id"]

        if reqid == "idkey":
            self.debug("### got key, subscribing to account messages")
            self._idkey = result
            self.client.send(json.dumps({"op":"mtgox.subscribe", "key":result}))

        elif reqid == "orders":
            self.debug("### got own order list")
            self.count_submitted = 0
            self.orderbook.init_own(result)
            self.debug("### have %d own orders for %s/%s" %
                (len(self.orderbook.owns), self.curr_base, self.curr_quote))

        elif reqid == "info":
            self.debug("### got account info")
            gox_wallet = result["Wallets"]
            self.wallet = {}
            self.monthly_volume = int(result["Monthly_Volume"]["value_int"])
            self.trade_fee = float(result["Trade_Fee"])
            for currency in gox_wallet:
                self.wallet[currency] = int(
                    gox_wallet[currency]["Balance"]["value_int"])

            self.signal_wallet(self, None)

        elif reqid == "order_lag":
            lag_usec = result["lag"]
            lag_text = result["lag_text"]
            self.debug("### got order lag: %s" % lag_text)
            self.order_lag = lag_usec
            self.signal_orderlag(self, (lag_usec, lag_text))

        elif "order_add:" in reqid:
            # order/add has been acked and we got an oid, now we can already
            # insert a pending order into the owns list (it will be pending
            # for a while when the server is busy but the most important thing
            # is that we have the order-id already).
            parts = reqid.split(":")
            typ = parts[1]
            price = int(parts[2])
            volume = int(parts[3])
            oid = result
            self.debug("### got ack for order/add:", typ, price, volume, oid)
            self.orderbook.add_own(Order(price, volume, typ, oid, "pending"))
            self.count_submitted -= 1

        elif "order_cancel:" in reqid:
            # cancel request has been acked but we won't remove it from our
            # own list now because it is still active on the server.
            # do nothing now, let things happen in the user_order message
            parts = reqid.split(":")
            oid = parts[1]
            self.debug("### got ack for order/cancel:", oid)

        else:
            self.debug("_on_op_result() ignoring:", msg)

    def _on_op_private(self, msg):
        """handle op=private messages, these are the messages of the channels
        we subscribed (trade, depth, ticker) and also the per-account messages
        (user_order, wallet, own trades, etc)"""
        private = msg["private"]
        handler = None
        try:
            handler = getattr(self, "_on_op_private_" + private)
        except AttributeError:
            self.debug("_on_op_private() ignoring: private=%s" % private)
            self.debug(pretty_format(msg))

        if handler:
            handler(msg)

    def _on_op_private_ticker(self, msg):
        """handle incoming ticker message (op=private, private=ticker)"""
        msg = msg["ticker"]
        if msg["sell"]["currency"] != self.curr_quote:
            return
        if msg["item"] != self.curr_base:
            return
        bid = int(msg["buy"]["value_int"])
        ask = int(msg["sell"]["value_int"])

        self.debug(" tick: %s %s" % (
            self.quote2str(bid),
            self.quote2str(ask)
        ))
        self.signal_ticker(self, (bid, ask))

    def _on_op_private_depth(self, msg):
        """handle incoming depth message (op=private, private=depth)"""
        msg = msg["depth"]
        if msg["currency"] != self.curr_quote:
            return
        if msg["item"] != self.curr_base:
            return
        typ = msg["type_str"]
        price = int(msg["price_int"])
        volume = int(msg["volume_int"])
        timestamp = int(msg["now"])
        total_volume = int(msg["total_volume_int"])

        delay = time.time() * 1e6 - timestamp
        self.socket_lag = (self.socket_lag * 2 + delay) / 3

        self.debug("depth: %s: %s @ %s total vol: %s (age: %0.2f s)" % (
            typ,
            self.base2str(volume),
            self.quote2str(price),
            self.base2str(total_volume),
            delay / 1e6
        ))
        self.signal_depth(self, (typ, price, volume, total_volume))

    def _on_op_private_trade(self, msg):
        """handle incoming trade mesage (op=private, private=trade)"""
        if msg["trade"]["price_currency"] != self.curr_quote:
            return
        if msg["trade"]["item"] != self.curr_base:
            return
        if msg["channel"] == "dbf1dee9-4f2e-4a08-8cb7-748919a71b21":
            own = False
        else:
            own = True
        date = int(msg["trade"]["date"])
        price = int(msg["trade"]["price_int"])
        volume = int(msg["trade"]["amount_int"])
        typ = msg["trade"]["trade_type"]

        if own:
            self.debug("trade: %s: %s @ %s (own order filled)" % (
                typ,
                self.base2str(volume),
                self.quote2str(price)
            ))
            # send another private/info request because the fee might have
            # changed. We request it a few seconds later because the server
            # seems to need some time until the new values are available.
            self.client.request_info_later(10)
        else:
            self.debug("trade: %s: %s @ %s" % (
                typ,
                self.base2str(volume),
                self.quote2str(price)
            ))

        self.signal_trade(self, (date, price, volume, typ, own))

    def _on_op_private_user_order(self, msg):
        """handle incoming user_order message (op=private, private=user_order)"""
        order = msg["user_order"]
        oid = order["oid"]
        if "price" in order:
            if order["currency"] == self.curr_quote and order["item"] == self.curr_base:
                price = int(order["price"]["value_int"])
                volume = int(order["amount"]["value_int"])
                typ = order["type"]
                status = order["status"]
                self.signal_userorder(self,
                    (price, volume, typ, oid, status))

        else: # removed (filled or canceled)
            self.signal_userorder(self, (0, 0, "", oid, "removed"))

    def _on_op_private_wallet(self, msg):
        """handle incoming wallet message (op=private, private=wallet)"""
        balance = msg["wallet"]["balance"]
        currency = balance["currency"]
        total = int(balance["value_int"])
        self.wallet[currency] = total
        self.signal_wallet(self, None)

    def _on_op_private_lag(self, msg):
        """handle the lag message"""
        self.order_lag = int(msg["lag"]["age"])
        if self.order_lag < 60000000:
            text = "%0.3f s" % (int(self.order_lag / 1000) / 1000.0)
        else:
            text = "%d s" % (int(self.order_lag / 1000000))
        self.signal_orderlag(self, (self.order_lag, text))

    def _on_op_remark(self, msg):
        """handler for op=remark messages"""

        if "success" in msg and not msg["success"]:
            if msg["message"] == "Invalid call":
                self._on_invalid_call(msg)
            elif msg["message"] == "Order not found":
                self._on_order_not_found(msg)
            elif msg["message"] == "Order amount is too low":
                self._on_order_amount_too_low(msg)
            elif "Too many orders placed" in msg["message"]:
                self._on_too_many_orders(msg)
            else:
                # we should log this, helps with debugging
                self.debug(msg)

    def _on_invalid_call(self, msg):
        """this comes as an op=remark message and is a strange mystery"""
        # Workaround: Maybe a bug in their server software,
        # I don't know what's missing. Its all poorly documented :-(
        # Sometimes some API calls fail the first time for no reason,
        # if this happens just send them again. This happens only
        # somtimes (10%) and sending them again will eventually succeed.

        if msg["id"] == "idkey":
            self.debug("### resending private/idkey")
            self.client.send_signed_call(
                "private/idkey", {}, "idkey")

        elif msg["id"] == "info":
            self.debug("### resending private/info")
            self.client.send_signed_call(
                "private/info", {}, "info")

        elif msg["id"] == "orders":
            self.debug("### resending private/orders")
            self.client.send_signed_call(
                "private/orders", {}, "orders")

        elif "order_add:" in msg["id"]:
            parts = msg["id"].split(":")
            typ = parts[1]
            price = int(parts[2])
            volume = int(parts[3])
            self.debug("### resending failed", msg["id"])
            self.client.send_order_add(typ, price, volume)

        elif "order_cancel:" in msg["id"]:
            parts = msg["id"].split(":")
            oid = parts[1]
            self.debug("### resending failed", msg["id"])
            self.client.send_order_cancel(oid)

        else:
            self.debug("_on_invalid_call() ignoring:", msg)

    def _on_order_not_found(self, msg):
        """this means we have sent order/cancel with non-existing oid"""
        parts = msg["id"].split(":")
        oid = parts[1]
        self.debug("### got 'Order not found' for", oid)
        # we are now going to fake a user_order message (the one we
        # obviously missed earlier) that will have the effect of
        # removing the order cleanly.
        fakemsg = {"user_order": {"oid": oid}}
        self._on_op_private_user_order(fakemsg)

    def _on_order_amount_too_low(self, _msg):
        """we received an order_amount too low message."""
        self.debug("Server said: 'Order amount is too low'")
        self.count_submitted -= 1

    def _on_too_many_orders(self, msg):
        """server complains too many orders were placd too fast"""
        self.debug("Server said: '%s" % msg["message"])
        self.count_submitted -= 1
        self.signal_order_too_fast(self, msg)


class Level:
    """represents a level in the orderbook"""
    def __init__(self, price, volume):
        self.price = price
        self.volume = volume
        self.own_volume = 0

        # these fields are only used to store temporary cache values
        # in some (not all!) levels and is calculated by the OrderBook
        # on demand, do not access this, use get_total_up_to() instead!
        self._cache_total_vol = 0
        self._cache_total_vol_quote = 0

class Order:
    """represents an order"""
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
        self.signal_fulldepth_processed = Signal()
        self.signal_owns_changed = Signal()

        gox.signal_ticker.connect(self.slot_ticker)
        gox.signal_depth.connect(self.slot_depth)
        gox.signal_trade.connect(self.slot_trade)
        gox.signal_userorder.connect(self.slot_user_order)
        gox.signal_fulldepth.connect(self.slot_fulldepth)

        self.bids = [] # list of Level(), lowest ask first
        self.asks = [] # list of Level(), highest bid first
        self.owns = [] # list of Order(), unordered list

        self.bid = 0
        self.ask = 0
        self.total_bid = 0
        self.total_ask = 0

        self.last_change_type = None # ("bid", "ask", None) this can be used
        self.last_change_price = 0   # for highlighting relative changes
        self.last_change_volume = 0  # of orderbook levels in goxtool.py

        self._valid_bid_cache = -1 # index of bid with valid _cache_total_vol
        self._valid_ask_cache = -1 # index of ask with valid _cache_total_vol

    def slot_ticker(self, dummy_sender, data):
        """Slot for signal_ticker, incoming ticker message"""
        (bid, ask) = data
        self.bid = bid
        self.ask = ask
        self.last_change_type = None
        self.last_change_price = 0
        self.last_change_volume = 0
        self._repair_crossed_asks(ask)
        self._repair_crossed_bids(bid)
        self.signal_changed(self, None)

    def slot_depth(self, dummy_sender, data):
        """Slot for signal_depth, process incoming depth message"""
        (typ, price, _voldiff, total_vol) = data
        if self._update_book(typ, price, total_vol):
            self.signal_changed(self, None)

    def slot_trade(self, dummy_sender, data):
        """Slot for signal_trade event, process incoming trade messages.
        For trades that also affect own orders this will be called twice:
        once during the normal public trade message, affecting the public
        bids and asks and then another time with own=True to update our
        own orders list"""
        (dummy_date, price, volume, typ, own) = data
        if own:
            # nothing special to do here (yet), there will also be
            # separate user_order messages to update my owns list
            # and a copy of this trade message in the public channel
            pass
        else:
            # we update the orderbook. We could also wait for the depth
            # message but we update the orderbook immediately.
            voldiff = -volume
            if typ == "bid":  # tryde_type=bid means an ask order was filled
                self._repair_crossed_asks(price)
                if len(self.asks):
                    if self.asks[0].price == price:
                        self.asks[0].volume -= volume
                        if self.asks[0].volume <= 0:
                            voldiff -= self.asks[0].volume
                            self.asks.pop(0)
                        self.last_change_type = "ask" #the asks have changed
                        self.last_change_price = price
                        self.last_change_volume = voldiff
                        self._update_total_ask(voldiff)
                        self._valid_ask_cache = -1
                if len(self.asks):
                    self.ask = self.asks[0].price

            if typ == "ask":  # trade_type=ask means a bid order was filled
                self._repair_crossed_bids(price)
                if len(self.bids):
                    if self.bids[0].price == price:
                        self.bids[0].volume -= volume
                        if self.bids[0].volume <= 0:
                            voldiff -= self.bids[0].volume
                            self.bids.pop(0)
                        self.last_change_type = "bid" #the bids have changed
                        self.last_change_price = price
                        self.last_change_volume = voldiff
                        self._update_total_bid(voldiff, price)
                        self._valid_bid_cache = -1
                if len(self.bids):
                    self.bid = self.bids[0].price

        self.signal_changed(self, None)

    def slot_user_order(self, dummy_sender, data):
        """Slot for signal_userorder, process incoming user_order mesage"""
        (price, volume, typ, oid, status) = data
        if status == "removed":
            for i in range(len(self.owns)):
                if self.owns[i].oid == oid:
                    order = self.owns[i]
                    self.debug(
                        "### removing order %s " % oid,
                        "price:", self.gox.quote2str(order.price),
                        "type:", order.typ)

                    # remove it from owns...
                    self.owns.pop(i)

                    # ...and update own volume cache in the bids or asks
                    self._update_level_own_volume(
                        order.typ,
                        order.price,
                        self.get_own_volume_at(order.price, order.typ)
                    )
                    break
        else:
            found = False
            for order in self.owns:
                if order.oid == oid:
                    found = True
                    self.debug(
                        "### updating order %s " % oid,
                        "volume:", self.gox.base2str(volume),
                        "status:", status)
                    order.volume = volume
                    order.status = status
                    break

            if not found:
                self.debug(
                    "### adding order %s " % oid,
                    "volume:", self.gox.base2str(volume),
                    "status:", status)
                self.owns.append(Order(price, volume, typ, oid, status))

            # update level own volume cache
            self._update_level_own_volume(
                typ, price, self.get_own_volume_at(price, typ))

        self.signal_changed(self, None)
        self.signal_owns_changed(self, None)

    def slot_fulldepth(self, dummy_sender, data):
        """Slot for signal_fulldepth, process received fulldepth data.
        This will clear the book and then re-initialize it from scratch."""
        (depth) = data
        self.debug("### got full depth, updating orderbook...")
        self.bids = []
        self.asks = []
        self.total_ask = 0
        self.total_bid = 0
        if "error" in depth:
            self.debug("### ", depth["error"])
            return
        for order in depth["data"]["asks"]:
            price = int(order["price_int"])
            volume = int(order["amount_int"])
            self._update_total_ask(volume)
            self.asks.append(Level(price, volume))
        for order in depth["data"]["bids"]:
            price = int(order["price_int"])
            volume = int(order["amount_int"])
            self._update_total_bid(volume, price)
            self.bids.insert(0, Level(price, volume))

        # update own volume cache
        for order in self.owns:
            self._update_level_own_volume(
                order.typ, order.price, self.get_own_volume_at(order.price, order.typ))

        if len(self.bids):
            self.bid = self.bids[0].price
        if len(self.asks):
            self.ask = self.asks[0].price

        self._valid_ask_cache = -1
        self._valid_bid_cache = -1
        self.signal_fulldepth_processed(self, None)
        self.signal_changed(self, None)

    def _repair_crossed_bids(self, bid):
        """remove all bids that are higher that official current bid value,
        this should actually never be necessary if their feed would not
        eat depth- and trade-messages occaionally :-("""
        while len(self.bids) and self.bids[0].price > bid:
            price = self.bids[0].price
            volume = self.bids[0].volume
            self._update_total_bid(-volume, price)
            self.bids.pop(0)
            self._valid_bid_cache = -1
            #self.debug("### repaired bid")

    def _repair_crossed_asks(self, ask):
        """remove all asks that are lower that official current ask value,
        this should actually never be necessary if their feed would not
        eat depth- and trade-messages occaionally :-("""
        while len(self.asks) and self.asks[0].price < ask:
            volume = self.asks[0].volume
            self._update_total_ask(-volume)
            self.asks.pop(0)
            self._valid_ask_cache = -1
            #self.debug("### repaired ask")

    def _update_book(self, typ, price, total_vol):
        """update the bids or asks list, insert or remove level and
        also update all other stuff that needs to be tracked such as
        total volumes and invalidate the total volume cache index.
        Return True if book has changed, return False otherwise"""
        (lst, index, level) = self._find_level(typ, price)
        if total_vol == 0:
            if level == None:
                return False
            else:
                voldiff = -level.volume
                lst.pop(index)
        else:
            if level == None:
                voldiff = total_vol
                level = Level(price, total_vol)
                lst.insert(index, level)
            else:
                voldiff = total_vol - level.volume
                if voldiff == 0:
                    return False
                level.volume = total_vol

        # now keep all the other stuff in sync with it
        self.last_change_type = typ
        self.last_change_price = price
        self.last_change_volume = voldiff
        if typ == "ask":
            self._update_total_ask(voldiff)
            if len(self.asks):
                self.ask = self.asks[0].price
            self._valid_ask_cache = max(self._valid_ask_cache, index - 1)
        else:
            self._update_total_bid(voldiff, price)
            if len(self.bids):
                self.bid = self.bids[0].price
            self._valid_bid_cache = max(self._valid_bid_cache, index - 1)

        return True

    def _update_total_ask(self, volume):
        """update total volume of base currency on the ask side"""
        self.total_ask += self.gox.base2float(volume)

    def _update_total_bid(self, volume, price):
        """update total volume of quote currency on the bid side"""
        self.total_bid += \
            self.gox.base2float(volume) * self.gox.quote2float(price)

    def _update_level_own_volume(self, typ, price, own_volume):
        """update the own_volume cache in the Level object at price"""

        if price == 0:
            # market orders have price == 0, we don't add them
            # to the orderbook, own_volume is meant for limit orders.
            # Also a price level of 0 makes no sense anyways, this
            # would only insert empty rows at price=0 into the book
            return

        if (typ == "ask" and price <= self.bid) or \
           (typ == "bid" and price >= self.ask):
            # same as above for orders that would immediately fill
            # because price is on the other side of the book.
            # don't add these to the book too.
            return

        (index, level) = self._find_level_or_insert_new(typ, price)
        if level.volume == 0 and own_volume == 0:
            if typ == "ask":
                self.asks.pop(index)
            else:
                self.bids.pop(index)
        else:
            level.own_volume = own_volume

    def _find_level(self, typ, price):
        """find the level in the orderbook and return a triple
        (list, index, level) where list is a reference to the list,
        index is the index if its an exact match or the index of the next
        element if it was not found (can be used for inserting) and level
        is either a reference to the found level or None if not found."""
        lst = {"ask": self.asks, "bid": self.bids}[typ]
        comp = {"ask": lambda x, y: x < y, "bid": lambda x, y: x > y}[typ]
        low = 0
        high = len(lst)

        # binary search
        while low < high:
            mid = (low + high) // 2
            midval = lst[mid].price
            if comp(midval, price):
                low = mid + 1
            elif comp(price, midval):
                high = mid
            else:
                return (lst, mid, lst[mid])

        # not found, return insertion point (index of next higher level)
        return (lst, high, None)

    def _find_level_or_insert_new(self, typ, price):
        """find the Level() object in bids or asks or insert a new
        Level() at the correct position. Returns tuple (index, level)"""
        (lst, index, level) = self._find_level(typ, price)
        if level:
            return (index, level)

        # no exact match found, create new Level() and insert
        level = Level(price, 0)
        lst.insert(index, level)

        # invalidate the total volume cache at and beyond this level
        if typ == "ask":
            self._valid_ask_cache = max(self._valid_ask_cache, index - 1)
        else:
            self._valid_bid_cache = max(self._valid_bid_cache, index - 1)

        return (index, level)

    def get_own_volume_at(self, price, typ=None):
        """returns the sum of the volume of own orders at a given price. This
        method will not look up the cache in the bids or asks lists, it will
        use the authoritative data from the owns list bacause this method is
        also used to calculate these cached values in the first place."""
        volume = 0
        for order in self.owns:
            if order.price == price and (not typ or typ == order.typ):
                volume += order.volume
        return volume

    def have_own_oid(self, oid):
        """do we have an own order with this oid in our list already?"""
        for order in self.owns:
            if order.oid == oid:
                return True
        return False

    # pylint: disable=W0212
    def get_total_up_to(self, price, is_ask):
        """return a tuple of the total volume in coins and in fiat between top
        and this price. This will calculate the total on demand, it has a cache
        to not repeat the same calculations more often than absolutely needed"""
        if is_ask:
            lst = self.asks
            known_level = self._valid_ask_cache
            comp = lambda x, y: x < y
        else:
            lst = self.bids
            known_level = self._valid_bid_cache
            comp = lambda x, y: x > y

        # now first we need the list index of the level we are looking for or
        # if it doesn't match exactly the index of the level right before that
        # price, for this we do a quick binary search for the price
        low = 0
        high = len(lst)
        while low < high:
            mid = (low + high) // 2
            midval = lst[mid].price
            if comp(midval, price):
                low = mid + 1
            elif comp(price, midval):
                high = mid
            else:
                break
        if comp(price, midval):
            needed_level = mid - 1
        else:
            needed_level = mid

        # if the total volume at this level has been calculated
        # already earlier then we don't need to do anything further,
        # we can immediately return the cached value from that level.
        if needed_level <= known_level:
            lvl = lst[needed_level]
            return (lvl._cache_total_vol, lvl._cache_total_vol_quote)

        # we are still here, this means we must calculate and update
        # all totals in all levels between last_known and needed_level
        # after that is done we can return the total at needed_level.
        if known_level == -1:
            total = 0
            total_quote = 0
        else:
            total = lst[known_level]._cache_total_vol
            total_quote = lst[known_level]._cache_total_vol_quote

        mult_base = self.gox.mult_base
        for i in range(known_level, needed_level):
            that = lst[i+1]
            total += that.volume
            total_quote += that.volume * that.price / mult_base
            that._cache_total_vol = total
            that._cache_total_vol_quote = total_quote

        if is_ask:
            self._valid_ask_cache = needed_level
        else:
            self._valid_bid_cache = needed_level

        return (total, total_quote)

    def init_own(self, own_orders):
        """called by gox when the initial order list is downloaded,
        this will happen after connect or reconnect"""
        self.owns = []

        # also reset the own volume cache in bids and ass list
        for level in self.bids + self.asks:
            level.own_volume = 0

        if own_orders:
            for order in own_orders:
                if order["currency"] == self.gox.curr_quote \
                and order["item"] == self.gox.curr_base:
                    self._add_own(Order(
                        int(order["price"]["value_int"]),
                        int(order["amount"]["value_int"]),
                        order["type"],
                        order["oid"],
                        order["status"]
                    ))

        self.signal_changed(self, None)
        self.signal_owns_changed(self, None)

    def add_own(self, order):
        """called by gox when a new order has been acked
        after it has been submitted. This is a separate method because
        we need to fire the *_changed signals when this happens"""
        self._add_own(order)
        self.signal_changed(self, None)
        self.signal_owns_changed(self, None)

    def _add_own(self, order):
        """add order to the list of own orders. This method is used during
        initial download of complete order list and also when a new order
        is inserted after receiving the ack (after order/add)."""
        if not self.have_own_oid(order.oid):
            self.owns.append(order)

        # update own volume in that level:
        self._update_level_own_volume(
            order.typ,
            order.price,
            self.get_own_volume_at(order.price, order.typ)
        )
