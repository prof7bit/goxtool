#!/usr/bin/env python

"""
Tool to display live MtGox market info and
framework for experimenting with trading bots
"""

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


# pylint: disable=C0302,R0903,R0903,R0913

import argparse
import base64
from ConfigParser import SafeConfigParser
from Crypto.Cipher import AES
import curses
import getpass
import hashlib
import hmac
import json
import logging
import os
import sys
import time
import traceback
import threading
import urllib
import urllib2
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

# pylint: disable=R0904
class GoxConfig(SafeConfigParser):
    """return a config parser object with default values"""
    
    _DEFAULTS = [["gox", "currency", "USD"]
                ,["gox", "use_ssl", "True"]
                ,["gox", "use_plain_old_websocket", "False"]
                ,["gox", "load_fulldepth", "True"]
                ,["gox", "load_history", "True"]
                ,["gox", "secret_key", ""]
                ,["gox", "secret_secret", ""]
                ]
    
    def __init__(self, filename):
        self.filename = filename
        SafeConfigParser.__init__(self)
        self.read(filename)
        for (sect, opt, default) in self._DEFAULTS:
            self._default(sect, opt, default)

    def save(self):
        """save the config file"""
        with open(self.filename, 'wb') as configfile:
            self.write(configfile)

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
            

class Secret:
    """Manage the MtGox API secret. This class has methods to decrypt the
    secret from the secret file and it also provides a method to create this
    encrypted file. The methods encrypt() and decrypt() will block and ask
    questions on the command line, they are called outside the curses
    environment (yes, its a quick and dirty hack but it works for now)."""
    key = ""
    secret = ""

    S_OK            = 0
    S_FAIL          = 1
    S_NO_SECRET     = 2
    S_FAIL_FATAL    = 3

    config = None

    def __init__(self, config):
        """initialize the instance"""
        self.config = config

    def decrypt(self, password):
        """decrypt the two lines of the secret file with the given password.
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


class EventSource():
    """can generate events to which observers can subscribe"""
    
    EVT_DEBUG = -1
    
    def __init__(self):
        """initialize a new EventSource instance"""
        self._observers = []
        self._lock = threading.RLock()
        
    def subscribe(self, event, function):
        """subscribe to event. function will be called with 2 parameters:
        the instance who created the event and data (usually a tuple of values
        whose exact struture depends on the sender and the kind of event)"""
        if not (event, function) in self._observers:
            self._observers.append((event, function))

    def unsubscribe(self, event, function):
        """ unsubscribe this function from this event"""
        for i in range(len(self._observers)):
            if self._observers[i] == (event, function):
                self._observers.pop(i)
                return

    def dispatch(self, event, data, sender=None):
        """dispatch the event to all its subscribed observers. The sender field
        will be set to self (the event source) unless a different sender is
        specified as the lat argument. This can be useful when passing through
        events from child objects to one's own subscribers."""
        with self._lock:
            delivered = False
            if not sender:
                sender = self
            for (evt, func) in self._observers:
                if evt == event:
                    try:
                        func(sender, data)
                        delivered = True
                        
                    # pylint: disable=W0703
                    except Exception:
                        err = "### error in '%s'-listener\n%s" \
                            % (func.__name__, traceback.format_exc())
                        if event == self.EVT_DEBUG:
                            logging.debug(err)
                        else:
                            self.debug(err)
                            
        return delivered

    def debug(self, *args):
        """send a string composed of all *args to the observers who
        are subscribed to the EVT_DEBUG event or print it to stdout if
        nobody is subscribed"""
        msg = " ".join([str(x) for x in args])
        if not self.dispatch(self.EVT_DEBUG, (msg)):
            print(msg)

class OHLCV():
    """represents a chart candle. tim is POSIX timestamp of open time,
    prices and volume are integers like in the other parts of the gox API"""
    
    tim  = 0
    opn  = 0
    hig  = 0
    low  = 0
    cls  = 0
    vol  = 0
    
    def __init__(self, tim, opn, hig, low, cls, vol):
        self.tim = tim
        self.opn = opn
        self.hig = hig
        self.low = low
        self.cls = cls
        self.vol = vol

    def update(self, price, volume):
        """update high and low values and add to volume"""
        if price > self.hig:
            self.hig = price
        if price < self.low:
            self.low = price
        self.cls = price
        self.vol += volume


class History(EventSource):
    """represents the trading history"""

    EVT_CHANGED = 0

    timeframe = 0 # seconds per candle
    candles = []
    
    def __init__(self, gox, timeframe):
        EventSource.__init__(self)
        self.gox = gox
        self.candles = []
        self.timeframe = timeframe
        gox.subscribe(gox.EVT_TRADE,        self.on_trade)
        gox.subscribe(gox.EVT_FULLHISTORY,  self.on_fullhistory)

    def add_candle(self, candle):
        """add a new candle to the history"""
        self._add_candle(candle)
        self.dispatch(self.EVT_CHANGED, (self.length()))

    def on_trade(self, dummy_sender, (date, price, volume, own)):
        """event handler for EVT_TRADE event"""
        if not own:
            time_round = int(date / self.timeframe) * self.timeframe
            candle = self.last_candle()
            if candle:
                if candle.tim == time_round:
                    candle.update(price, volume)
                    self.dispatch(self.EVT_CHANGED, (1))
                else:
                    self.debug("### opening new candle")
                    self.add_candle(OHLCV(
                        time_round, price, price, price, price, volume))
            else:
                self.add_candle(OHLCV(
                    time_round, price, price, price, price, volume))

    def _add_candle(self, candle):
        """add a new candle to the history but don't fire EVT_CHANGED event"""
        self.candles.insert(0, candle)

    def on_fullhistory(self, dummy_sender, (history)):
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
        self.dispatch(self.EVT_CHANGED, (self.length()))

    def last_candle(self):
        """return the last (current) candle or None if empty"""
        if self.length() > 0:
            return self.candles[0]
        else:
            return None

    def length(self):
        """return the number of candles in the history"""
        return len(self.candles)
        

class BaseClient(EventSource):
    """abstract base class for SocketIOClient and WebsocketClient"""

    currency = ""
    socket = None
    secret = None
    config = None
    
    EVT_RECV        = 0
    EVT_FULLDEPTH   = 1
    EVT_FULLHISTORY = 2

    SOCKETIO_HOST = "socketio.mtgox.com"
    WEBSOCKET_HOST = "websocket.mtgox.com"
    HTTP_HOST = "mtgox.com"
    
    def __init__(self, currency, secret, config):
        EventSource.__init__(self)
        self.currency = currency
        self.secret = secret
        self.config = config

    def start(self):
        """start the client"""
        start_thread(self._recv_thread)

    def send(self, json_str):
        """there exist 2 subtly different ways to send a string over a
        websocket. Each client class will override this send method"""
        raise NotImplementedError()

    def request_fulldepth(self):
        """start the fulldepth thread"""
        
        def fulldepth_thread():
            """request the full market depth, initialize the order book
            and then terminate. This is called in a separate thread after
            the streaming API has been connected."""
            self.debug("requesting initial full depth")
            fulldepth = urllib2.urlopen("https://" +  self.HTTP_HOST \
                + "/api/1/BTC" + self.currency + "/fulldepth")
            self.dispatch(self.EVT_FULLDEPTH, (json.load(fulldepth)))
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
                self.dispatch(self.EVT_FULLHISTORY, history["return"])

        start_thread(history_thread)
        
    def _recv_thread(self):
        """this will be executed as the main receiving thread, each type of
        client (websocket or socketio) will implement its own"""
        raise NotImplementedError()
        
    def channel_subscribe(self):
        """subscribe to the needed channels and alo initiate the
        download of the initial full market depth"""

        self.send(json.dumps({"op":"mtgox.subscribe", "type":"depth"}))
        self.send(json.dumps({"op":"mtgox.subscribe", "type":"trades"}))
        self.send(json.dumps({"op":"mtgox.subscribe", "type":"ticker"}))
        
        self.send_signed_call("private/info", {}, "info")
        self.send_signed_call("private/orders", {}, "orders")
        self.send_signed_call("private/idkey", {}, "idkey")
        
        # The very first signed call will sometimes fail (WTF???), sometimes
        # even the first two calls, so I just send everything twice until I
        # found out why. Requesting it twice won't hurt.
        self.send_signed_call("private/info", {}, "info")
        self.send_signed_call("private/orders", {}, "orders")
        self.send_signed_call("private/idkey", {}, "idkey")

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
    
    def _recv_thread(self):
        """connect to the webocket and tart receiving inan infinite loop.
        Try to reconnect whenever connection is lost. Each received json
        string will be dispatched as an EVT_RECV event"""
        use_ssl = self.config.get_bool("gox", "use_ssl")
        wsp = {True: "wss://", False: "ws://"}[use_ssl]
        while True:  #loop 0 (connect, reconnect)
            try:
                ws_url = wsp + self.WEBSOCKET_HOST \
                    + "/mtgox?Currency=" + self.currency
                self.debug("connecting websocket %s... " % ws_url)
                self.socket = websocket.create_connection(ws_url)
                
                self.debug("connected, subscribing needed channels")
                self.channel_subscribe()
                
                self.debug("waiting for data...")
                while True: #loop1 (read messages)
                    str_json = self.socket.recv()
                    if str_json[0] == "{":
                        self.dispatch(self.EVT_RECV, (str_json))
                    
                
            # pylint: disable=W0703
            except Exception as exc:
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
    
    def _recv_thread(self):
        """this is the main thread that is running all the time. It will
        connect and then read (blocking) on the socket in an infinite
        loop. SocketIO messages ('2::', etc.) are handled here immediately
        and all received json strings are dispathed a an EVT_RECV event."""
        use_ssl = self.config.get_bool("gox", "use_ssl")
        wsp = {True: "wss://", False: "ws://"}[use_ssl]
        htp = {True: "https://", False: "http://"}[use_ssl]
        while True:  #loop 0 (connect, reconnect)
            try:
                self.debug("connecting to %s... " % self.SOCKETIO_HOST \
                    + "(might take very loooooooong)")

                url = urllib2.urlopen(
                    htp + self.SOCKETIO_HOST + "/socket.io/1?Currency=" +
                    self.currency)
                params = url.read()
                url.close()
                
                ws_id = params.split(":")[0]
                ws_url = wsp + self.SOCKETIO_HOST + "/socket.io/1/websocket/" \
                     + ws_id + "?Currency=" + self.currency

                self.debug("trying websocket to %s" % ws_url)
                self.socket = websocket.create_connection(ws_url)
                
                self.debug("connected")
                self.socket.send("1::/mtgox")
                self.socket.recv() # '1::'
                self.socket.recv() # '1::/mtgox'

                self.debug("subscribing to channels")
                self.channel_subscribe()
                
                self.debug("waiting for data...")
                while True: #loop1 (read messages)
                    msg = self.socket.recv()
                    if msg == "2::":
                        self.debug("### ping -> pong")
                        self.socket.send("2::")
                        continue
                    prefix = msg[:10]
                    if prefix == "4::/mtgox:":
                        str_json = msg[10:]
                        if str_json[0] == "{":
                            self.dispatch(self.EVT_RECV, (str_json))
                            
            # pylint: disable=W0703
            except Exception as exc:
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
    

class Gox(EventSource):
    """represents the API of the MtGox exchange. An Instance of this
    class will connect to the streaming socket.io API, receive live
    events, can trigger own callback functions on all events, has
    methods to buy and sell"""
    
    EVT_DEPTH        = 0
    EVT_TRADE        = 1
    EVT_TICKER       = 2
    EVT_FULLDEPTH    = 3
    EVT_FULLHISTORY  = 4
    EVT_WALLET       = 5
    EVT_USERORDER    = 6
    
    wallet = {}
    currency    = ""

    client          = None
    orderbook       = None
    config          = None
    history         = None

    _got_idkey      = False

    def __init__(self, secret, config):
        """initialize the gox API but do not yet connect to it.
        currency is the 3-letter symbol denoting the currency
        (for example 'USD' or 'JPY') to be traded"""
        EventSource.__init__(self)
        self.config = config
        self.currency = config.get("gox", "currency", "USD")
        
        self.history = History(self, 60 * 15)
        self.history.subscribe(self.history.EVT_DEBUG,      self.on_debug)
        
        self.orderbook = OrderBook(self)
        self.orderbook.subscribe(self.orderbook.EVT_DEBUG,  self.on_debug)
        
        if self.config.get_bool("gox", "use_plain_old_websocket"):
            self.client = WebsocketClient(self.currency, secret, config)
        else:
            self.client = SocketIOClient(self.currency, secret, config)
        self.client.subscribe(self.client.EVT_DEBUG,        self.on_debug)
        self.client.subscribe(self.client.EVT_RECV,         self.on_recv)
        self.client.subscribe(self.client.EVT_FULLDEPTH,    self.on_fulldepth)
        self.client.subscribe(self.client.EVT_FULLHISTORY,  self.on_fullhistory)
    
    def start(self):
        """connect to MtGox and start receiving events."""
        self.debug("starting gox streaming API, currency=" + self.currency)
        self.client.start()

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
            self.dispatch(self.EVT_USERORDER,
                (price, volume, typ, res["return"], "pending"))
            return(res["return"])
        else:
            self.debug("### WTF??? order could not be placed!")
            return ""

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
            self.dispatch(self.EVT_USERORDER,
                (0, 0, "", res["return"], "removed"))
            return True
        else:
            self.debug("### WTF??? order could not be canceled!")
            return False

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

    def on_debug(self, sender, data):
        """pass through the debug messages from child objects"""
        self.dispatch(self.EVT_DEBUG, data, sender)

    def on_fulldepth(self, sender, data):
        """pass through the fulldepth event from the client"""
        self.dispatch(self.EVT_FULLDEPTH, data, sender)

    def on_fullhistory(self, sender, data):
        """event handler for EVT_FULLHISTORY"""
        self.dispatch(self.EVT_FULLHISTORY, data, sender)
    
    def on_recv(self, dummy_sender, (str_json)):
        """Event handler for EVT_RECV, handle new incoming
        JSON message. Decode the JSON string into a Python object
        and dispatch it to the method that can handle it."""
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

        # pylint: disable=W0703
        except Exception:
            self.debug(traceback.format_exc())

    def _on_tick(self, msg):
        """handle incoming ticker message"""
        msg = msg["ticker"]
        if msg["sell"]["currency"] != self.currency:
            return
        ask = int(msg["sell"]["value_int"])
        bid = int(msg["buy"]["value_int"])
        
        self.debug(" tick:  bid:", int2str(bid, self.currency),
            "ask:", int2str(ask, self.currency))
        self.dispatch(self.EVT_TICKER, (bid, ask))
    
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
        self.dispatch(self.EVT_DEPTH, (type_str, price, volume, total_volume))
    
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
        
        self.debug(
            "trade:      ", int2str(price, self.currency),
            "vol:", int2str(volume, "BTC"))
        self.dispatch(self.EVT_TRADE, (date, price, volume, own))

    def _on_call_result(self, msg):
        """handle result of authenticated API call"""
        result = msg["result"]
        reqid = msg["id"]

        if reqid == "idkey":
            self.debug("### got key, subscribing to account messages")
            self._got_idkey = True
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
            self.dispatch(self.EVT_WALLET, ())
            return

        if reqid == "order_add":
            self.debug(result)

        if reqid == "order_cancel":
            self.debug(result)

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
                self.dispatch(self.EVT_USERORDER,
                    (price, volume, typ, oid, status))

        else: # removed (filled or canceled)
            self.dispatch(self.EVT_USERORDER, (0, 0, "", oid, "removed"))

    def _on_wallet(self, dummy_msg):
        """handle incoming wallet message"""
        # I am lazy, just sending a new info request,
        # so it will update automatically.
        self.client.send_signed_call("private/info", {}, "info")



class Order:
    """represents an order in the orderbook"""

    price   = 0
    volume  = 0
    typ     = ""
    oid     = ""
    status  = ""

    def __init__(self, price, volume, typ, oid="", status=""):
        """initialize a new order object"""
        self.price = price
        self.volume = volume
        self.typ = typ
        self.oid = oid
        self.status = status


class OrderBook(EventSource):
    """represents the orderbook. Each Gox instance has one
    instance of OrderBook to maintain the open orders. This also
    maintains a list of own orders belonging to this account"""

    EVT_CHANGED = 0
    
    bids = [] # list of Order(), lowest ask first
    asks = [] # list of Order(), highest bid first
    owns = [] # list of Order(), unordered list

    bid = 0
    ask = 0
    
    def __init__(self, gox):
        """create a new empty orderbook and associate it with its
        Gox instance"""
        EventSource.__init__(self)
        self.gox = gox
        gox.subscribe(gox.EVT_TICKER,       self.on_tick)
        gox.subscribe(gox.EVT_DEPTH,        self.on_depth)
        gox.subscribe(gox.EVT_TRADE,        self.on_trade)
        gox.subscribe(gox.EVT_USERORDER,    self.on_user_order)
        gox.subscribe(gox.EVT_FULLDEPTH,    self.on_fulldepth)
    
    def on_tick(self, dummy_sender, (bid, ask)):
        """handler for EVT_TICKER event, incoming ticker message"""
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
            self.dispatch(self.EVT_CHANGED, ())

    def on_depth(self, dummy_sender, (typ, price, dummy_voldiff, total_vol)):
        """handler for EVT_DEPTH event, process incoming depth message"""
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
        self.dispatch(self.EVT_CHANGED, ())
        
    def on_trade(self, dummy_sender, (dummy_date, price, volume, own)):
        """handler for EVT_TRADE event, process incoming trade messages.
        For trades that also affect own orders this will be called twice:
        once during the normal public trade message, affecting the public
        bids and asks and then another time with own=True to update our
        own orders list"""
        
        def update_list(lst, price, volume):
            """find the order in the list and update or remove it."""
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
            update_list(self.asks, price, volume)
            update_list(self.bids, price, volume)
            if len(self.asks):
                self.ask = self.asks[0].price
            if len(self.bids):
                self.bid = self.bids[0].price
            
        self.dispatch(self.EVT_CHANGED, ())


    def on_user_order(self, dummy_sender, (price, volume, typ, oid, status)):
        """handler for EVT_USERORDER, process incoming user_order mesage"""
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

        self.dispatch(self.EVT_CHANGED, ())

    def on_fulldepth(self, dummy_sender, (depth)):
        """handler for EVT_FULLDEPTH event, process received fulldepth data.
        This will clear the book and then re-initialize it from scratch."""
        self.debug("### got full depth: beginning update of orderbook...")
        self.bids = []
        self.asks = []
        for order in depth["return"]["asks"]:
            price = int(order["price_int"])
            volume = int(order["amount_int"])
            self.asks.append(Order(price, volume, "ask"))
        for order in depth["return"]["bids"]:
            price = int(order["price_int"])
            volume = int(order["amount_int"])
            self.bids.insert(0, Order(price, volume, "bid"))
            
        self.dispatch(self.EVT_CHANGED, ())
        self.debug("### got full depth: complete.")

    def reset_own(self):
        """clear all own orders"""
        self.owns = []
        self.dispatch(self.EVT_CHANGED, ())

    def add_own(self, order):
        """add order to the list of own orders. This method is used
        by the Gox object only during initial download of complete
        order list, all subsequent updates will then be done through
        the event methods on_user_order and on_trade"""
        self.owns.append(order)
        self.dispatch(self.EVT_CHANGED, ())


#
#
# curses user interface
#

HEIGHT_STATUS   = 2
HEIGHT_CON      = 7
WIDTH_ORDERBOOK = 44

COLORS =    [["con_text",    curses.COLOR_BLUE,    curses.COLOR_CYAN]
            ,["status_text", curses.COLOR_BLUE,    curses.COLOR_CYAN]
            
            ,["book_text",   curses.COLOR_BLACK,   curses.COLOR_BLUE]
            ,["book_bid",    curses.COLOR_BLACK,   curses.COLOR_GREEN]
            ,["book_ask",    curses.COLOR_BLACK,   curses.COLOR_RED]
            ,["book_own",    curses.COLOR_BLACK,   curses.COLOR_YELLOW]
            ,["book_vol",    curses.COLOR_BLACK,   curses.COLOR_BLUE]
            
            ,["chart_text",  curses.COLOR_BLACK,   curses.COLOR_CYAN]
            ,["chart_up",    curses.COLOR_BLACK,   curses.COLOR_GREEN]
            ,["chart_down",  curses.COLOR_BLACK,   curses.COLOR_RED]
            ]
            
COLOR_PAIR = {}

def init_colors():
    """initialize curses color pairs and give them names. The color pair
    can then later quickly be retrieved from the COLOR_PAIR[] dict"""
    index = 1
    for (name, back, fore) in COLORS:
        curses.init_pair(index, fore, back)
        COLOR_PAIR[name] = curses.color_pair(index)
        index += 1

class Win:
    """represents a curses window"""
    # pylint: disable=R0902
    
    posx = 0
    posy = 0
    width = 10
    height = 10
    termwidth = 10
    termheight = 10
    win = None
    
    def __init__(self, stdscr):
        """create and initialize the window. This will also subsequently
        call the paint() method."""
        self.stdscr = stdscr
        self.__create_win()

    def calc_size(self):
        """override this method to change posx, posy, width, height.
        It will be called before window creation and on resize."""
        pass
        
    def paint(self):
        """paint the window. Override this with your own implementation.
        This method must paint the entire window contents from scratch.
        It is automatically called after the window has been initially
        created and also after every resize. Call it explicitly when
        your data has changed and must be displayed"""
        self.win.touchwin()
        self.win.refresh()

    def resize(self):
        """You must call this method from your main loop when the
        terminal has been resized. It will subsequently make it
        recalculate its own new size and then call its paint() method"""
        del self.win
        self.__create_win()
        
    def __create_win(self):
        """create the window. This will also be called on every resize,
        windows won't be moved, they will be deleted and recreated."""
        self.__calc_size()
        self.win = curses.newwin(self.height, self.width, self.posy, self.posx)
        self.win.scrollok(True)
        self.paint()

    def __calc_size(self):
        """calculate the default values for positionand size. By default
        this will result in a window covering the entire terminal.
        Implement the calc_size() method (which will be called afterwards)
        to change (some of) these values according to your needs."""
        maxyx = self.stdscr.getmaxyx()
        self.termwidth = maxyx[1]
        self.termheight = maxyx[0]
        self.posx = 0
        self.posy = 0
        self.width = self.termwidth
        self.height = self.termheight
        self.calc_size()


class WinConsole(Win):
    """The console window at the bottom"""
    def __init__(self, stdscr, gox):
        """create the console window and connect it to the Gox debug
        callback function"""
        self.gox = gox
        gox.subscribe(gox.EVT_DEBUG,    self.on_debug)
        Win.__init__(self, stdscr)
        
    def paint(self):
        """just empty the window after resize (I am lazy)"""
        self.win.bkgd(" ", COLOR_PAIR["con_text"])
        self.win.refresh()

    def resize(self):
        """resize and print a log message. Old messages will have been
        lost after resize because of my dumb paint() implementation, so
        at least print a message indicating that fact into the
        otherwise now empty console window"""
        Win.resize(self)
        self.write("### console has been resized")
        
    def calc_size(self):
        """put it at the bottom of the screen"""
        self.height = HEIGHT_CON
        self.posy = self.termheight - self.height

    def on_debug(self, dummy_gox, (txt)):
        """this event handler will be subscribed to all debug events."""
        self.write(txt)
        
    def write(self, txt):
        """write a line of text, scroll if needed"""
        self.win.addstr("\n" + txt,  COLOR_PAIR["con_text"])
        self.win.refresh()


class WinOrderBook(Win):
    """the orderbook window"""
    
    def __init__(self, stdscr, gox):
        """create the orderbook window and connect it to the
        onChanged callback of the gox.orderbook instance"""
        self.gox = gox
        gox.orderbook.subscribe(gox.orderbook.EVT_CHANGED, self.on_changed)
        Win.__init__(self, stdscr)
        
    def calc_size(self):
        """put it into the middle left side"""
        self.height = self.termheight - HEIGHT_CON - HEIGHT_STATUS
        self.posy = HEIGHT_STATUS
        self.width = WIDTH_ORDERBOOK

    def paint(self):
        """paint the visible portion of the orderbook"""
        self.win.bkgd(" ",  COLOR_PAIR["book_text"])
        self.win.erase()
        mid = self.height / 2
        col_bid = COLOR_PAIR["book_bid"]
        col_ask = COLOR_PAIR["book_ask"]
        col_vol = COLOR_PAIR["book_vol"]
        col_own = COLOR_PAIR["book_own"]
        
        # print the asks
        # pylint: disable=C0301
        book = self.gox.orderbook
        pos = mid - 1
        i = 0
        cnt = len(book.asks)
        while pos >= 0 and  i < cnt:
            self.win.addstr(pos, 0,  int2str(book.asks[i].price, book.gox.currency), col_ask)
            self.win.addstr(pos, 12, int2str(book.asks[i].volume, "BTC"), col_vol)
            ownvol = 0
            for order in book.owns:
                if order.price == book.asks[i].price:
                    ownvol += order.volume
            if ownvol:
                self.win.addstr(pos, 28, int2str(ownvol, "BTC"), col_own)
            pos -= 1
            i += 1

        # print the bids
        pos = mid + 1
        i = 0
        cnt = len(book.bids)
        while pos < self.height and  i < cnt:
            self.win.addstr(pos, 0,  int2str(book.bids[i].price, book.gox.currency), col_bid)
            self.win.addstr(pos, 12, int2str(book.bids[i].volume, "BTC"), col_vol)
            ownvol = 0
            for order in book.owns:
                if order.price == book.bids[i].price:
                    ownvol += order.volume
            if ownvol:
                self.win.addstr(pos, 28, int2str(ownvol, "BTC"), col_own)
            pos += 1
            i += 1

        self.win.refresh()


    def on_changed(self, dummy_gox, dummy_data):
        """event handler for orderbook.EVT_CHANGED"""
        self.paint()


class WinChart(Win):
    """the chart window"""

    pmin = 0
    pmax = 0
    
    def __init__(self, stdscr, gox):
        self.gox = gox
        gox.history.subscribe(gox.history.EVT_CHANGED, self.on_hist_changed)
        gox.orderbook.subscribe(gox.orderbook.EVT_CHANGED, self.on_book_changed)
        Win.__init__(self, stdscr)

    def calc_size(self):
        """position in the middle, right to the orderbook"""
        self.posx = WIDTH_ORDERBOOK
        self.posy = HEIGHT_STATUS
        self.width = self.termwidth - WIDTH_ORDERBOOK
        self.height = self.termheight - HEIGHT_CON - HEIGHT_STATUS

    def is_in_range(self, price):
        """is this price in the currently viible range?"""
        return price <= self.pmax and price >= self.pmin
        
    def price_to_screen(self, price):
        """convert price into screen coordinates (y=0 is at the top!)"""
        relative_from_bottom = \
            float(price - self.pmin) / float(self.pmax - self.pmin)
        screen_from_bottom = relative_from_bottom * self.height
        return int(self.height - screen_from_bottom)
        
    def addstr_safe(self, posy, posx, character, color_pair):
        """place a character but don't throw error in lower right corner"""
        try:
            self.win.addstr(posy, posx, character, color_pair)

        # pylint: disable=W0702
        except:
            pass
            
    def paint_candle(self, posx, candle):
        """paint a single candle"""
        sopen  = self.price_to_screen(candle.opn)
        shigh  = self.price_to_screen(candle.hig)
        slow   = self.price_to_screen(candle.low)
        sclose = self.price_to_screen(candle.cls)

        for posy in range(self.height):
            if posy >= shigh and posy < sopen and posy < sclose:
                # upper wick
                self.addstr_safe(posy, posx, "|", COLOR_PAIR["chart_text"])
            if posy >= sopen and posy < sclose:
                # red body
                self.addstr_safe(posy, posx, "#", COLOR_PAIR["chart_down"])
            if posy >= sclose and posy < sopen:
                # green body
                self.addstr_safe(posy, posx, "#", COLOR_PAIR["chart_up"])
            if posy >= sopen and posy >= sclose and posy < slow:
                # lower wick
                self.addstr_safe(posy, posx, "|", COLOR_PAIR["chart_text"])
    
    def paint(self):
        """paint the visible portion of the chart"""

        
        self.win.bkgd(" ",  COLOR_PAIR["chart_text"])
        self.win.erase()
        
        hist = self.gox.history
        book = self.gox.orderbook
        
        self.pmax = 0
        self.pmin = 9999999999

        # determine y range
        posx = self.width - 2
        index = 0
        while index < hist.length() and posx >= 0:
            candle = hist.candles[index]
            if self.pmax < candle.hig:
                self.pmax = candle.hig
            if self.pmin > candle.low:
                self.pmin = candle.low
            index += 1
            posx -= 1

        if self.pmax == self.pmin:
            return

        # paint the candles
        posx = self.width - 2
        index = 0
        while index < hist.length() and posx >= 0:
            candle = hist.candles[index]
            self.paint_candle(posx, candle)
            index += 1
            posx -= 1

        # paint bid, ask, own orders
        posx = self.width - 1
        for order in book.owns:
            if self.is_in_range(order.price):
                posy = self.price_to_screen(order.price)
                self.addstr_safe(posy, posx, "o", COLOR_PAIR["chart_text"])
                
        if self.is_in_range(book.bid):
            posy = self.price_to_screen(book.bid)
            self.addstr_safe(posy, posx, "-", COLOR_PAIR["chart_up"])
            
        if self.is_in_range(book.ask):
            posy = self.price_to_screen(book.ask)
            self.addstr_safe(posy, posx, "-", COLOR_PAIR["chart_down"])

        self.win.refresh()
        
    def on_hist_changed(self, dummy_history, (dummy_cnt)):
        """event handler for history.EVT_CHANGED"""
        self.paint()
        
    def on_book_changed(self, dummy_book, dummy_data):
        """event handler for orderbook.EVT_CHANGED"""
        self.paint()


class WinStatus(Win):
    """the status window at the top"""
    def __init__(self, stdscr, gox):
        """create the status window and connect the needed callbacks"""
        self.gox = gox
        gox.subscribe(gox.EVT_WALLET, self.on_status_changed)
        Win.__init__(self, stdscr)
        
    def calc_size(self):
        """place it at the top of the terminal"""
        self.height = HEIGHT_STATUS

    def paint(self):
        """paint the complete status"""
        self.win.bkgd(" ", COLOR_PAIR["status_text"])
        self.win.erase()
        line1 = "Currency: " + self.gox.currency + " | "
        line1 += "Account: "
        if len(self.gox.wallet):
            for currency in self.gox.wallet:
                line1 += currency + " " \
                + int2str(self.gox.wallet[currency], currency).strip() \
                + " + "
            line1 = line1.strip(" +")
        else:
            line1 += "No info (yet)"
        self.win.addstr(0, 0, line1, COLOR_PAIR["status_text"])
        self.win.refresh()

    def on_status_changed(self, dummy_sender, dummy_data):
        """the callback funtion called by the Gox() instance"""
        self.paint()


#
#
# logging
#

def log_debug(sender, (msg)):
    """event handler for EVT_DEBUG events"""
    logging.debug("%s:%s", sender.__class__.__name__, msg)

def logging_init(gox):
    """initialize logger and subscribe to EVT_DEBUG events"""
    logging.basicConfig(filename='goxtool.log'
                       ,filemode='w'
                       ,format='%(asctime)s:%(levelname)s:%(message)s'
                       ,level=logging.DEBUG
                       )
    gox.subscribe(gox.EVT_DEBUG, log_debug)


#
#
# dynamically (re)loadable strategy module
#

class StrategyManager():
    """load the strategy module"""
    
    def __init__(self, gox):
        self.strategy = None
        self.gox = gox
        self.reload()

    def reload(self):
        """reload and re-initialize the strategy module"""
        import strategy
        try:
            if self.strategy:
                self.strategy.on_before_unload(self.gox)
            reload(strategy)
            self.strategy = strategy.Strategy(self.gox)
        
        # pylint: disable=W0703
        except Exception:
            self.gox.debug(traceback.format_exc())

    def call_key(self, key):
        """try to call the on_key_* method in the strategymodule if it exists"""
        try:
            method = getattr(self.strategy, "on_key_%s" % key)
            try:
                method(self.gox)
                
            # pylint: disable=W0703
            except Exception:
                self.gox.debug(traceback.format_exc())
            
        except AttributeError:
            self.gox.debug("### no handler defined for key: '%s'" % key)


#
#
# main program (yes, its really only a few lines ;-)
#

def main():
    """main funtion, called from within the curses.wrapper"""
    
    def curses_loop(stdscr):
        """This code runs within curses environment"""
        init_colors()
        
        gox = Gox(secret, config)
        
        conwin = WinConsole(stdscr, gox)
        bookwin = WinOrderBook(stdscr, gox)
        statuswin = WinStatus(stdscr, gox)
        chartwin = WinChart(stdscr, gox)

        logging_init(gox)
        strategy_manager = StrategyManager(gox)

        gox.start()
        while True:
            key = conwin.win.getch()
            if key == ord("q"):
                break
            if key == curses.KEY_RESIZE:
                stdscr.erase()
                stdscr.refresh()
                conwin.resize()
                bookwin.resize()
                chartwin.resize()
                statuswin.resize()
                continue
            if key == ord("l"):
                strategy_manager.reload()
                continue
            if key > ord("a") and key < ord("z"):
                strategy_manager.call_key(chr(key))

        # shutdown; no more ugly tracebacks from here on
        sys.excepthook = lambda x, y, z: None


    # before we can finally start the curses UI we might need to do some user
    # interaction on the command line, regarding the encrypted secret
    argp = argparse.ArgumentParser(description='MtGox live market data tool')
    argp.add_argument('--add-secret', action= "store_true",
        help="prompt for API secret, encrypt it and then exit")
    argp.add_argument('--lint', action= "store_true",
        help="run pychecker and pylint on all source code and then exit")
    args = argp.parse_args()

    config = GoxConfig("goxtool.ini")
    secret = Secret(config)
    if args.add_secret:
        secret.prompt_encrypt()
    elif args.lint:
        lint()
    else:
        if secret.prompt_decrypt() != secret.S_FAIL_FATAL:
            curses.wrapper(curses_loop)
            print
            print "*******************************************************"
            print "*  Please donate: 1D7ELjGofBiRUJNwK55DVC3XWYjfN77CA3  *"
            print "*******************************************************"


def lint():
    """run pychecker and pylint on the sources of this program. Most of
    the problems are found by pylint, a few additional things by pychecker"""
    files = "goxtool.py strategy*.py"
    os.system("pychecker \
        --limit=100 \
        --quiet \
        --no-argsused \
        --blacklist=ConfigParser \
        %s" % files)
    os.system("pylint \
        --output-format=parseable \
        --include-ids=y \
        --disable=I0011 \
        --reports=n \
        %s 2>/dev/null" % files)


if __name__ == "__main__":
    main()
