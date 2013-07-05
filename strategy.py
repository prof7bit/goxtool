"""
trading robot breadboard
"""

import goxapi

class Strategy(goxapi.BaseObject):
    # pylint: disable=C0111,W0613,R0201

    def __init__(self, gox):
        goxapi.BaseObject.__init__(self)
        self.signal_debug.connect(gox.signal_debug)
        gox.signal_keypress.connect(self.slot_keypress)
        gox.signal_strategy_unload.connect(self.slot_before_unload)
        gox.signal_ticker.connect(self.slot_tick)
        gox.signal_depth.connect(self.slot_depth)
        gox.signal_trade.connect(self.slot_trade)
        gox.signal_userorder.connect(self.slot_userorder)
        gox.orderbook.signal_owns_changed.connect(self.slot_owns_changed)
        gox.history.signal_changed.connect(self.slot_history_changed)
        gox.signal_wallet.connect(self.slot_wallet_changed)
        self.gox = gox
        self.name = "%s.%s" % \
            (self.__class__.__module__, self.__class__.__name__)
        self.debug("%s loaded" % self.name)

    def __del__(self):
        """the strategy object will be garbage collected now, this mainly
        only exists to produce the log message, so you can make sure it
        really garbage collects and won't stay in memory on reload. If you
        don't see this log mesage on reload then you have circular references"""
        self.debug("%s unloaded" % self.name)

    def slot_before_unload(self, _sender, _data):
        """the strategy is about to be unloaded. Use this signal to persist
        any state and also use it to forcefully destroy any circular references
        to allow it to be properly garbage collected (you might need to do
        this if you instantiated linked lists or similar structures, the
        symptom would be that you don't see the 'unloaded' message above."""
        pass

    def slot_keypress(self, gox, (key)):
        """a key in has been pressed (only a..z without "q" and "l")
        The argument key contains the ascii code. To react to a certain
        key use something like if key == ord('a')
        """
        pass

    def slot_tick(self, gox, (bid, ask)):
        """a tick message has been received from the streaming API"""
        pass

    def slot_depth(self, gox, (typ, price, volume, total_volume)):
        """a depth message has been received. Use this only if you want to
        keep track of the depth and orderbook updates yourself or if you
        for example want to log all depth messages to a database. This
        signal comes directly from the streaming API and the gox.orderbook
        might not yet be updated at this time."""
        pass

    def slot_trade(self, gox, (date, price, volume, typ, own)):
        """a trade message has been received. Note that this signal comes
        directly from the streaming API, it might come before orderbook.owns
        list has been updated, don't rely on the own orders and wallet already
        having been updated when this is fired."""
        pass

    def slot_userorder(self, gox, (price, volume, typ, oid, status)):
        """this comes directly from the API and owns list might not yet be
        updated, if you need the new owns list then use slot_owns_changed"""
        pass

    def slot_owns_changed(self, orderbook, _dummy):
        """this comes *after* userorder and orderbook.owns is updated already.
        Also note that this signal is sent by the orderbook object, not by gox,
        so the sender argument is orderbook and not gox. This signal might be
        useful if you want to detect whether an order has been filled, you
        count open orders, count pending orders and compare with last count"""
        pass

    def slot_wallet_changed(self, gox, _dummy):
        """this comes after the wallet has been updated. Access the new balances
        like so: gox.wallet[gox.curr_base] or gox.wallet[gox.curr_quote] and use
        gox.base2float() or gox.quote2float() if you need float values. You can
        also access balances from other currenies like gox.wallet["JPY"] but it
        is not guaranteed that they exist if you never had a balance in that
        particular currency. Always test for their existence first."""
        pass

    def slot_history_changed(self, history, _dummy):
        """this is fired whenever a new trade is inserted into the history,
        you can also use this to query the close price of the most recent
        candle which is effectvely the price of the last trade message.
        Contrary to the slot_trade this also fires when streaming API
        reconnects and re-downloads the trade history, you can use this
        to implement a stoploss or you could also use it for example to detect
        when a new candle is opened"""
        pass
