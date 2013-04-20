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
        gox.signal_wallet.connect(self.slot_wallet_changed)
        self.gox = gox
        self.name = "%s.%s" % \
            (self.__class__.__module__, self.__class__.__name__)
        self.debug("%s loaded" % self.name)

    def __del__(self):
        self.debug("%s unloaded" % self.name)

    def slot_before_unload(self, _sender, _data):
        self.debug("%s before unload" % self.name)

    def slot_keypress(self, gox, (key)):
        self.debug("someone pressed the %s key" % chr(key))

    def slot_tick(self, gox, (bid, ask)):
        pass

    def slot_depth(self, gox, (typ, price, volume, total_volume)):
        pass

    def slot_trade(self, gox, (date, price, volume, typ, own)):
        """a trade message has been received. Note that this might come
        before the orderbook.owns list has been updated, don't rely on the
        own orders and wallet already having been updated when this fires."""
        pass

    def slot_userorder(self, gox, (price, volume, typ, oid, status)):
        """this comes directly from the API and owns list might not yet be
        updated, if you need the new owns list then use slot_owns_changed"""
        pass

    def slot_owns_changed(self, orderbook, _dummy):
        """this comes *after* userorder and orderbook.owns is updated already"""
        pass

    def slot_wallet_changed(self, gox, _dummy):
        """this comes after the wallet has been updated"""
        pass
