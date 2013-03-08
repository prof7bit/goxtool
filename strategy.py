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
        gox.signal_ticker.connect(self.slot_tick)
        gox.signal_depth.connect(self.slot_depth)
        gox.signal_trade.connect(self.slot_trade)
        gox.signal_userorder.connect(self.slot_userorder)
        self.debug("### strategy loaded")

    def on_before_unload(self, gox):
        self.debug("### strategy will be unloaded")


    def slot_keypress(self, gox, (key)):
        self.debug("someone pressed the %s key" % chr(key))

    def slot_tick(self, gox, (bid, ask)):
        pass

    def slot_depth(self, gox, (typ, price, volume, total_volume)):
        pass

    def slot_trade(self, gox, (date, price, volume, typ, own)):
        pass

    def slot_userorder(self, gox, (price, volume, typ, oid, status)):
        pass


