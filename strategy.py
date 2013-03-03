"""
trading robot breadboard
"""

from goxtool import BaseObject

class Strategy(BaseObject):
    # pylint: disable=C0111,W0613,R0201

    def __init__(self, gox):
        BaseObject.__init__(self)
        self.signal_debug.connect(gox.slot_debug)
        gox.signal_ticker.connect(self.slot_tick)
        gox.signal_depth.connect(self.slot_depth)
        gox.signal_trade.connect(self.slot_trade)
        gox.signal_userorder.connect(self.slot_userorder)
        self.debug("### strategy loaded")

    def on_before_unload(self, gox):
        self.debug("### strategy will be unloaded")

    def on_key_b(self, gox):
        self.debug("### someone pressed the b key")        

    def on_key_s(self, gox):
        self.debug("### someone pressed the s key")


    def slot_tick(self, gox, (bid, ask)):
        pass

    def slot_depth(self, gox, (typ, price, volume, total_volume)):
        pass

    def slot_trade(self, gox, (date, price, volume, own)):
        pass

    def slot_userorder(self, gox, (price, volume, typ, oid, status)):
        pass

        
