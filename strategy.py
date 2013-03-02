"""
trading robot breadboard
"""

from goxtool import EventSource

class Strategy(EventSource):
    # pylint: disable=C0111,W0613,R0201

    def __init__(self, gox):
        EventSource.__init__(self)
        self.subscribe(self.EVT_DEBUG,      gox.on_debug)
        gox.subscribe(gox.EVT_TICKER,       self.on_tick)
        gox.subscribe(gox.EVT_DEPTH,        self.on_depth)
        gox.subscribe(gox.EVT_TRADE,        self.on_trade)
        gox.subscribe(gox.EVT_USERORDER,    self.on_user_order)
        self.debug("### strategy loaded")

    def on_before_unload(self, gox):
        self.debug("### strategy will be unloaded")

    

    def on_key_b(self, gox):
        self.debug("### someone pressed the b key")        

    def on_key_s(self, gox):
        self.debug("### someone pressed the s key")
        
    def on_tick(self, gox, (bid, ask)):
        pass

    def on_depth(self, gox, (typ, price, volume, total_volume)):
        pass

    def on_trade(self, gox, (date, price, volume, own)):
        pass

    def on_user_order(self, gox, (price, volume, typ, oid, status)):
        pass

        
