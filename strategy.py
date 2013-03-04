"""
trading robot breadboard
"""

import goxapi

class Strategy(goxapi.BaseObject):
    # pylint: disable=C0111,W0613,R0201

    STEP = int(0.11 * 1E5)   #dollar
    RADIUS = 4 * STEP
    VOLUME = int(0.02 * 1E8)  #btc
    NUMORDERS = 13
        
    def __init__(self, gox):
        goxapi.BaseObject.__init__(self)
        self.signal_debug.connect(gox.slot_debug)
        gox.signal_ticker.connect(self.slot_tick)
        gox.signal_depth.connect(self.slot_depth)
        gox.signal_trade.connect(self.slot_trade)
        gox.signal_userorder.connect(self.slot_userorder)

        self.gridpos = 0
        self.lastask = 0
        self.lastbid = 0
        self.running = False
        
        self.debug("### strategy loaded")

    def on_before_unload(self, gox):
        self.debug("### strategy will be unloaded")


    def on_key_x(self, gox):
        self.debug("starting bot")
        self.running = True
        
    def on_key_y(self, gox):
        self.debug("stopping bot")
        self.running = False


    def on_key_b(self, gox):
        self.debug("### someone pressed the b key")        

    def on_key_s(self, gox):
        self.debug("### someone pressed the s key")

    # pylint: disable=R0912
    def slot_tick(self, gox, (bid, ask)):

        def round_step(price):
            return round(price / self.STEP) * self.STEP

        def have_this_order(price):
            for order in gox.orderbook.owns:
                if order.price == price:
                    return True
            return False

        def need_this_order(order):
            """can this order be canceled (too far away)?"""
            if abs(order.price - self.gridpos) \
            > self.RADIUS + self.NUMORDERS * self.STEP:
                return False
            return True

        def update_orders():
            sellprices = []
            buyprices = []
            for i in range(self.NUMORDERS):
                sellprices.append(self.gridpos + self.RADIUS + i * self.STEP)
                buyprices.append(self.gridpos - self.RADIUS - i * self.STEP)

            gox.debug(sellprices)
            gox.debug(buyprices)
            
            for price in sellprices:
                if not have_this_order(price):
                    gox.debug("S place new sell order at ", price) 
                    gox.sell(price, self.VOLUME)

            for price in buyprices:
                if not have_this_order(price):
                    gox.debug("B place new buy order at ", price)
                    gox.buy(price, self.VOLUME) 

            for order in gox.orderbook.owns:
                if not need_this_order(order):
                    gox.debug("C cancel old order at ", order.price)
                    gox.cancel(order.oid)

            gox.config.set("gridbot", "firstask", str(sellprices[0]))
            gox.config.save()
            
        def set_gridpos(price):
            changed = False
            while price >= self.gridpos + self.RADIUS:
                self.gridpos += self.STEP
                print "(+)",
                changed = True
            while price <= self.gridpos - self.RADIUS:
                self.gridpos -= self.STEP
                print "(-)",
                changed = True
            if changed:
                update_orders()

        def set_gridpos_ba(bid, ask):
            if self.lastask != ask:
                self.lastask = ask
                set_gridpos(ask)
                
            if self.lastbid != bid:
                self.lastbid = bid
                set_gridpos(bid)

        if self.running:
            firstask = int(float(gox.config.get_safe("gridbot", "firstask")))
            #inituialize only after restart
            if self.gridpos == 0:
                self.gridpos = round_step(firstask - self.RADIUS)
                update_orders()
                
            set_gridpos_ba(bid, ask)
        

    def slot_depth(self, gox, (typ, price, volume, total_volume)):
        pass

    def slot_trade(self, gox, (date, price, volume, own)):
        pass

    def slot_userorder(self, gox, (price, volume, typ, oid, status)):
        pass

        
