#!/usr/bin/env python2

"""
Tool to display live MtGox market info and
framework for experimenting with trading bots
"""
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

# pylint: disable=C0301,C0302,R0902,R0903,R0912,R0913,R0914,R0915,R0922,W0703

import argparse
import curses
import curses.panel
import curses.textpad
import goxapi
import logging
import locale
import math
import os
import sys
import time
import traceback
import threading

sys_out = sys.stdout #pylint: disable=C0103

#
#
# curses user interface
#

HEIGHT_STATUS   = 2
HEIGHT_CON      = 7
WIDTH_ORDERBOOK = 45

COLORS =    [["con_text",       curses.COLOR_BLUE,    curses.COLOR_CYAN]
            ,["con_text_buy",   curses.COLOR_BLUE,    curses.COLOR_GREEN]
            ,["con_text_sell",  curses.COLOR_BLUE,    curses.COLOR_RED]
            ,["status_text",    curses.COLOR_BLUE,    curses.COLOR_CYAN]

            ,["book_text",      curses.COLOR_BLACK,   curses.COLOR_CYAN]
            ,["book_bid",       curses.COLOR_BLACK,   curses.COLOR_GREEN]
            ,["book_ask",       curses.COLOR_BLACK,   curses.COLOR_RED]
            ,["book_own",       curses.COLOR_BLACK,   curses.COLOR_YELLOW]
            ,["book_vol",       curses.COLOR_BLACK,   curses.COLOR_CYAN]

            ,["chart_text",     curses.COLOR_BLACK,   curses.COLOR_WHITE]
            ,["chart_up",       curses.COLOR_BLACK,   curses.COLOR_GREEN]
            ,["chart_down",     curses.COLOR_BLACK,   curses.COLOR_RED]
            ,["order_pending",  curses.COLOR_BLACK,   curses.COLOR_RED]

            ,["dialog_text",     curses.COLOR_BLUE,   curses.COLOR_CYAN]
            ,["dialog_sel",      curses.COLOR_CYAN,   curses.COLOR_BLUE]
            ,["dialog_sel_text", curses.COLOR_BLUE,   curses.COLOR_YELLOW]
            ,["dialog_sel_sel",  curses.COLOR_YELLOW, curses.COLOR_BLUE]
            ,["dialog_bid_text", curses.COLOR_GREEN,  curses.COLOR_BLACK]
            ,["dialog_ask_text", curses.COLOR_RED,    curses.COLOR_WHITE]
            ]

INI_DEFAULTS =  [["goxtool", "set_xterm_title", "True"]
                ,["goxtool", "dont_truncate_logfile", "False"]
                ,["goxtool", "show_orderbook_stats", "True"]
                ,["goxtool", "highlight_changes", "True"]
                ,["goxtool", "orderbook_group", "0"]
                ,["goxtool", "orderbook_sum_total", "False"]
                ,["goxtool", "display_right", "history_chart"]
                ,["goxtool", "depth_chart_group", "1"]
                ,["goxtool", "depth_chart_sum_total", "True"]
                ,["goxtool", "show_ticker", "True"]
                ,["goxtool", "show_depth", "True"]
                ,["goxtool", "show_trade", "True"]
                ,["goxtool", "show_trade_own", "True"]
                ]

COLOR_PAIR = {}

def init_colors():
    """initialize curses color pairs and give them names. The color pair
    can then later quickly be retrieved from the COLOR_PAIR[] dict"""
    index = 1
    for (name, back, fore) in COLORS:
        if curses.has_colors():
            curses.init_pair(index, fore, back)
            COLOR_PAIR[name] = curses.color_pair(index)
        else:
            COLOR_PAIR[name] = 0
        index += 1

def dump_all_stacks():
    """dump a stack trace for all running threads for debugging purpose"""

    def get_name(thread_id):
        """return the human readable name that was assigned to a thread"""
        for thread in threading.enumerate():
            if thread.ident == thread_id:
                return thread.name

    ret = "\n# Full stack trace of all running threads:\n"
    #pylint: disable=W0212
    for thread_id, stack in sys._current_frames().items():
        ret += "\n# %s (%s)\n" % (get_name(thread_id), thread_id)
        for filename, lineno, name, line in traceback.extract_stack(stack):
            ret += 'File: "%s", line %d, in %s\n' % (filename, lineno, name)
            if line:
                ret += "  %s\n" % (line.strip())
    return ret

def try_get_lock_or_break_open():
    """this is an ugly hack to workaround possible deadlock problems.
    It is used during shutdown to make sure we can properly exit even when
    some slot is stuck (due to a programming error) and won't release the lock.
    If we can't acquire it within 2 seconds we just break it open forcefully."""
    #pylint: disable=W0212
    time_end = time.time() + 2
    while time.time() < time_end:
        if goxapi.Signal._lock.acquire(False):
            return
        time.sleep(0.001)

    # something keeps holding the lock, apparently some slot is stuck
    # in an infinite loop. In order to be able to shut down anyways
    # we just throw away that lock and replace it with a new one
    lock = threading.RLock()
    lock.acquire()
    goxapi.Signal._lock = lock
    print "### could not acquire signal lock, frozen slot somewhere?"
    print "### please see the stacktrace log to determine the cause."

class Win:
    """represents a curses window"""
    # pylint: disable=R0902

    def __init__(self, stdscr):
        """create and initialize the window. This will also subsequently
        call the paint() method."""
        self.stdscr = stdscr
        self.posx = 0
        self.posy = 0
        self.width = 10
        self.height = 10
        self.termwidth = 10
        self.termheight = 10
        self.win = None
        self.panel = None
        self.__create_win()

    def __del__(self):
        del self.panel
        del self.win
        curses.panel.update_panels()
        curses.doupdate()

    def calc_size(self):
        """override this method to change posx, posy, width, height.
        It will be called before window creation and on resize."""
        pass

    def do_paint(self):
        """call this if you want the window to repaint itself"""
        curses.curs_set(0)
        if self.win:
            self.paint()
            self.done_paint()

    # method could be a function - pylint: disable=R0201
    def done_paint(self):
        """update the sreen after paint operations, this will invoke all
        necessary stuff to refresh all (possibly overlapping) windows in
        the right order and then push it to the screen"""
        curses.panel.update_panels()
        curses.doupdate()

    def paint(self):
        """paint the window. Override this with your own implementation.
        This method must paint the entire window contents from scratch.
        It is automatically called after the window has been initially
        created and also after every resize. Call it explicitly when
        your data has changed and must be displayed"""
        pass

    def resize(self):
        """You must call this method from your main loop when the
        terminal has been resized. It will subsequently make it
        recalculate its own new size and then call its paint() method"""
        del self.win
        self.__create_win()

    def addstr(self, *args):
        """drop-in replacement for addstr that will never raie exceptions
        and that will cut off at end of line instead of wrapping"""
        if len(args) > 0:
            line, col = self.win.getyx()
            string = args[0]
            attr = 0
        if len(args) > 1:
            attr = args[1]
        if len(args) > 2:
            line, col, string = args[:3]
            attr = 0
        if len(args) > 3:
            attr = args[3]
        if line >= self.height:
            return
        space_left = self.width - col - 1 #always omit last column, avoids problems.
        if space_left <= 0:
            return
        self.win.addstr(line, col, string[:space_left], attr)

    def addch(self, posy, posx, character, color_pair):
        """place a character but don't throw error in lower right corner"""
        if posy < 0 or posy > self.height - 1:
            return
        if posx < 0 or posx > self.width - 1:
            return
        if posx == self.width - 1 and posy == self.height - 1:
            return
        self.win.addch(posy, posx, character, color_pair)

    def __create_win(self):
        """create the window. This will also be called on every resize,
        windows won't be moved, they will be deleted and recreated."""
        self.__calc_size()
        try:
            self.win = curses.newwin(self.height, self.width, self.posy, self.posx)
            self.panel = curses.panel.new_panel(self.win)
            self.win.scrollok(True)
            self.win.keypad(1)
            self.do_paint()
        except:
            self.win = None
            self.panel = None

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
        gox.signal_debug.connect(self.slot_debug)
        Win.__init__(self, stdscr)

    def paint(self):
        """just empty the window after resize (I am lazy)"""
        self.win.bkgd(" ", COLOR_PAIR["con_text"])

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

    def slot_debug(self, dummy_gox, (txt)):
        """this slot will be connected to all debug signals."""
        self.write(txt)

    def write(self, txt):
        """write a line of text, scroll if needed"""
        if not self.win:
            return

        # This code would break if the format of
        # the log messages would ever change!
        if " tick:" in txt:
            if not self.gox.config.get_bool("goxtool", "show_ticker"):
                return
        if "depth:" in txt:
            if not self.gox.config.get_bool("goxtool", "show_depth"):
                return
        if "trade:" in txt:
            if "own order" in txt:
                if not self.gox.config.get_bool("goxtool", "show_trade_own"):
                    return
            else:
                if not self.gox.config.get_bool("goxtool", "show_trade"):
                    return

        col = COLOR_PAIR["con_text"]
        if "trade: bid:" in txt:
            col = COLOR_PAIR["con_text_buy"] + curses.A_BOLD
        if "trade: ask:" in txt:
            col = COLOR_PAIR["con_text_sell"] + curses.A_BOLD
        self.win.addstr("\n" + txt,  col)
        self.done_paint()


class WinOrderBook(Win):
    """the orderbook window"""

    def __init__(self, stdscr, gox):
        """create the orderbook window and connect it to the
        onChanged callback of the gox.orderbook instance"""
        self.gox = gox
        gox.orderbook.signal_changed.connect(self.slot_changed)
        Win.__init__(self, stdscr)

    def calc_size(self):
        """put it into the middle left side"""
        self.height = self.termheight - HEIGHT_CON - HEIGHT_STATUS
        self.posy = HEIGHT_STATUS
        self.width = WIDTH_ORDERBOOK

    def paint(self):
        """paint the visible portion of the orderbook"""

        def paint_row(pos, price, vol, ownvol, color, changevol):
            """paint a row in the orderbook (bid or ask)"""
            if changevol > 0:
                col2 = col_bid + curses.A_BOLD
            elif changevol < 0:
                col2 = col_ask + curses.A_BOLD
            else:
                col2 = col_vol
            self.addstr(pos, 0,  book.gox.quote2str(price), color)
            self.addstr(pos, 12, book.gox.base2str(vol), col2)
            if ownvol:
                self.addstr(pos, 28, book.gox.base2str(ownvol), col_own)

        self.win.bkgd(" ",  COLOR_PAIR["book_text"])
        self.win.erase()

        gox = self.gox
        book = gox.orderbook

        mid = self.height / 2
        col_bid = COLOR_PAIR["book_bid"]
        col_ask = COLOR_PAIR["book_ask"]
        col_vol = COLOR_PAIR["book_vol"]
        col_own = COLOR_PAIR["book_own"]

        sum_total = gox.config.get_bool("goxtool", "orderbook_sum_total")
        group = gox.config.get_float("goxtool", "orderbook_group")
        group = gox.quote2int(group)
        if group == 0:
            group = 1

        #
        #
        # paint the asks (first we put them into bins[] then we paint them)
        #
        if len(book.asks):
            i = 0
            bins = []
            pos = mid - 1
            vol = 0
            prev_vol = 0

            # no grouping, bins can be created in one simple and fast loop
            if group == 1:
                cnt = len(book.asks)
                while pos >= 0 and i < cnt:
                    level = book.asks[i]
                    price = level.price
                    if sum_total:
                        vol += level.volume
                    else:
                        vol = level.volume
                    ownvol = level.own_volume
                    bins.append([pos, price, vol, ownvol, 0])
                    pos -= 1
                    i += 1

            # with gouping its a bit more complicated
            else:
                # first bin is exact lowest ask price
                price = book.asks[0].price
                vol = book.asks[0].volume
                bins.append([pos, price, vol, 0, 0])
                prev_vol = vol
                pos -= 1

                # now all following bins
                bin_price = int(math.ceil(float(price) / group) * group)
                if bin_price == price:
                    # first level was exact bin price already, skip to next bin
                    bin_price += group
                while pos >= 0 and bin_price < book.asks[-1].price + group:
                    vol, _vol_quote = book.get_total_up_to(bin_price, True)          ## 01 freeze
                    if vol > prev_vol:
                        # append only non-empty bins
                        if sum_total:
                            bins.append([pos, bin_price, vol, 0, 0])
                        else:
                            bins.append([pos, bin_price, vol - prev_vol, 0, 0])
                        prev_vol = vol
                        pos -= 1
                    bin_price += group

                # now add the own volumes to their bins
                for order in book.owns:
                    if order.typ == "ask":
                        order_bin_price = int(math.ceil(float(order.price) / group) * group)
                        for abin in bins:
                            if abin[1] == order.price:
                                abin[3] += order.volume
                                break
                            if abin[1] == order_bin_price:
                                abin[3] += order.volume
                                break

            # mark the level where change took place (optional)
            if gox.config.get_bool("goxtool", "highlight_changes"):
                if book.last_change_type == "ask":
                    change_bin_price = int(math.ceil(float(book.last_change_price) / group) * group)
                    for abin in bins:
                        if abin[1] == book.last_change_price:
                            abin[4] = book.last_change_volume
                            break
                        if abin[1] == change_bin_price:
                            abin[4] = book.last_change_volume
                            break

            # now finally paint the asks
            for pos, price, vol, ownvol, changevol in bins:
                paint_row(pos, price, vol, ownvol, col_ask, changevol)

        #
        #
        # paint the bids (first we put them into bins[] then we paint them)
        #
        if len(book.bids):
            i = 0
            bins = []
            pos = mid + 1
            vol = 0
            prev_vol = 0

            # no grouping, bins can be created in one simple and fast loop
            if group == 1:
                cnt = len(book.bids)
                while pos < self.height and i < cnt:
                    level = book.bids[i]
                    price = level.price
                    if sum_total:
                        vol += level.volume
                    else:
                        vol = level.volume
                    ownvol = level.own_volume
                    bins.append([pos, price, vol, ownvol, 0])
                    prev_vol = vol
                    pos += 1
                    i += 1

            # with gouping its a bit more complicated
            else:
                # first bin is exact lowest ask price
                price = book.bids[0].price
                vol = book.bids[0].volume
                bins.append([pos, price, vol, 0, 0])
                prev_vol = vol
                pos += 1

                # now all following bins
                bin_price = int(math.floor(float(price) / group) * group)
                if bin_price == price:
                    # first level was exact bin price already, skip to next bin
                    bin_price -= group
                while pos < self.height and bin_price >= 0:
                    vol, _vol_quote = book.get_total_up_to(bin_price, False)
                    if vol > prev_vol:
                        # append only non-empty bins
                        if sum_total:
                            bins.append([pos, bin_price, vol, 0, 0])
                        else:
                            bins.append([pos, bin_price, vol - prev_vol, 0, 0])
                        prev_vol = vol
                        pos += 1
                    bin_price -= group

                # now add the own volumes to their bins
                for order in book.owns:
                    if order.typ == "bid":
                        order_bin_price = int(math.floor(float(order.price) / group) * group)
                        for abin in bins:
                            if abin[1] == order.price:
                                abin[3] += order.volume
                                break
                            if abin[1] == order_bin_price:
                                abin[3] += order.volume
                                break

            # mark the level where change took place (optional)
            if gox.config.get_bool("goxtool", "highlight_changes"):
                if book.last_change_type == "bid":
                    change_bin_price = int(math.floor(float(book.last_change_price) / group) * group)
                    for abin in bins:
                        if abin[1] == book.last_change_price:
                            abin[4] = book.last_change_volume
                            break
                        if abin[1] == change_bin_price:
                            abin[4] = book.last_change_volume
                            break

            # now finally paint the bids
            for pos, price, vol, ownvol, changevol in bins:
                paint_row(pos, price, vol, ownvol, col_bid, changevol)

        # update the xterm title bar
        if self.gox.config.get_bool("goxtool", "set_xterm_title"):
            last_candle = self.gox.history.last_candle()
            if last_candle:
                title = self.gox.quote2str(last_candle.cls).strip()
                title += " - goxtool -"
                title += " bid:" + self.gox.quote2str(book.bid).strip()
                title += " ask:" + self.gox.quote2str(book.ask).strip()

                term = os.environ["TERM"]
                # the following is incomplete but better safe than sorry
                # if you know more terminals then please provide a patch
                if "xterm" in term or "rxvt" in term:
                    sys_out.write("\x1b]0;%s\x07" % title)
                    sys_out.flush()

    def slot_changed(self, _book, _dummy):
        """Slot for orderbook.signal_changed"""
        self.do_paint()


TYPE_HISTORY = 1
TYPE_ORDERBOOK = 2

class WinChart(Win):
    """the chart window"""

    def __init__(self, stdscr, gox):
        self.gox = gox
        self.pmin = 0
        self.pmax = 0
        self.change_type = None
        gox.history.signal_changed.connect(self.slot_history_changed)
        gox.orderbook.signal_changed.connect(self.slot_orderbook_changed)

        # some terminals do not support reverse video
        # so we cannot use reverse space for candle bodies
        if curses.A_REVERSE & curses.termattrs():
            self.body_char = " "
            self.body_attr = curses.A_REVERSE
        else:
            self.body_char = curses.ACS_CKBOARD # pylint: disable=E1101
            self.body_attr = 0

        Win.__init__(self, stdscr)

    def calc_size(self):
        """position in the middle, right to the orderbook"""
        self.posx = WIDTH_ORDERBOOK
        self.posy = HEIGHT_STATUS
        self.width = self.termwidth - WIDTH_ORDERBOOK
        self.height = self.termheight - HEIGHT_CON - HEIGHT_STATUS

    def is_in_range(self, price):
        """is this price in the currently visible range?"""
        return price <= self.pmax and price >= self.pmin

    def get_optimal_step(self, num_min):
        """return optimal step size for painting y-axis labels so that the
        range will be divided into at least num_min steps"""
        if self.pmax <= self.pmin:
            return None
        stepex = float(self.pmax - self.pmin) / num_min
        step1 = math.pow(10, math.floor(math.log(stepex, 10)))
        step2 = step1 * 2
        step5 = step1 * 5
        if step5 <= stepex:
            return step5
        if step2 <= stepex:
            return step2
        return step1

    def price_to_screen(self, price):
        """convert price into screen coordinates (y=0 is at the top!)"""
        relative_from_bottom = \
            float(price - self.pmin) / float(self.pmax - self.pmin)
        screen_from_bottom = relative_from_bottom * self.height
        return int(self.height - screen_from_bottom)

    def paint_candle(self, posx, candle):
        """paint a single candle"""

        sopen  = self.price_to_screen(candle.opn)
        shigh  = self.price_to_screen(candle.hig)
        slow   = self.price_to_screen(candle.low)
        sclose = self.price_to_screen(candle.cls)

        for posy in range(self.height):
            if posy >= shigh and posy < sopen and posy < sclose:
                # upper wick
                # pylint: disable=E1101
                self.addch(posy, posx, curses.ACS_VLINE, COLOR_PAIR["chart_text"])
            if posy >= sopen and posy < sclose:
                # red body
                self.addch(posy, posx, self.body_char, self.body_attr + COLOR_PAIR["chart_down"])
            if posy >= sclose and posy < sopen:
                # green body
                self.addch(posy, posx, self.body_char, self.body_attr + COLOR_PAIR["chart_up"])
            if posy >= sopen and posy >= sclose and posy < slow:
                # lower wick
                # pylint: disable=E1101
                self.addch(posy, posx, curses.ACS_VLINE, COLOR_PAIR["chart_text"])

    def paint(self):
        typ = self.gox.config.get_string("goxtool", "display_right")
        if typ == "history_chart":
            self.paint_history_chart()
        elif typ == "depth_chart":
            self.paint_depth_chart()
        else:
            self.paint_history_chart()

    def paint_depth_chart(self):
        """paint a depth chart"""

        # pylint: disable=C0103
        if self.gox.curr_quote in "JPY SEK":
            BAR_LEFT_EDGE = 7
            FORMAT_STRING = "%6.0f"
        else:
            BAR_LEFT_EDGE = 8
            FORMAT_STRING = "%7.2f"

        def paint_depth(pos, price, vol, own, col_price, change):
            """paint one row of the depth chart"""
            if change > 0:
                col = col_bid + curses.A_BOLD
            elif change < 0:
                col = col_ask + curses.A_BOLD
            else:
                col = col_bar
            pricestr = FORMAT_STRING % self.gox.quote2float(price)
            self.addstr(pos, 0, pricestr, col_price)
            length = int(vol * mult_x)
            # pylint: disable=E1101
            self.win.hline(pos, BAR_LEFT_EDGE, curses.ACS_CKBOARD, length, col)
            if own:
                self.addstr(pos, length + BAR_LEFT_EDGE, "o", col_own)

        self.win.bkgd(" ",  COLOR_PAIR["chart_text"])
        self.win.erase()

        book = self.gox.orderbook
        if not (book.bid and book.ask and len(book.bids) and len(book.asks)):
            # orderbook is not initialized yet, paint nothing
            return

        col_bar = COLOR_PAIR["book_vol"]
        col_bid = COLOR_PAIR["book_bid"]
        col_ask = COLOR_PAIR["book_ask"]
        col_own = COLOR_PAIR["book_own"]

        group = self.gox.config.get_float("goxtool", "depth_chart_group")
        if group == 0:
            group = 1
        group = self.gox.quote2int(group)

        max_vol_ask = 0
        max_vol_bid = 0
        bin_asks = []
        bin_bids = []
        mid = self.height / 2
        sum_total = self.gox.config.get_bool("goxtool", "depth_chart_sum_total")

        #
        #
        # bin the asks
        #
        pos = mid - 1
        prev_vol = 0
        bin_price = int(math.ceil(float(book.asks[0].price) / group) * group)
        while pos >= 0 and bin_price < book.asks[-1].price + group:
            bin_vol, _bin_vol_quote = book.get_total_up_to(bin_price, True)
            if bin_vol > prev_vol:
                # add only non-empty bins
                if sum_total:
                    bin_asks.append([pos, bin_price, bin_vol, 0, 0])
                    max_vol_ask = max(bin_vol, max_vol_ask)
                else:
                    bin_asks.append([pos, bin_price, bin_vol - prev_vol, 0, 0])
                    max_vol_ask = max(bin_vol - prev_vol, max_vol_ask)
                prev_vol = bin_vol
                pos -= 1
            bin_price += group

        #
        #
        # bin the bids
        #
        pos = mid + 1
        prev_vol = 0
        bin_price = int(math.floor(float(book.bids[0].price) / group) * group)
        while pos < self.height and bin_price >= 0:
            _bin_vol_base, bin_vol_quote = book.get_total_up_to(bin_price, False)
            bin_vol = self.gox.base2int(bin_vol_quote / book.bid)
            if bin_vol > prev_vol:
                # add only non-empty bins
                if sum_total:
                    bin_bids.append([pos, bin_price, bin_vol, 0, 0])
                    max_vol_bid = max(bin_vol, max_vol_bid)
                else:
                    bin_bids.append([pos, bin_price, bin_vol - prev_vol, 0, 0])
                    max_vol_bid = max(bin_vol - prev_vol, max_vol_bid)
                prev_vol = bin_vol
                pos += 1
            bin_price -= group

        max_vol_tot = max(max_vol_ask, max_vol_bid)
        if not max_vol_tot:
            return
        mult_x = float(self.width - BAR_LEFT_EDGE - 2) / max_vol_tot

        # add the own volume to the bins
        for order in book.owns:
            if order.typ == "ask":
                bin_price = int(math.ceil(float(order.price) / group) * group)
                for abin in bin_asks:
                    if abin[1] == bin_price:
                        abin[3] += order.volume
                        break
            else:
                bin_price = int(math.floor(float(order.price) / group) * group)
                for abin in bin_bids:
                    if abin[1] == bin_price:
                        abin[3] += order.volume
                        break

        # highlight the relative change (optional)
        if self.gox.config.get_bool("goxtool", "highlight_changes"):
            price = book.last_change_price
            if book.last_change_type == "ask":
                bin_price = int(math.ceil(float(price) / group) * group)
                for abin in bin_asks:
                    if abin[1] == bin_price:
                        abin[4] = book.last_change_volume
                        break
            if book.last_change_type == "bid":
                bin_price = int(math.floor(float(price) / group) * group)
                for abin in bin_bids:
                    if abin[1] == bin_price:
                        abin[4] = book.last_change_volume
                        break

        # paint the asks
        for pos, price, vol, own, change in bin_asks:
            paint_depth(pos, price, vol, own, col_ask, change)

        # paint the bids
        for pos, price, vol, own, change in bin_bids:
            paint_depth(pos, price, vol, own, col_bid, change)

    def paint_history_chart(self):
        """paint a history candlestick chart"""

        if self.change_type == TYPE_ORDERBOOK:
            # erase only the rightmost column to redraw bid/ask and orders
            # beause we won't redraw the chart, its only an orderbook change
            self.win.vline(0, self.width - 1, " ", self.height, COLOR_PAIR["chart_text"])
        else:
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

        # paint the candlestick chart.
        # We won't paint it if it was triggered from an orderbook change
        # signal because that would be redundant and only waste CPU.
        # In that case we only repaint the bid/ask markers (see below)
        if self.change_type != TYPE_ORDERBOOK:
            # paint the candles
            posx = self.width - 2
            index = 0
            while index < hist.length() and posx >= 0:
                candle = hist.candles[index]
                self.paint_candle(posx, candle)
                index += 1
                posx -= 1

            # paint the y-axis labels
            posx = 0
            step = self.get_optimal_step(4)
            if step:
                labelprice = int(self.pmin / step) * step
                while not labelprice > self.pmax:
                    posy = self.price_to_screen(labelprice)
                    if posy < self.height - 1:
                        self.addstr(
                            posy, posx,
                            self.gox.quote2str(labelprice),
                            COLOR_PAIR["chart_text"]
                        )
                    labelprice += step

        # paint bid, ask, own orders
        posx = self.width - 1
        for order in book.owns:
            if self.is_in_range(order.price):
                posy = self.price_to_screen(order.price)
                if order.status == "pending":
                    self.addch(posy, posx,
                        ord("p"), COLOR_PAIR["order_pending"])
                else:
                    self.addch(posy, posx,
                        ord("o"), COLOR_PAIR["book_own"])

        if self.is_in_range(book.bid):
            posy = self.price_to_screen(book.bid)
            # pylint: disable=E1101
            self.addch(posy, posx,
                curses.ACS_HLINE, COLOR_PAIR["chart_up"])

        if self.is_in_range(book.ask):
            posy = self.price_to_screen(book.ask)
            # pylint: disable=E1101
            self.addch(posy, posx,
                curses.ACS_HLINE, COLOR_PAIR["chart_down"])


    def slot_history_changed(self, _sender, _data):
        """Slot for history changed"""
        self.change_type = TYPE_HISTORY
        self.do_paint()
        self.change_type = None

    def slot_orderbook_changed(self, _sender, _data):
        """Slot for orderbook changed"""
        self.change_type = TYPE_ORDERBOOK
        self.do_paint()
        self.change_type = None


class WinStatus(Win):
    """the status window at the top"""

    def __init__(self, stdscr, gox):
        """create the status window and connect the needed callbacks"""
        self.gox = gox
        self.order_lag = 0
        self.order_lag_txt = ""
        self.sorted_currency_list = []
        gox.signal_orderlag.connect(self.slot_orderlag)
        gox.signal_wallet.connect(self.slot_changed)
        gox.orderbook.signal_changed.connect(self.slot_changed)
        Win.__init__(self, stdscr)

    def calc_size(self):
        """place it at the top of the terminal"""
        self.height = HEIGHT_STATUS

    def sort_currency_list_if_changed(self):
        """sort the currency list in the wallet for better display,
        sort it only if it has changed, otherwise leave it as it is"""
        currency_list = self.gox.wallet.keys()
        if len(currency_list) == len(self.sorted_currency_list):
            return

        # now we will bring base and quote currency to the front and sort the
        # the rest of the list of names by acount balance in descending order
        if self.gox.curr_base in currency_list:
            currency_list.remove(self.gox.curr_base)
        if self.gox.curr_quote in currency_list:
            currency_list.remove(self.gox.curr_quote)
        currency_list.sort(key=lambda name: -self.gox.wallet[name])
        currency_list.insert(0, self.gox.curr_quote)
        currency_list.insert(0, self.gox.curr_base)
        self.sorted_currency_list = currency_list

    def paint(self):
        """paint the complete status"""
        cbase = self.gox.curr_base
        cquote = self.gox.curr_quote
        self.sort_currency_list_if_changed()
        self.win.bkgd(" ", COLOR_PAIR["status_text"])
        self.win.erase()

        #
        # first line
        #
        line1 = "Market: %s%s | " % (cbase, cquote)
        line1 += "Account: "
        if len(self.sorted_currency_list):
            for currency in self.sorted_currency_list:
                if currency in self.gox.wallet:
                    line1 += currency + " " \
                    + goxapi.int2str(self.gox.wallet[currency], currency).strip() \
                    + " + "
            line1 = line1.strip(" +")
        else:
            line1 += "No info (yet)"

        #
        # second line
        #
        line2 = ""
        if self.gox.config.get_bool("goxtool", "show_orderbook_stats"):
            str_btc = locale.format('%d', self.gox.orderbook.total_ask, 1)
            str_fiat = locale.format('%d', self.gox.orderbook.total_bid, 1)
            if self.gox.orderbook.total_ask:
                str_ratio = locale.format('%1.2f',
                    self.gox.orderbook.total_bid / self.gox.orderbook.total_ask, 1)
            else:
                str_ratio = "-"

            line2 += "sum_bid: %s %s | " % (str_fiat, cquote)
            line2 += "sum_ask: %s %s | " % (str_btc, cbase)
            line2 += "ratio: %s %s/%s | " % (str_ratio, cquote, cbase)

        line2 += "o_lag: %s | " % self.order_lag_txt
        line2 += "s_lag: %.3f s" % (self.gox.socket_lag / 1e6)
        self.addstr(0, 0, line1, COLOR_PAIR["status_text"])
        self.addstr(1, 0, line2, COLOR_PAIR["status_text"])


    def slot_changed(self, dummy_sender, dummy_data):
        """the callback funtion called by the Gox() instance"""
        self.do_paint()

    def slot_orderlag(self, dummy_sender, (usec, text)):
        """slot for order_lag mesages"""
        self.order_lag = usec
        self.order_lag_txt = text
        self.do_paint()


class DlgListItems(Win):
    """dialog with a scrollable list of items"""
    def __init__(self, stdscr, width, title, hlp, keys):
        self.items = []
        self.selected = []
        self.item_top = 0
        self.item_sel = 0
        self.dlg_width = width
        self.dlg_title = title
        self.dlg_hlp = hlp
        self.dlg_keys = keys
        self.reserved_lines = 5  # how many lines NOT used for order list
        self.init_items()
        Win.__init__(self, stdscr)

    def init_items(self):
        """initialize the items list, must override and implement this"""
        raise NotImplementedError()

    def calc_size(self):
        maxh = self.termheight - 4
        self.height = len(self.items) + self.reserved_lines
        if self.height > maxh:
            self.height = maxh
        self.posy = (self.termheight - self.height) / 2

        self.width = self.dlg_width
        self.posx = (self.termwidth - self.width) / 2

    def paint_item(self, posx, index):
        """paint the item. Must override and implement this"""
        raise NotImplementedError()

    def paint(self):
        self.win.bkgd(" ", COLOR_PAIR["dialog_text"])
        self.win.erase()
        self.win.border()
        self.addstr(0, 1, " %s " % self.dlg_title, COLOR_PAIR["dialog_text"])
        index = self.item_top
        posy = 2
        while posy < self.height - 3 and index < len(self.items):
            self.paint_item(posy, index)
            index += 1
            posy += 1

        self.win.move(self.height - 2, 2)
        for key, desc in self.dlg_hlp:
            self.addstr(key + " ",  COLOR_PAIR["dialog_sel"])
            self.addstr(desc + " ", COLOR_PAIR["dialog_text"])

    def down(self, num):
        """move the cursor down (or up)"""
        if not len(self.items):
            return
        self.item_sel += num
        if self.item_sel < 0:
            self.item_sel = 0
        if self.item_sel > len(self.items) - 1:
            self.item_sel = len(self.items) - 1

        last_line = self.height - 1 - self.reserved_lines
        if self.item_sel < self.item_top:
            self.item_top = self.item_sel
        if self.item_sel - self.item_top > last_line:
            self.item_top = self.item_sel - last_line

        self.do_paint()

    def toggle_select(self):
        """toggle selection under cursor"""
        if not len(self.items):
            return
        item = self.items[self.item_sel]
        if item in self.selected:
            self.selected.remove(item)
        else:
            self.selected.append(item)
        self.do_paint()

    def modal(self):
        """run the modal getch-loop for this dialog"""
        if self.win:
            done = False
            while not done:
                key_pressed = self.win.getch()
                if key_pressed in [27, ord("q"), curses.KEY_F10]:
                    done = True
                if key_pressed == curses.KEY_DOWN:
                    self.down(1)
                if key_pressed == curses.KEY_UP:
                    self.down(-1)
                if key_pressed == curses.KEY_IC:
                    self.toggle_select()
                    self.down(1)

                for key, func in self.dlg_keys:
                    if key == key_pressed:
                        func()
                        done = True

        # help the garbage collector clean up circular references
        # to make sure __del__() will be called to close the dialog
        del self.dlg_keys


class DlgCancelOrders(DlgListItems):
    """modal dialog to cancel orders"""
    def __init__(self, stdscr, gox):
        self.gox = gox
        hlp = [("INS", "select"), ("F8", "cancel selected"), ("F10", "exit")]
        keys = [(curses.KEY_F8, self._do_cancel)]
        DlgListItems.__init__(self, stdscr, 45, "Cancel order(s)", hlp, keys)

    def init_items(self):
        for order in self.gox.orderbook.owns:
            self.items.append(order)
        self.items.sort(key = lambda o: -o.price)

    def paint_item(self, posy, index):
        """paint one single order"""
        order = self.items[index]
        if order in self.selected:
            marker = "*"
            if index == self.item_sel:
                attr = COLOR_PAIR["dialog_sel_sel"]
            else:
                attr = COLOR_PAIR["dialog_sel_text"] + curses.A_BOLD
        else:
            marker = ""
            if index == self.item_sel:
                attr = COLOR_PAIR["dialog_sel"]
            else:
                attr = COLOR_PAIR["dialog_text"]

        self.addstr(posy, 2, marker, attr)
        self.addstr(posy, 5, order.typ, attr)
        self.addstr(posy, 9, self.gox.quote2str(order.price), attr)
        self.addstr(posy, 22, self.gox.base2str(order.volume), attr)

    def _do_cancel(self):
        """cancel all selected orders (or the order under cursor if empty)"""

        def do_cancel(order):
            """cancel a single order"""
            self.gox.cancel(order.oid)

        if not len(self.items):
            return
        if not len(self.selected):
            order = self.items[self.item_sel]
            do_cancel(order)
        else:
            for order in self.selected:
                do_cancel(order)


class TextBox():
    """wrapper for curses.textpad.Textbox"""

    def __init__(self, dlg, posy, posx, length):
        self.dlg = dlg
        self.win = dlg.win.derwin(1, length, posy, posx)
        self.win.keypad(1)
        self.box = curses.textpad.Textbox(self.win, insert_mode=True)
        self.value = ""
        self.result = None
        self.editing = False

    def __del__(self):
        self.box = None
        self.win = None

    def modal(self):
        """enter te edit box modal loop"""
        self.win.move(0, 0)
        self.editing = True
        goxapi.start_thread(self.cursor_placement_thread, "TextBox cursor placement")
        self.value = self.box.edit(self.validator)
        self.editing = False
        return self.result

    def validator(self, char):
        """here we tweak the behavior slightly, especially we want to
        end modal editing mode immediately on arrow up/down and on enter
        and we also want to catch ESC and F10, to abort the entire dialog"""
        if curses.ascii.isprint(char):
            return char
        if char == curses.ascii.TAB:
            char = curses.KEY_DOWN
        if char in [curses.KEY_DOWN, curses.KEY_UP]:
            self.result = char
            return curses.ascii.BEL
        if char in [10, 13, curses.KEY_ENTER, curses.ascii.BEL]:
            self.result = 10
            return curses.ascii.BEL
        if char in [27, curses.KEY_F10]:
            self.result = -1
            return curses.ascii.BEL
        return char

    def cursor_placement_thread(self):
        """this is the most ugly hack of the entire program. During the
        signals hat are fired while we are editing there will be many repaints
        of other other panels below this dialog and when curses is done
        repainting everything the blinking cursor is not in the correct
        position. This is only a cosmetic problem but very annnoying. Try to
        force it into the edit field by repainting it very often."""
        while self.editing:
            # pylint: disable=W0212
            with goxapi.Signal._lock:
                curses.curs_set(2)
                self.win.touchwin()
                self.win.refresh()
            time.sleep(0.1)
        curses.curs_set(0)


class NumberBox(TextBox):
    """TextBox that only accepts numbers"""
    def __init__(self, dlg, posy, posx, length):
        TextBox.__init__(self, dlg, posy, posx, length)

    def validator(self, char):
        """allow only numbers to be entered"""
        if char == ord("q"):
            char = curses.KEY_F10
        if curses.ascii.isprint(char):
            if chr(char) not in "0123456789.":
                char = 0
        return TextBox.validator(self, char)


class DlgNewOrder(Win):
    """abtract base class for entering new orders"""
    def __init__(self, stdscr, gox, color, title):
        self.gox = gox
        self.color = color
        self.title = title
        self.edit_price = None
        self.edit_volume = None
        Win.__init__(self, stdscr)

    def calc_size(self):
        Win.calc_size(self)
        self.width = 35
        self.height = 8
        self.posx = (self.termwidth - self.width) / 2
        self.posy = (self.termheight - self.height) / 2

    def paint(self):
        self.win.bkgd(" ", self.color)
        self.win.border()
        self.addstr(0, 1, " %s " % self.title, self.color)
        self.addstr(2, 2, " price", self.color)
        self.addstr(2, 30, self.gox.curr_quote)
        self.addstr(4, 2, "volume", self.color)
        self.addstr(4, 30, self.gox.curr_base)
        self.addstr(6, 2, "F10 ", self.color + curses.A_REVERSE)
        self.addstr("cancel ", self.color)
        self.addstr("Enter ", self.color + curses.A_REVERSE)
        self.addstr("submit ", self.color)
        self.edit_price = NumberBox(self, 2, 10, 20)
        self.edit_volume = NumberBox(self, 4, 10, 20)

    def do_submit(self, price_float, volume_float):
        """sumit the order. implementating class will do eiter buy or sell"""
        raise NotImplementedError()

    def modal(self):
        """enter the modal getch() loop of this dialog"""
        if self.win:
            focus = 1
            # next time I am going to use some higher level
            # wrapper on top of curses, i promise...
            while True:
                if focus == 1:
                    res = self.edit_price.modal()
                    if res == -1:
                        break # cancel entire dialog
                    if res in [10, curses.KEY_DOWN, curses.KEY_UP]:
                        try:
                            price_float = float(self.edit_price.value)
                            focus = 2
                        except ValueError:
                            pass # can't move down until this is a valid number

                if focus == 2:
                    res = self.edit_volume.modal()
                    if res == -1:
                        break # cancel entire dialog
                    if res in [curses.KEY_UP, curses.KEY_DOWN]:
                        focus = 1
                    if res == 10:
                        try:
                            volume_float = float(self.edit_volume.value)
                            break # have both values now, can submit order
                        except ValueError:
                            pass # no float number, stay in this edit field

            if res == -1:
                #user has hit f10. just end here, do nothing
                pass
            if res == 10:
                self.do_submit(price_float, volume_float)

        # make sure all cyclic references are garbage collected or
        # otherwise the curses window won't disappear
        self.edit_price = None
        self.edit_volume = None


class DlgNewOrderBid(DlgNewOrder):
    """Modal dialog for new buy order"""
    def __init__(self, stdscr, gox):
        DlgNewOrder.__init__(self, stdscr, gox,
            COLOR_PAIR["dialog_bid_text"],
            "New buy order")

    def do_submit(self, price, volume):
        price = self.gox.quote2int(price)
        volume = self.gox.base2int(volume)
        self.gox.buy(price, volume)


class DlgNewOrderAsk(DlgNewOrder):
    """Modal dialog for new sell order"""
    def __init__(self, stdscr, gox):
        DlgNewOrder.__init__(self, stdscr, gox,
             COLOR_PAIR["dialog_ask_text"],
            "New sell order")

    def do_submit(self, price, volume):
        price = self.gox.quote2int(price)
        volume = self.gox.base2int(volume)
        self.gox.sell(price, volume)



#
#
# logging, printing, etc...
#

class LogWriter():
    """connects to gox.signal_debug and logs it all to the logfile"""
    def __init__(self, gox):
        self.gox = gox
        if self.gox.config.get_bool("goxtool", "dont_truncate_logfile"):
            logfilemode = 'a'
        else:
            logfilemode = 'w'

        logging.basicConfig(filename='goxtool.log'
                           ,filemode=logfilemode
                           ,format='%(asctime)s:%(levelname)s:%(message)s'
                           ,level=logging.DEBUG
                           )
        self.gox.signal_debug.connect(self.slot_debug)

    def close(self):
        """stop logging"""
        #not needed
        pass

    # pylint: disable=R0201
    def slot_debug(self, sender, (msg)):
        """handler for signal_debug signals"""
        name = "%s.%s" % (sender.__class__.__module__, sender.__class__.__name__)
        logging.debug("%s:%s", name, msg)


class PrintHook():
    """intercept stdout/stderr and send it all to gox.signal_debug instead"""
    def __init__(self, gox):
        self.gox = gox
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self

    def close(self):
        """restore normal stdio"""
        sys.stdout = self.stdout
        sys.stderr = self.stderr

    def write(self, string):
        """called when someone uses print(), send it to gox"""
        string = string.strip()
        if string != "":
            self.gox.signal_debug(self, string)



#
#
# dynamically (re)loadable strategy module
#

class StrategyManager():
    """load the strategy module"""

    def __init__(self, gox, strategy_name_list):
        self.strategy_object_list = []
        self.strategy_name_list = strategy_name_list
        self.gox = gox
        self.reload()

    def unload(self):
        """unload the strategy, will trigger its the __del__ method"""
        self.gox.signal_strategy_unload(self, None)
        self.strategy_object_list = []

    def reload(self):
        """reload and re-initialize the strategy module"""
        self.unload()
        for name in self.strategy_name_list:
            name = name.replace(".py", "").strip()

            try:
                strategy_module = __import__(name)
                try:
                    reload(strategy_module)
                    strategy_object = strategy_module.Strategy(self.gox)
                    self.strategy_object_list.append(strategy_object)
                    if hasattr(strategy_object, "name"):
                        self.gox.strategies[strategy_object.name] = strategy_object

                except Exception:
                    self.gox.debug("### error while loading strategy %s.py, traceback follows:" % name)
                    self.gox.debug(traceback.format_exc())

            except ImportError:
                self.gox.debug("### could not import %s.py, traceback follows:" % name)
                self.gox.debug(traceback.format_exc())


def toggle_setting(gox, alternatives, option_name, direction):
    """toggle a setting in the ini file"""
    # pylint: disable=W0212
    with goxapi.Signal._lock:
        setting = gox.config.get_string("goxtool", option_name)
        try:
            newindex = (alternatives.index(setting) + direction) % len(alternatives)
        except ValueError:
            newindex = 0
        gox.config.set("goxtool", option_name, alternatives[newindex])
        gox.config.save()

def toggle_depth_group(gox, direction):
    """toggle the step width of the depth chart"""
    if gox.curr_quote in "JPY SEK":
        alt = ["5", "10", "25", "50", "100", "200", "500", "1000"]
    else:
        alt = ["0.05", "0.1", "0.25", "0.5", "1", "2", "5", "10"]
    toggle_setting(gox, alt, "depth_chart_group", direction)
    gox.orderbook.signal_changed(gox.orderbook, None)

def toggle_orderbook_group(gox, direction):
    """toggle the group width of the orderbook"""
    if gox.curr_quote in "JPY SEK":
        alt = ["0", "5", "10", "25", "50", "100", "200", "500", "1000"]
    else:
        alt = ["0", "0.05", "0.1", "0.25", "0.5", "1", "2", "5", "10"]
    toggle_setting(gox, alt, "orderbook_group", direction)
    gox.orderbook.signal_changed(gox.orderbook, None)

def toggle_orderbook_sum(gox):
    """toggle the summing in the orderbook on and off"""
    alt = ["False", "True"]
    toggle_setting(gox, alt, "orderbook_sum_total", 1)
    gox.orderbook.signal_changed(gox.orderbook, None)

def toggle_depth_sum(gox):
    """toggle the summing in the depth chart on and off"""
    alt = ["False", "True"]
    toggle_setting(gox, alt, "depth_chart_sum_total", 1)
    gox.orderbook.signal_changed(gox.orderbook, None)

def set_ini(gox, setting, value, signal, signal_sender, signal_params):
    """set the ini value and then send a signal"""
    # pylint: disable=W0212
    with goxapi.Signal._lock:
        gox.config.set("goxtool", setting, value)
        gox.config.save()
    signal(signal_sender, signal_params)



#
#
# main program
#

def main():
    """main funtion, called at the start of the program"""

    debug_tb = []
    def curses_loop(stdscr):
        """Only the code inside this function runs within the curses wrapper"""

        # this function may under no circumstancs raise an exception, so I'm
        # wrapping everything into try/except (should actually never happen
        # anyways but when it happens during coding or debugging it would
        # leave the terminal in an unusable state and this must be avoded).
        # We have a list debug_tb[] where we can append tracebacks and
        # after curses uninitialized properly and the terminal is restored
        # we can print them.
        try:
            init_colors()
            gox = goxapi.Gox(secret, config)

            logwriter = LogWriter(gox)
            printhook = PrintHook(gox)

            conwin = WinConsole(stdscr, gox)
            bookwin = WinOrderBook(stdscr, gox)
            statuswin = WinStatus(stdscr, gox)
            chartwin = WinChart(stdscr, gox)

            strategy_manager = StrategyManager(gox, strat_mod_list)

            gox.start()
            while True:
                key = stdscr.getch()
                if key == ord("q"):
                    break
                elif key == curses.KEY_F4:
                    DlgNewOrderBid(stdscr, gox).modal()
                elif key == curses.KEY_F5:
                    DlgNewOrderAsk(stdscr, gox).modal()
                elif key == curses.KEY_F6:
                    DlgCancelOrders(stdscr, gox).modal()
                elif key == curses.KEY_RESIZE:
                    # pylint: disable=W0212
                    with goxapi.Signal._lock:
                        stdscr.erase()
                        stdscr.refresh()
                        conwin.resize()
                        bookwin.resize()
                        chartwin.resize()
                        statuswin.resize()
                elif key == ord("l"):
                    strategy_manager.reload()

                # which chart to show on the right side
                elif key == ord("H"):
                    set_ini(gox, "display_right", "history_chart",
                        gox.history.signal_changed, gox.history, None)
                elif key == ord("D"):
                    set_ini(gox, "display_right", "depth_chart",
                        gox.orderbook.signal_changed, gox.orderbook, None)

                #  depth chart step
                elif key == ord(","): # zoom out
                    toggle_depth_group(gox, +1)
                elif key == ord("."): # zoom in
                    toggle_depth_group(gox, -1)

                # orderbook grouping step
                elif key == ord("-"): # zoom out (larger step)
                    toggle_orderbook_group(gox, +1)
                elif key == ord("+"): # zoom in (smaller step)
                    toggle_orderbook_group(gox, -1)

                elif key == ord("S"):
                    toggle_orderbook_sum(gox)

                elif key == ord("T"):
                    toggle_depth_sum(gox)

                # lowercase keys go to the strategy module
                elif key >= ord("a") and key <= ord("z"):
                    gox.signal_keypress(gox, (key))
                else:
                    gox.debug("key pressed: key=%i" % key)

        except KeyboardInterrupt:
            # Ctrl+C has been pressed
            pass

        except Exception:
            debug_tb.append(traceback.format_exc())

        # we are here because shutdown was requested.
        #
        # Before we do anything we dump stacktraces of all currently running
        # threads to a separate logfile because this helps debugging freezes
        # and deadlocks that might occur if things went totally wrong.
        with open("goxtool.stacktrace.log", "w") as stacklog:
            stacklog.write(dump_all_stacks())

        # we need the signal lock to be able to shut down. And we cannot
        # wait for any frozen slot to return, so try really hard to get
        # the lock and if that fails then unlock it forcefully.
        try_get_lock_or_break_open()

        # Now trying to shutdown everything in an orderly manner.it in the
        # Since we are still inside curses but we don't know whether
        # the printhook or the logwriter was initialized properly already
        # or whether it crashed earlier we cannot print here and we also
        # cannot log, so we put all tracebacks into the debug_tb list to
        # print them later once the terminal is properly restored again.
        try:
            strategy_manager.unload()
        except Exception:
            debug_tb.append(traceback.format_exc())

        try:
            gox.stop()
        except Exception:
            debug_tb.append(traceback.format_exc())

        try:
            printhook.close()
        except Exception:
            debug_tb.append(traceback.format_exc())

        try:
            logwriter.close()
        except Exception:
            debug_tb.append(traceback.format_exc())

        # curses_loop() ends here, we must reach this point under all circumstances.
        # Now curses will restore the terminal back to cooked (normal) mode.


    # Here it begins. The very first thing is to always set US or GB locale
    # to have always the same well defined behavior for number formatting.
    for loc in ["en_US.UTF8", "en_GB.UTF8", "en_EN", "en_GB", "C"]:
        try:
            locale.setlocale(locale.LC_NUMERIC, loc)
            break
        except locale.Error:
            continue

    # before we can finally start the curses UI we might need to do some user
    # interaction on the command line, regarding the encrypted secret
    argp = argparse.ArgumentParser(description='MtGox live market data monitor'
        + ' and trading bot experimentation framework')
    argp.add_argument('--add-secret', action="store_true",
        help="prompt for API secret, encrypt it and then exit")
    argp.add_argument('--strategy', action="store", default="strategy.py",
        help="name of strategy module files, comma separated list, default=strategy.py")
    argp.add_argument('--protocol', action="store", default="",
        help="force protocol (socketio or websocket), ignore setting in .ini")
    argp.add_argument('--no-fulldepth', action="store_true", default=False,
        help="do not download full depth (useful for debugging)")
    argp.add_argument('--no-history', action="store_true", default=False,
        help="do not download full history (useful for debugging)")
    argp.add_argument('--use-http', action="store_true", default=False,
        help="use http api for trading (more reliable, recommended")
    argp.add_argument('--no-http', action="store_true", default=False,
        help="use streaming api for trading (problematic when streaming api disconnects often)")
    argp.add_argument('--password', action="store", default=None,
        help="password for decryption of stored key. This is a dangerous option "
            +"because the password might end up being stored in the history file "
            +"of your shell, for example in ~/.bash_history. Use this only when "
            +"starting it from within a script and then of course you need to "
            +"keep this start script in a secure place!")
    args = argp.parse_args()

    config = goxapi.GoxConfig("goxtool.ini")
    config.init_defaults(INI_DEFAULTS)
    secret = goxapi.Secret(config)
    secret.password_from_commandline_option = args.password
    if args.add_secret:
        # prompt for secret, encrypt, write to .ini and then exit the program
        secret.prompt_encrypt()
    else:
        strat_mod_list = args.strategy.split(",")
        goxapi.FORCE_PROTOCOL = args.protocol
        goxapi.FORCE_NO_FULLDEPTH = args.no_fulldepth
        goxapi.FORCE_NO_HISTORY = args.no_history
        goxapi.FORCE_HTTP_API = args.use_http
        goxapi.FORCE_NO_HTTP_API = args.no_http

        # if its ok then we can finally enter the curses main loop
        if secret.prompt_decrypt() != secret.S_FAIL_FATAL:

            ###
            #
            # now going to enter cbreak mode and start the curses loop...
            curses.wrapper(curses_loop)
            # curses ended, terminal is back in normal (cooked) mode
            #
            ###

            if len(debug_tb):
                print "\n\n*** error(s) in curses_loop() that caused unclean shutdown:\n"
                for trb in debug_tb:
                    print trb
            else:
                print
                print "*******************************************************"
                print "*  Please donate: 1C8aDabADaYvTKvCAG1htqYcEgpAhkeYoW  *"
                print "*******************************************************"

if __name__ == "__main__":
    main()

