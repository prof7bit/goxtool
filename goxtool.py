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

# pylint: disable=C0301,C0302,R0902,R0903,R0912,R0913,R0915,R0922

import argparse
import curses
import curses.panel
import curses.textpad
import goxapi
import logging
import locale
import math
import sys
import time
import traceback
import threading


#
#
# curses user interface
#

HEIGHT_STATUS   = 2
HEIGHT_CON      = 7
WIDTH_ORDERBOOK = 45

COLORS =    [["con_text",       curses.COLOR_BLUE,    curses.COLOR_CYAN]
            ,["status_text",    curses.COLOR_BLUE,    curses.COLOR_CYAN]

            ,["book_text",      curses.COLOR_BLACK,   curses.COLOR_BLUE]
            ,["book_bid",       curses.COLOR_BLACK,   curses.COLOR_GREEN]
            ,["book_ask",       curses.COLOR_BLACK,   curses.COLOR_RED]
            ,["book_own",       curses.COLOR_BLACK,   curses.COLOR_YELLOW]
            ,["book_vol",       curses.COLOR_BLACK,   curses.COLOR_BLUE]

            ,["chart_text",     curses.COLOR_BLACK,   curses.COLOR_WHITE]
            ,["chart_up",       curses.COLOR_BLACK,   curses.COLOR_GREEN]
            ,["chart_down",     curses.COLOR_BLACK,   curses.COLOR_RED]
            ,["order_pending",  curses.COLOR_BLACK,   curses.COLOR_BLUE]

            ,["dialog_text",     curses.COLOR_BLUE,   curses.COLOR_CYAN]
            ,["dialog_sel",      curses.COLOR_CYAN,   curses.COLOR_BLUE]
            ,["dialog_sel_text", curses.COLOR_BLUE,   curses.COLOR_YELLOW]
            ,["dialog_sel_sel",  curses.COLOR_YELLOW, curses.COLOR_BLUE]

            ,["dialog_bid_text", curses.COLOR_GREEN,  curses.COLOR_BLACK]
            ,["dialog_ask_text", curses.COLOR_RED,    curses.COLOR_WHITE]

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
        self.paint()
        self.done_paint()

    def done_paint(self):
        """update the sreen after paint operations, this will invoke all
        necessary stuff to refresh all (possibly overlapping) windows in
        the right order and then push it to the screen"""
        self.win.touchwin()
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
        self.win = curses.newwin(self.height, self.width, self.posy, self.posx)
        self.panel = curses.panel.new_panel(self.win)
        self.win.scrollok(True)
        self.win.keypad(1)
        self.do_paint()

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
        self.win.addstr("\n" + txt,  COLOR_PAIR["con_text"])
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
            self.addstr(pos, 0,  goxapi.int2str(book.asks[i].price, book.gox.currency), col_ask)
            self.addstr(pos, 12, goxapi.int2str(book.asks[i].volume, "BTC"), col_vol)
            ownvol = book.get_own_volume_at(book.asks[i].price)
            if ownvol:
                self.addstr(pos, 28, goxapi.int2str(ownvol, "BTC"), col_own)
            pos -= 1
            i += 1

        # print the bids
        pos = mid + 1
        i = 0
        cnt = len(book.bids)
        while pos < self.height and  i < cnt:
            self.addstr(pos, 0,  goxapi.int2str(book.bids[i].price, book.gox.currency), col_bid)
            self.addstr(pos, 12, goxapi.int2str(book.bids[i].volume, "BTC"), col_vol)
            ownvol = book.get_own_volume_at(book.bids[i].price)
            if ownvol:
                self.addstr(pos, 28, goxapi.int2str(ownvol, "BTC"), col_own)
            pos += 1
            i += 1

    def slot_changed(self, book, dummy_data):
        """Slot for orderbook.signal_changed"""
        self.do_paint()

        # update the xterm title (this is not handled by curses)
        if self.gox.config.get_bool("goxtool", "set_xterm_title"):
            last_candle = self.gox.history.last_candle()
            if last_candle:
                title = goxapi.int2str(last_candle.cls, self.gox.currency).strip()
                title += " - goxtool -"
                title += " bid:" + goxapi.int2str(book.bid, self.gox.currency).strip()
                title += " ask:" + goxapi.int2str(book.ask, self.gox.currency).strip()
                curses.putp("\033]0;%s\007" % title)


class WinChart(Win):
    """the chart window"""

    def __init__(self, stdscr, gox):
        self.gox = gox
        self.pmin = 0
        self.pmax = 0
        gox.history.signal_changed.connect(self.slot_hist_changed)
        gox.orderbook.signal_changed.connect(self.slot_book_changed)
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
                self.addch(posy, posx,
                    curses.ACS_VLINE, COLOR_PAIR["chart_text"])
            if posy >= sopen and posy < sclose:
                # red body
                self.addch(posy, posx,
                    ord(" "), curses.A_REVERSE + COLOR_PAIR["chart_down"])
            if posy >= sclose and posy < sopen:
                # green body
                self.addch(posy, posx,
                    ord(" "), curses.A_REVERSE + COLOR_PAIR["chart_up"])
            if posy >= sopen and posy >= sclose and posy < slow:
                # lower wick
                # pylint: disable=E1101
                self.addch(posy, posx,
                    curses.ACS_VLINE, COLOR_PAIR["chart_text"])

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
                if order.status == "pending":
                    self.addch(posy, posx,
                        ord("o"), COLOR_PAIR["order_pending"])
                else:
                    self.addch(posy, posx,
                        ord("O"), COLOR_PAIR["chart_text"])

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
                        goxapi.int2str(labelprice, self.gox.currency),
                        COLOR_PAIR["chart_text"]
                    )
                labelprice += step

    def slot_hist_changed(self, dummy_history, (dummy_cnt)):
        """Slot for history.signal_changed"""
        self.do_paint()

    def slot_book_changed(self, dummy_book, dummy_data):
        """Slot for orderbook.signal_changed"""
        self.do_paint()


class WinStatus(Win):
    """the status window at the top"""

    def __init__(self, stdscr, gox):
        """create the status window and connect the needed callbacks"""
        self.gox = gox
        self.order_lag = 0
        self.order_lag_txt = ""
        gox.signal_orderlag.connect(self.slot_orderlag)
        gox.signal_wallet.connect(self.slot_changed)
        gox.orderbook.signal_changed.connect(self.slot_changed)
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
                + goxapi.int2str(self.gox.wallet[currency], currency).strip() \
                + " + "
            line1 = line1.strip(" +")
        else:
            line1 += "No info (yet)"

        str_btc = locale.format('%d', self.gox.orderbook.total_ask, 1)
        str_fiat = locale.format('%d', self.gox.orderbook.total_bid, 1)
        if self.gox.orderbook.total_ask:
            str_ratio = locale.format('%1.2f',
                self.gox.orderbook.total_bid / self.gox.orderbook.total_ask, 1)
        else:
            str_ratio = "-"

        line2 = "total bid: " + str_fiat + " " + self.gox.currency + " | "
        line2 += "total ask: " +str_btc + " BTC | "
        line2 += "ratio: " + str_ratio + " " + self.gox.currency + "/BTC | "
        line2 += "order lag: " + self.order_lag_txt
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
        self.addstr(posy, 9, goxapi.int2str(order.price, self.gox.currency), attr)
        self.addstr(posy, 22, goxapi.int2str(order.volume, "BTC"), attr)

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
        threading.Thread(None, self.cursor_placement_thread).start()
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
            self.win.touchwin()
            self.win.refresh()
            time.sleep(0.1)


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
        self.addstr(4, 2, "volume", self.color)
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
        price = goxapi.float2int(price, self.gox.currency)
        volume = goxapi.float2int(volume, "BTC")
        self.gox.buy(price, volume)


class DlgNewOrderAsk(DlgNewOrder):
    """Modal dialog for new sell order"""
    def __init__(self, stdscr, gox):
        DlgNewOrder.__init__(self, stdscr, gox,
             COLOR_PAIR["dialog_ask_text"],
            "New sell order")

    def do_submit(self, price, volume):
        price = goxapi.float2int(price, self.gox.currency)
        volume = goxapi.float2int(volume, "BTC")
        self.gox.sell(price, volume)



#
#
# logging, printing, etc...
#

class LogWriter():
    """connects to gox.signal_debug and logs it all to the logfile"""
    def __init__(self, gox):
        self.gox = gox
        logging.basicConfig(filename='goxtool.log'
                           ,filemode='w'
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
        logging.debug("%s:%s", sender.__class__.__name__, msg)


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

    def __init__(self, gox, strategy_module_name):
        self.strategy_object = None
        self.strategy_module_name = strategy_module_name
        self.gox = gox
        self.reload()

    def unload(self):
        """unload the strategy, will trigger its the __del__ method"""
        self.strategy_object = None

    def reload(self):
        """reload and re-initialize the strategy module"""
        try:
            strategy_module = __import__(self.strategy_module_name)
            try:
                self.unload()
                reload(strategy_module)
                self.strategy_object = strategy_module.Strategy(self.gox)

            # pylint: disable=W0703
            except Exception:
                self.gox.debug(traceback.format_exc())

        except ImportError:
            self.gox.debug("### could not import %s.py"
                % self.strategy_module_name)
            self.gox.debug("### running without strategy module")



#
#
# main program
#

def main():
    """main funtion, called from within the curses.wrapper"""

    def curses_loop(stdscr):
        """This code runs within curses environment"""

        init_colors()

        gox = goxapi.Gox(secret, config)

        conwin = WinConsole(stdscr, gox)
        bookwin = WinOrderBook(stdscr, gox)
        statuswin = WinStatus(stdscr, gox)
        chartwin = WinChart(stdscr, gox)

        logwriter = LogWriter(gox)
        printhook = PrintHook(gox)
        strategy_manager = StrategyManager(gox, strat_mod_name)

        gox.start()
        try:
            while True:
                key = conwin.win.getch()
                if key == ord("q"):
                    break
                if key == curses.KEY_F4:
                    DlgNewOrderBid(stdscr, gox).modal()
                if key == curses.KEY_F5:
                    DlgNewOrderAsk(stdscr, gox).modal()
                if key == curses.KEY_F6:
                    DlgCancelOrders(stdscr, gox).modal()
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
                    gox.signal_keypress(gox, (key))

        except KeyboardInterrupt:
            gox.debug("got Ctrl+C, trying to shut down cleanly.")
            gox.debug("Hint: did you know you can also exit with 'q'?")

        strategy_manager.unload()
        gox.stop()
        printhook.close()
        logwriter.close()
        # The End.

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
        help="name of strategy module file, default=strategy.py")
    argp.add_argument('--protocol', action="store", default="",
        help="force protocol (socketio or websocket), ignore setting in .ini")
    argp.add_argument('--no-fulldepth', action="store_true", default="",
        help="do not download full depth (useful for debugging)")
    argp.add_argument('--no-history', action="store_true", default="",
        help="do not download full history (useful for debugging)")
    args = argp.parse_args()

    config = goxapi.GoxConfig("goxtool.ini")
    secret = goxapi.Secret(config)
    if args.add_secret:
        # prompt for secret, encrypt, write to .ini and then exit the program
        secret.prompt_encrypt()
    else:
        strat_mod_name = args.strategy.replace(".py", "")
        goxapi.FORCE_PROTOCOL = args.protocol
        goxapi.FORCE_NO_FULLDEPTH = args.no_fulldepth
        goxapi.FORCE_NO_HISTORY = args.no_history
        if secret.prompt_decrypt() != secret.S_FAIL_FATAL:
            curses.wrapper(curses_loop)
            print
            print "*******************************************************"
            print "*  Please donate: 1D7ELjGofBiRUJNwK55DVC3XWYjfN77CA3  *"
            print "*******************************************************"


if __name__ == "__main__":
    main()

