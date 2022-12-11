#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
#**************************************************************************
#
#   Copyright (c) 2022 by Petri Damstén <petri.damsten@iki.fi>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the
#   Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
#**************************************************************************

# json file example (main keyboard = 47)
#
# {
#   "port": 7563,
#   "keyboard": 40,
#   "keymap":[
#     50, 27, 24, 114, 115, 116, 117, 119, 121, 48, 53, 49,
#     69, 78, 67, 75, 43, 47, 44, 41, 39, 33, 30, 42,
#     83, 84, 85, 86, 87, 88, 89, 91, 92, 82, 65, 76,
#     122, 120, 99, 118, 96, 97, 98, 100, 101, 109, 103, 111,
#     16, 6, 18, 19, 20, 21, 23, 22, 26, 28, 25, 29,
#     46, 45, 31, 35, 12, 15, 1, 17, 32, 9, 13, 7,
#     0, 11, 8, 2, 14, 3, 5, 4, 34, 38, 40, 37
#   ],
#   "apps": {
#     "Adobe Photoshop 2022": {
#       "*": "shift+cmd+f10"
#     }
#   }
# }

import Quartz
import signal
import sys
import socketserver
import threading
from AppKit import NSWorkspace
import json
import os
import time
import logging
import run

FILTER = 'abcdefghijklmnopqrstuvwxyzåäö1234567890,;+'
SETUP = os.path.dirname(os.path.realpath(__file__)) + '/macro_kb.json'
LOG = os.path.dirname(os.path.realpath(__file__)) + '/macro_handler.log'
settings = None

logging.basicConfig(
    filename = LOG,
    level = logging.DEBUG,
    format = '%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt = '%Y-%m-%d %H:%M:%S',
)

def kill_previous():
    pids = [os.getppid(), os.getpid()]
    path = os.path.dirname(os.path.realpath(__file__)) + '/macro_handler'
    r = run.cmd(f'ps -A | grep {path}')
    for l in r[1].splitlines()[:-2]:
        pid = int(l.strip().split(' ', 1)[0])
        if pid not in pids:
            logging.debug(f'KILLING {pid}')
            try:
                os.kill(pid, signal.SIGTERM)
            except:
                logging.info(f'Failed to kill {pid}')

    time.sleep(0.5)

# Signals

def terminate(sig, frame):
    logging.info('Exiting')
    sys.exit(0)

def set_sigmals():
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGHUP, terminate)
    signal.signal(signal.SIGTERM, terminate)

# TCP server

class KeyRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            global last_key
            cmd = self.rfile.readline().strip().decode("utf-8")
            if cmd == 'GET':
                logging.debug(cmd + ' ' + str(last_key))
                self.wfile.write(str(last_key).encode())
            if cmd.startswith('PUT'):
                # We probably have key pressed down from macro kb press. Wait it to go away before this.
                logging.debug(cmd)
                ptimer = threading.Timer(0.225, lambda: send_key_press(cmd[4:]))
                ptimer.start()
        except:
            logging.exception("handle")

def tcp_server():
    global settings

    try:
        server = socketserver.TCPServer(("127.0.0.1", settings['port']), KeyRequestHandler)
        server.serve_forever()
    except:
        logging.exception("tcp_server")

def start_server():
    try:
        daemon = threading.Thread(target = tcp_server)
        daemon.daemon = True
        daemon.start()
    except:
        logging.exception("start_server")

# Keyboard handling

last_key = -1 # Only modified in one place. Thread safe?
utimer = None
modifiers = 0

def macro_keyboard_event(event, key, app):
    try:
        if app in settings['apps']:
            k = app
        elif '*' in settings['apps']:
            k = '*'
        else:
            return
        if str(key) in settings['apps'][k]:
            macro = settings['apps'][k][str(key)]
        elif '*' in settings['apps'][k]:
            macro = settings['apps'][k]['*']
        else:
            return
        macro = macro.split('|')
        logging.debug(f'macro {macro}')
        if len(macro) > 1:
            logging.debug(f'DOWN/UP event')
            n = 0 if event == Quartz.kCGEventKeyDown else 1
            send_key_press(macro[n])
        else:
            logging.debug(f'normal event {macro[0]}')
            send_key_event(macro[0], event)
    except:
        logging.exception("macro_keyboard_event")

def set_modifiers(s, key_down):
    global modifiers

    if s in ['shift', 'shift_r']:
        modifiers = modifiers | Quartz.kCGEventFlagMaskShift if (key_down) else modifiers & ~Quartz.kCGEventFlagMaskShift
    elif s in ['ctrl', 'ctrl_r']:
        modifiers = modifiers | Quartz.kCGEventFlagMaskControl if (key_down) else modifiers & ~Quartz.kCGEventFlagMaskControl
    elif s in ['alt', 'alt_r']:
        modifiers = modifiers | Quartz.kCGEventFlagMaskAlternate if (key_down) else modifiers & ~Quartz.kCGEventFlagMaskAlternate
    elif s in ['cmd', 'cmd_r']:
        modifiers = modifiers | Quartz.kCGEventFlagMaskCommand if (key_down) else modifiers & ~Quartz.kCGEventFlagMaskCommand

def send_key_tap(s, key_down):
    try:
        if s in settings['keycodes']:
            kc = settings['keycodes'][s]
            logging.debug(f'TAP: {kc}, {key_down} {modifiers}')
            e = Quartz.CGEventCreateKeyboardEvent(None, kc, key_down)
            # Prevents us from getting these events again
            Quartz.CGEventSetIntegerValueField(e, Quartz.kCGKeyboardEventKeyboardType, settings['mainkeyboard'])
            if key_down:
                set_modifiers(s, True)
            Quartz.CGEventSetFlags(e, modifiers)
            if not key_down:
                set_modifiers(s, False)
            Quartz.CGEventPost(Quartz.kCGHIDEventTap, e)
                
            time.sleep(0.001)
        else:
            logging.info(f'{s} not found')
    except:
        logging.exception("send_key_tap")

def send_key_press(s):
    send_key_event(s, Quartz.kCGEventKeyDown)
    time.sleep(0.050)
    send_key_event(s, Quartz.kCGEventKeyUp)

def send_key_event(s, etype):
    a = ''.join(list(filter(lambda ch : ch in FILTER, s.lower()))).split('+')
    if etype == Quartz.kCGEventKeyUp:
        a.reverse()
    for k in a:
        if (k == ''):
            continue
        if etype == Quartz.kCGEventKeyUp:
            logging.debug(f'UP {k}')
            send_key_tap(k, False)
        elif etype == Quartz.kCGEventKeyDown:
            logging.debug(f'DOWN {k}')
            send_key_tap(k, True)

def parse_flags(flags):
    res = 0
    if Quartz.kCGEventFlagMaskShift & flags:
        res += 1000
    if Quartz.kCGEventFlagMaskControl & flags:
        res += 2000
    if Quartz.kCGEventFlagMaskAlternate & flags:
        res += 4000
    if Quartz.kCGEventFlagMaskCommand & flags:
        res += 8000
    return res

def keyCallback(proxy, etype, event, refcon):
    global last_key
    global utimer

    try:
        ktype = Quartz.CGEventGetIntegerValueField(event, Quartz.kCGKeyboardEventKeyboardType)
        #logging.debug(f'Event {ktype}')
        if ktype == settings['keyboard']:

            key_code = Quartz.CGEventGetIntegerValueField(event, Quartz.kCGKeyboardEventKeycode)

            if etype == Quartz.kCGEventKeyDown and key_code in settings['keymap']:
                key = settings['keymap'].index(key_code)
                key += parse_flags(Quartz.CGEventGetFlags(event))
                try:
                    current_app = NSWorkspace.sharedWorkspace().activeApplication()['NSApplicationName']
                except:
                    return
                logging.debug(f'{current_app}, {key_code}, {key}, {etype == Quartz.kCGEventKeyDown}')
                if utimer and utimer.is_alive() and key == last_key:
                    # Key repeat, keep key down
                    utimer.cancel()
                    utimer = threading.Timer(0.225, 
                            lambda: macro_keyboard_event(Quartz.kCGEventKeyUp, key, current_app))
                    utimer.start()
                else:
                    dtimer = threading.Timer(0.025, 
                            lambda: macro_keyboard_event(Quartz.kCGEventKeyDown, key, current_app))
                    dtimer.start()
                    # we ignore keyup. it comes right after down even if user keeps key down.
                    # timer handles up when no key repeat occurs.
                    utimer = threading.Timer(0.225, 
                            lambda: macro_keyboard_event(Quartz.kCGEventKeyUp, key, current_app))
                    utimer.start()
                last_key = key
            return
        return event
    except:
        logging.exception("darwin")

def main():
    global settings

    logging.info('Starting')
    kill_previous()

    with open(SETUP) as json_file:
        settings = json.load(json_file)
    set_sigmals()
    start_server()

    tap = Quartz.CGEventTapCreate(
        Quartz.kCGSessionEventTap,
        Quartz.kCGHeadInsertEventTap,
        Quartz.kCGEventTapOptionDefault,
        Quartz.CGEventMaskBit(Quartz.kCGEventKeyDown) |
            Quartz.CGEventMaskBit(Quartz.kCGEventKeyUp) |
            Quartz.CGEventMaskBit(Quartz.kCGEventFlagsChanged),
        keyCallback,
        None
    )
    if tap:
        rls = Quartz.CFMachPortCreateRunLoopSource(Quartz.kCFAllocatorDefault, tap, 0)
        Quartz.CFRunLoopAddSource(Quartz.CFRunLoopGetCurrent(), rls, Quartz.kCFRunLoopCommonModes)
        Quartz.CGEventTapEnable(tap, True)
        Quartz.CFRunLoopRun()
    else:
        logging.error("failed to start keyboard loop.")

try:
    main()
except Exception as e:
    logging.exception("main")
