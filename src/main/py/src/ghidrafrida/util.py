## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
from collections import namedtuple
from concurrent.futures import Future
import concurrent.futures
#from ctypes import *
from dataclasses import dataclass
import functools
import io
import os
import queue
import re
import sys
import threading
import traceback
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, TypeVar, Union, cast

import frida # type: ignore

@dataclass(frozen=True)
class DbgVersion:
	full: str
	name: str
	dotted: str
	arch: str

targets = {}
processes = {}
current_state = {}
current_state['sid'] = 'local'
current_state['pid'] = None
current_state['tid'] = None
current_state['fid'] = None

class _Worker(threading.Thread):
    def __init__(self, new_base, work_queue, dispatch):
        super().__init__(name='DbgWorker', daemon=True)
        self.new_base = new_base
        self.work_queue = work_queue
        self.dispatch = dispatch

    def run(self):
        self.new_base()
        while True:
            try:
                work_item = self.work_queue.get_nowait()
            except queue.Empty:
                work_item = None
            if work_item is None:
                # HACK to avoid lockup on race condition
                try:
                    self.dispatch(100)
                except Exception as e:
                    # This is routine :
                    print(f"{e}")
                    pass
            else:
                work_item.run()


# Derived from Python core library
# https://github.com/python/cpython/blob/main/Lib/concurrent/futures/thread.py
# accessed 9 Jan 2024
class _WorkItem(object):
    def __init__(self, future, fn, args, kwargs):
        self.future = future
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
        except BaseException as exc:
            self.future.set_exception(exc)
            # Python core lib does this, I presume for good reason
            self = None
        else:
            self.future.set_result(result)


class DebuggeeRunningException(BaseException):
    pass


T = TypeVar('T')


class DbgExecutor(object):
    def __init__(self, ghidra_dbg: 'GhidraDbg') -> None:
        self._ghidra_dbg = ghidra_dbg
        self._work_queue = queue.SimpleQueue()
        self._thread = _Worker(ghidra_dbg._new_base,
                               self._work_queue, ghidra_dbg._dispatch_events)
        self._thread.start()
        self._executing = False

    def submit(self, fn, /, *args, **kwargs):
        f = self._submit_no_exit(fn, *args, **kwargs)
        self._ghidra_dbg.exit_dispatch()
        return f

    def _submit_no_exit(self, fn, /, *args, **kwargs):
        f = Future()
        if self._executing:
            f.set_exception(DebuggeeRunningException("Debuggee is Running"))
            return f
        w = _WorkItem(f, fn, args, kwargs)
        self._work_queue.put(w)
        return f

    def _clear_queue(self):
        while True:
            try:
                work_item = self._work_queue.get_nowait()
            except queue.Empty:
                return
            work_item.future.set_exception(
                DebuggeeRunningException("Debuggee is Running"))

    def _state_execute(self):
        self._executing = True
        self._clear_queue()

    def _state_break(self):
        self._executing = False


class WrongThreadException(BaseException):
    pass


C = TypeVar('C', bound=Callable[..., Any])


class GhidraDbg(object):
    def __init__(self, device_id: Any) -> None:
        self._device_id = device_id
        self._queue = DbgExecutor(self)
        self._thread = self._queue._thread
        # Wait for the executor to be operational before getting base
        self._queue._submit_no_exit(lambda: None).result()
        self._install_stdin()

        base = self._protected_base
        for name in ['attach', 'bus', 'disable_spawn_gating', 'enable_spawn_gating', 
                     'enumerate_applications', 'enumerate_pending_children', 
                     'enumerate_pending_spawn', 'enumerate_processes', 
                     'get_bus', 'get_frontmost_application', 'get_process', 
                     'icon', 'id', 'inject_library_blob', 'inject_library_file', 
                     'input', 'is_lost', 'kill', 'name', 'off', 'on', 'open_channel', 
                     'query_system_parameters', 'resume', 'spawn', 'type', 'unpair'
                     ]:
            setattr(self, name, self.eng_thread(getattr(base, name)))

    def _new_base(self) -> None:
        if self._device_id == "local":
            self._protected_base = frida.get_local_device()
        elif self._device_id == "remote":
            self._protected_base = frida.get_remote_device()
        elif self._device_id == "usb":
            self._protected_base = frida.get_usbl_device()
        else:
            self._protected_base = frida.get_device(self._device_id)

    @property
    def _base(self) -> Any:
        return self._protected_base

    def run(self, fn: Callable[..., T], *args, **kwargs) -> T:
        # TODO: Remove this check?
        if hasattr(self, '_thread') and threading.current_thread() is self._thread:
            raise WrongThreadException()
        future = self._queue.submit(fn, *args, **kwargs)
        # https://stackoverflow.com/questions/72621731/is-there-any-graceful-way-to-interrupt-a-python-concurrent-future-result-call gives an alternative
        while True:
            try:
                return future.result(0.5)
            except concurrent.futures.TimeoutError:
                pass

    def run_async(self, fn: Callable[..., T], *args, **kwargs) -> Future[T]:
        return self._queue.submit(fn, *args, **kwargs)

    def check_thread(func: C) -> C:
        '''
        For methods inside of GhidraDbg, ensure it runs on the engine
        thread
        '''
        @functools.wraps(func)
        def _func(self, *args, **kwargs) -> Any:
            if threading.current_thread() is self._thread:
                return func(self, *args, **kwargs)
            else:
                return self.run(func, self, *args, **kwargs)
        return cast(C, _func)

    def eng_thread(self, func: C) -> C:
        '''
        For methods and functions outside of GhidraDbg, ensure it
        runs on this GhidraDbg's engine thread
        '''
        @functools.wraps(func)
        def _func(*args, **kwargs):
            if threading.current_thread() is self._thread:
                return func(*args, **kwargs)
            else:
                return self.run(func, *args, **kwargs)
        return cast(C, _func)

    @check_thread
    def _install_stdin(self) -> None:
        pass

    # Manually decorated to preserve undecorated
    def _dispatch_events(self, timeout: int = -1) -> None:
         pass
    dispatch_events = check_thread(_dispatch_events)

    # no check_thread. Must allow reentry
    def exit_dispatch(self):
        pass


dbg = None
device = os.getenv('OPT_TARGET_DEVICE')
if device is not None:
    dbg = GhidraDbg(device)


DBG_VERSION = frida.__version__

def on_message_to_file(message: Dict[str, Any], data: Any) -> None:
    f = open("script_results", "w")
    f.write(str(message['payload']))
    f.close()

def on_message_print(message: Dict[str, Any], data: Any) -> None:
    print(f"{message}, {data}")
    

def load_permanent_script(name: str, text: str, callback: Callable) -> None:
    pid = selected_process()
    if pid is None:
        print(f"no selection for process")
        return
    target = targets[pid]
    script = target.create_script(text)
    script.on('message', callback)
    script.load()


def run_script_no_ret(name: str, text: str, callback: Callable) -> None:
    pid = selected_process()
    if pid is None:
        print(f"no selection for process")
        return
    target = targets[pid]
    script = target.create_script(text)
    script.on('message', callback)
    script.load()
    script.off('message', callback)
    script.unload()


def run_script(name: str, text: str, callback: Callable) -> None:
    pid = selected_process()
    if pid is None:
        print(f"no selection for process")
        return
    target = targets[pid]
    wrapped_text =  "var result = ''; " 
    wrapped_text += text
    wrapped_text += "var msg = { key: '" + name
    wrapped_text += "', value: result};"
    wrapped_text += "send(JSON.stringify(msg));"
    script = target.create_script(wrapped_text)
    script.on('message', callback)
    script.load()
    script.off('message', callback)
    script.unload()


def run_script_with_data(name: str, text: str, data: str, callback: Callable) -> None:
    pid = selected_process()
    if pid is None:
        print(f"no selection for process")
        return
    target = targets[pid]
    wrapped_text =  "var data = " + data + "; " 
    wrapped_text +=  "var result = ''; " 
    wrapped_text += text
    wrapped_text += "var msg = { key: '" + name
    wrapped_text += "', value: result, data: data};"
    wrapped_text += "send(JSON.stringify(msg));"
    script = target.create_script(wrapped_text)
    script.on('message', callback)
    script.load()
    script.off('message', callback)
    script.unload()


def selected_session() -> Optional[int]:
    try:
        return current_state['sid']
    except Exception:
        return None



def selected_process() -> Optional[int]:
    try:
        return current_state['pid']
    except Exception:
        return None



def selected_thread() -> Optional[int]:
    try:
        return current_state['tid']
    except Exception:
        return None



def selected_frame() -> Optional[int]:
    try:
        return current_state['fid']
    except Exception:
        return None


def select_session(id: int) -> None:
    global current_state
    current_state['sid'] = id


def select_process(id: int) -> None:
    global current_state
    current_state['pid'] = id


def select_thread(id: int) -> None:
    global current_state
    current_state['tid'] = id


def select_frame(id: int) -> None:
    global current_state
    current_state['fid'] = id


def put_module_address(path: str, addr: Any) -> None:
    global current_state
    current_state[path] = addr
    

def get_module_address(path: str) -> Any:
    global current_state
    return current_state[path]
    

def parse_and_eval(expr: Union[str, int],
                   type: Optional[int] = None) -> int:
    return int(expr)


conv_map: Dict[str, str]  = {}


def get_convenience_variable(id: str) -> Any:
    if id not in conv_map:
        return "auto"
    val = conv_map[id]
    if val is None:
        return "auto"
    return val


def set_convenience_variable(id: str, value: Any) -> None:
    conv_map[id] = value
