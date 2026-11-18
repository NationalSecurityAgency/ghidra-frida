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
import pytest

from ghidrafrida import util


def _new_base(device_id):
    # Run only the device-selection step of GhidraDbg, without its worker thread
    dbg = object.__new__(util.GhidraDbg)
    dbg._device_id = device_id
    dbg._new_base()
    return dbg


@pytest.mark.parametrize('device_id,expected', [
    ('local', ('get_local_device',)),
    ('remote', ('get_remote_device',)),
    ('usb', ('get_usb_device',)),
    ('socket@10.0.0.2:27042', ('get_device', 'socket@10.0.0.2:27042')),
])
def test_device_selection(monkeypatch, device_id, expected):
    calls = []
    for name in ('get_local_device', 'get_remote_device', 'get_usb_device', 'get_device'):
        monkeypatch.setattr(util.frida, name,
                            lambda *args, name=name: calls.append((name,) + args))
    _new_base(device_id)
    assert calls == [expected]
