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

from ghidrafrida import arch, util


@pytest.fixture
def system(monkeypatch):
    """Make util.dbg a stand-in device reporting the given arch/platform."""
    monkeypatch.setattr(util, 'conv_map', {})

    def _set(arch_name, platform='linux'):
        class FakeDbg:
            def query_system_parameters(self):
                return {'arch': arch_name, 'platform': platform}
        monkeypatch.setattr(util, 'dbg', FakeDbg())
    return _set


# Frida reports one of these for query_system_parameters()['arch']
@pytest.mark.parametrize('frida_arch,expected', [
    ('x64', 'x86:LE:64:default'),
    ('ia32', 'x86:LE:32:default'),
    ('arm64', 'AARCH64:LE:64:v8A'),
    ('arm', 'ARM:LE:32:v8'),
    ('mips', 'MIPS:LE:32:default'),
])
def test_language_for_frida_arch_names(system, frida_arch, expected):
    system(frida_arch)
    assert arch.compute_ghidra_language() == expected


@pytest.mark.parametrize('frida_arch,expected', [
    ('arm64', 'AARCH64:BE:64:v8A'),
    ('arm', 'ARM:BE:32:v8'),
    ('mips', 'MIPS:BE:32:default'),
])
def test_big_endian_selection(system, frida_arch, expected):
    system(frida_arch)
    util.set_convenience_variable('endian', 'big')
    assert arch.compute_ghidra_language() == expected


def test_ia32_uses_x86_compilers(system):
    system('ia32', 'windows')
    assert arch.compute_ghidra_lcsp() == ('x86:LE:32:default', 'windows')


def test_unknown_arch_falls_back_to_data(system):
    system('sparc64')
    assert arch.compute_ghidra_language() == 'DATA:LE:64:default'
