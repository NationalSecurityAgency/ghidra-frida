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
"""
These tests cover the parts of ghidrafrida that run without a Frida device,
a frida-server, or a running Ghidra. They need ghidratrace (from Ghidra's
Debugger-rmi-trace/pypkg/dist) and frida installed, because the modules
import both at load time.
"""
import os
import sys

# Importing ghidrafrida.util with OPT_TARGET_DEVICE set opens a Frida device
os.environ.pop('OPT_TARGET_DEVICE', None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
