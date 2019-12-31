#
# Copyright 2019 Delphix
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import gdb

def symbol_address(symbol):
    sym = gdb.lookup_global_symbol(symbol)
    if sym == None:
        sym = gdb.lookup_symbol(symbol)[0]
    if sym is not None:
        return sym.value().address
    return None

def alloc_list_iter(func):
        head = symbol_address("dmem_alloc_list_head");
        p = head['dae_next']
        while int(p) != 0x0 and p != head:
            func(p)
            p = p['dae_next']

class WalkAllocatedBuffers(gdb.Command):
    def __init__(self) -> None:
        super().__init__("walk_alloc_bufs", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        sizeof_dae = gdb.lookup_type('dmem_alloc_entry_t').sizeof
        alloc_list_iter((lambda p: print(hex(int(int(p) + sizeof_dae)))))
WalkAllocatedBuffers()

class WalkAllocatedEntries(gdb.Command):
    def __init__(self) -> None:
        super().__init__("walk_alloc_entries", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        sizeof_dae = gdb.lookup_type('dmem_alloc_entry_t').sizeof
        alloc_list_iter(print)
WalkAllocatedEntries()

class ShowAllocStacks(gdb.Command):
    def __init__(self) -> None:
        super().__init__("show_alloc_stacks", gdb.COMMAND_DATA)

    @staticmethod
    def print_stack(entry):
        trace = entry['dae_tx']
        print(f"{entry} allocated from {hex(trace['dt_thread'])} at:")
        for f in range(11):
            frame = trace['dt_stack'][f]
            if int(frame) == 0x0:
                break
            pretty_frame = str(frame).split('<')[1][:-1]
            print(f"\t{pretty_frame}")
        print()

    def invoke(self, arg, from_tty):
        alloc_list_iter(self.print_stack)
ShowAllocStacks()
