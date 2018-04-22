from binaryninja import *
from binaryninja.plugin import BackgroundTaskThread, PluginCommand
import difflib

alignment = ["\xcc", "\xc3"]
suggestions = {"x86": ["\x55\x8b\xec",
                       "\x55\x89\xe5",
                       "\xff\x25",
                       "\x6a\x00\x68",
                       "\x55\x8b\x4c\x24",
                       "\x56\x8b\x4c\x24",
                       "\x8b\x4c\x24",
                       "\x55\x8b\x44\x24",
                       "\x56\x8b\x44\x24",
                       "\x8b\x44\x24",
                       "\x55\x8b\x54\x24",
                       "\x56\x8b\x54\x24",
                       "\x8b\x54\x24",
                       "\x8b\xff\x56",
                       "\x8b\xff\x55",
                       "\x51\x53\x8b\x1d",
                       "\x83\xec"],
               "x86_64": ["\x55\x48\x89\xe5",
                          "\x40\x53\x55\x56\x57\x41\x54\x41\x55\x41\x56\x48\x83\xec",
                          "\x40\x53\x55\x56\x57\x48\x83\xec",
                          "\x40\x53\x56\x57\x48\x83\xec",
                          "\x40\x53\x57\x48\x83\xec",
                          "\x40\x53\x48\x83\xec",
                          "\x40\x55\x48\x83\xec",
                          "\x48\x83\xec",
                          "\x48\x89\x5c",
                          "\x48\x8b\xc4",
                          "\x48\x8b\xd8",
                          "\x48\x81\xec",
                          "\x64\x48\x8b",
                          "\xff\x25"]}
MIN_PRO_COUNT = 10
MIN_IL = 10

CAUTIOUS = 0
AGGRESSIVE = 1
USER = 2
EXHAUSTIVE = 3

def model(bv):
    """

    :type bv: BinaryView
    """
    pros = {}
    br = BinaryReader(bv)
    current = 0
    while True:
        next_address = bv.get_next_function_start_after(current)
        if current == next_address:
            break
        current = next_address
        blocks = bv.get_basic_blocks_starting_at(current)
        if len(blocks) != 1:
            continue
        block = blocks[0]  # type: BasicBlock
        if block.length < MIN_IL:
            continue
        br.seek(current)
        pro = br.read(3)
        if pro in pros:
            pros[pro] += 1
        else:
            pros[pro] = 1
    ret = []
    for k in sorted(pros, key=pros.get, reverse=True):
        if pros[k] > MIN_PRO_COUNT:
            ret.append(k)
        else:
            break
    return ret


class Searcher(BackgroundTaskThread):
    def __init__(self, mode, bv, addr, size):
        BackgroundTaskThread.__init__(self, "Linear sweep", True)
        self.mode = mode
        self.bv = bv
        self.addr = addr
        self.size = size
        self.found = 0
        self.progress = "Linear sweep starting"

    def run(self):
        print "[linsweep] Waiting for analysis"
        self.bv.update_analysis_and_wait()
        if self.mode == USER:
            self.sweep_user(self.bv, self.addr, self.size)
        elif self.mode == EXHAUSTIVE:
            print "[linsweep] Exhaustive sweeping"
            for align in [16, 8, 4, 2]:
                go = True
                while go:
                    go = self.sweep_after(self.bv, align) > 32

            go = True
            while go:
                go = self.sweep_after(self.bv, 1) > 0
        else:
            self.sweep(self.bv, self.mode)
        print "[linsweep] Done, found: " + str(self.found)
        self.progress = "Linear sweep done"
        # interaction.show_message_box('Linear Sweep', "Created %d new functions" % self.found,
        #                              buttons=MessageBoxButtonSet.OKButtonSet)

    def prog(self, cur, end):
        self.progress = "Sweeping %d %d/%d" % (self.found, cur, end)

    def sweep_after(self, bv, align):
        """
        :type bv: BinaryView
        """
        found = 0
        br = BinaryReader(bv)

        create = []
        for segment in bv.segments:
            if not segment.executable:
                continue
            start = segment.start
            end = segment.end

            current = start
            while current < end:
                data = bv.get_next_data_after(current)
                if data <= current:
                    break

                current = data
                # next_code = bv.get_next_function_start_ after()
                next_code = bv.get_next_basic_block_start_after(current)
                if next_code > end:
                    next_code = end
                br.seek(current)

                c = 0
                go = True
                while go:
                    c += 1
                    if c > 1000:
                        c = 0
                        if not bv.is_offset_executable(br.offset):
                            raise "Error: " + hex(br.offset) + " not executable while sweeping from " + hex(current)
                    r = br.read8()
                    go = r == 0xCC or r == 0xC3
                current = br.offset - 1

                if current < next_code and current % align == 0:
                    create.append(current)

                current = next_code

        created = []
        for current in create:
            symbol = bv.get_symbol_at(current)
            if symbol is not None:
                continue
            data_var = bv.get_data_var_at(current)
            if data_var is not None:
                continue
            fn = bv.get_functions_containing(current)
            if not fn:
                found += 1
                self.found += 1
                bv.create_user_function(current)
                created.append(current)

        if found > 0:
            print "[linsweep] %3d functions created using EXHAUSTIVE (align=%d)" % (found, align)
            bv.update_analysis_and_wait()

        for current in created:
            fn = bv.get_function_at(current)
            if fn is not None:
                fn.name += '-E'

        return found

    def search(self, bv, align, pro, start, end, apnd=''):
        """
        :type bv: BinaryView
        :type align: str
        :type pro: str
        :type start: int
        :type end: int
        :type apnd: str
        """
        tgt = align + pro
        cur = start - 1
        found_here = 0
        while cur:
            cur = bv.find_next_data(cur + 1, tgt)
            if cur is None:
                break
            if pro == '':
                while True:
                    n = bv.find_next_data(cur + 1, tgt)

                    if n is None or (n - cur) > 1:
                        cur = cur + len(align)
                        break
                    cur = n
            else:
                cur += len(align)
            if cur >= end:
                break
            if bv.is_offset_executable(cur) and not bv.get_basic_blocks_at(cur):
                bv.create_user_function(cur)
                f = bv.get_function_at(cur)
                if f.name[0:4] == 'sub_':
                    # if len(f.low_level_il) < 5:
                    #     print "[linsweep] Removing Function At: %s" % f.name
                    #     bv.remove_user_function(f)
                    # else:
                    f.name = f.name + apnd
                found_here += 1
                self.found += 1
            # self.progress doesn't seem to do anything currently
            # self.prog(cur, end)
        if found_here > 0:
            bv.update_analysis_and_wait()
            print "[linsweep] %3d functions created using search: %s" % (found_here, tgt.encode('hex'))

    def find_functions(self, bv, tgts, start, end, apnd=''):
        for prologue in tgts:
            for align in alignment:
                self.search(bv, align, prologue, start, end, apnd)
            self.search(bv, '', prologue, start, end, apnd)

    def sweep(self, bv, mode):
        if bv.arch.name not in suggestions.keys():
            interaction.show_message_box('Linear Sweep',
                                         "Architecture [%s] not currently supported" % bv.arch.name,
                                         buttons=MessageBoxButtonSet.OKButtonSet, icon=MessageBoxIcon.ErrorIcon)
            return
        fs = len(bv.functions)
        print "[linsweep] Cautious Search Start"
        pros = model(bv)
        if '.text' in bv.sections:
            start = bv.sections['.text'].start
            end = bv.sections['.text'].end
        else:
            start = bv.start
            end = bv.end
        self.find_functions(bv, pros, start, end, "-C")
        fsc = len(bv.functions)
        print "[linsweep] Cautious: Found %d New Functions" % (fsc - fs)
        if mode == AGGRESSIVE:
            print "[linsweep] Aggressive Search Start"
            self.find_functions(bv, suggestions[bv.arch.name], bv.start, bv.end, "-A")
            for align in alignment:
                self.search(bv, align=align * 4, pro='', start=bv.start, end=bv.end, apnd="-P")
            print "[linsweep] Aggressive: Found %d New Functions" % (len(bv.functions) - fsc)

    def sweep_user(self, bv, addr, size):
        br = BinaryReader(bv)
        br.seek(addr)
        tgt = [br.read(size)]
        print "[linsweep] User Defined Search Start"
        fs = len(bv.functions)
        self.find_functions(bv, tgt, bv.start, bv.end, "-U")
        print "[linsweep] User: Found %d New Functions" % (len(bv.functions) - fs)
        interaction.show_message_box('Linear Sweep', "Created %d new functions" % (len(bv.functions) - fs),
                                     buttons=MessageBoxButtonSet.OKButtonSet)


PluginCommand.register("Simple Linear Sweep - Cautious", "Search for existing prologues in text section",
                       lambda bv: Searcher(CAUTIOUS, bv, None, None).start())
PluginCommand.register("Simple Linear Sweep - Aggressive", "Search for function prologues from bv.start",
                       lambda bv: Searcher(AGGRESSIVE, bv, None, None).start())
PluginCommand.register("Simple Linear Sweep - Exhaustive", "Search for function prologues from bv.start",
                       lambda bv: Searcher(EXHAUSTIVE, bv, None, None).start())
PluginCommand.register_for_range("Simple Linear Sweep - User", "Search for selected data as a prologue",
                                 lambda bv, addr, size: Searcher(USER, bv, addr, size).start())

if "bv" in locals():
    # noinspection PyUnresolvedReferences
    print "Detected execfile from console " + str(bv)
    print "Starting aggressive search"
    # noinspection PyUnresolvedReferences
    Searcher(EXHAUSTIVE, bv, None, None).start()
