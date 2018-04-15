from binaryninja import *
from binaryninja.plugin import BackgroundTaskThread, PluginCommand

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
                          "\x48\x81\xec",
                          "\x64\x48\x8b",
                          "\xff\x25"]}
MIN_PRO_COUNT = 8
MIN_IL = 10

CAUTIOUS = 0
AGGRESSIVE = 1
USER = 2


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
        if self.mode == CAUTIOUS:
            self.sweep(self.bv, CAUTIOUS)
        elif self.mode == AGGRESSIVE:
            self.sweep(self.bv, AGGRESSIVE)
        elif self.mode == USER:
            self.sweep_user(self.bv, self.addr, self.size)
        self.progress = "Linear sweep done"

    def model(self, bv):
        pros = {}
        br = BinaryReader(bv)
        for f in bv.functions:
            if len(f.low_level_il) < MIN_IL:
                continue
            br.seek(f.start)
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

    def search(self, bv, align, pro, start, end, apnd=''):
        tgt = align + pro
        cur = bv.find_next_data(start, tgt)
        funcs = len(bv.functions)
        while cur:
            if pro == '':
                while True:
                    n = bv.find_next_data(cur + 1, tgt)
                    if n is None or (n - cur) > 1:
                        cur = cur + len(align)
                        break
                    cur = n
            else:
                cur += len(align)
            if cur > end:
                break
            if not bv.get_basic_blocks_at(cur):
                bv.add_function(cur)
                bv.update_analysis_and_wait()
                f = bv.get_function_at(cur)
                if f.name[0:4] == 'sub_':
                    # if len(f.low_level_il) < 5:
                    #     print "[linsweep] Removing Function At: %s" % f.name
                    #     bv.remove_user_function(f)
                    # else:
                    f.name = f.name + apnd
                self.found += 1
            self.progress = "Sweeping %d at %d/%d" % (self.found, cur, end)
            cur = bv.find_next_data(cur + 1, tgt)
        if len(bv.functions) > funcs:
            print "[linsweep] %3d functions created using search: %s" % (
                len(bv.functions) - funcs, tgt.encode('hex'))

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
        pros = self.model(bv)
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
            self.search(bv, align="\xcc" * 4, pro='', start=bv.start, end=bv.end, apnd="-P")
            print "[linsweep] Aggressive: Found %d New Functions" % (len(bv.functions) - fsc)
        interaction.show_message_box('Linear Sweep', "Created %d new functions" % (len(bv.functions) - fs),
                                     buttons=MessageBoxButtonSet.OKButtonSet)

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
PluginCommand.register_for_range("Simple Linear Sweep - User", "Search for selected data as a prologue",
                                 lambda bv, addr, size: Searcher(USER, bv, addr, size).start())
