#!/usr/bin/python
"""GDB whereis command

Find and print where a given set of addresses are in the proc-maps of
the current inferior process

To use this command, source it into your .gdbinit file:
   source /path/to/checkaddr.py
"""

import gdb

class ProcMapsStruct():
    """Represents a single proc maps entry"""
    def __init__(self, line):
        """Instantiates the object by parsing the given proc-maps line
        A proc-maps line is of the form:
        55a921d1c000-55a921d24000 r-xp 00000000 08:23 1183186   /usr/bin/cat
        """
        self.line = line.strip()
        self.perms = line.split(' ')[1]
        self.name = line.split(' ')[-1]
        addrs = line.split(' ')[0]
        self.start = int(addrs.split('-')[0], 16)
        self.end = int(addrs.split('-')[1], 16)

    def __str__(self):
        return "{0:s} (size: {1:d} Bytes)".format(self.line,
                                                  self.end - self.start)

    def __repr__(self):
        return str(self)

    def within_range(self, addr):
        # type: (int) -> bool
        """Returns true if the given address is within this proc-map entry"""
        return addr >= self.start and addr < self.end

    def offset(self, addr):
        # type: (int) -> int
        """Returns offset of addr from beginning of proc-map region"""
        return addr - self.start

class CheckAddress(gdb.Command):
    """Print where the given addresses are in the proc maps of the current process
    Usage: whereis [addr1] [addr2] [addr3] ...
    Prints the memory maps if no addresses were given
    """

    def __init__(self):
        super(CheckAddress, self).__init__("whereis", gdb.COMMAND_USER)
        self.proc_map = []

    def find_containing_procentry(self, addr):
        # type: (int) -> ProcMapsStruct
        """Returns the ProcMapEntry object containing the given address,
           or None if the address is not in any proc maps entry
        """
        return next((x for x in self.proc_map if x.within_range(addr)), None)

    def read_procmaps(self, pid):
        # type: (int) -> List[ProcMapsStruct]
        """Reads the proc-maps for the given pid and constructs
           an array of ProcMapsStruct objects """
        with open("/proc/" + str(pid) + "/maps", 'r') as f:
            self.proc_map = [ProcMapsStruct(line) for line in f.readlines()]

    def print_procmaps(self):
        # type: (int) -> void
        """Prints the proc maps of the current process"""
        for ent in self.proc_map:
            print(str(ent))

    def get_symbol_addr(self, symname):
        # type: (str) -> (str, str)
        """Returns a (str, address) tuple for the given symbol name """
        (sym, found) = gdb.lookup_symbol(symname)
        if sym is None or sym.type is None:
            val = gdb.parse_and_eval(symname)
            return (str(symname), str(val))
        if sym.type.code in (gdb.TYPE_CODE_STRUCT,
                             gdb.TYPE_CODE_INT,
                             gdb.TYPE_CODE_FLT,
                             gdb.TYPE_CODE_CHAR,
                             gdb.TYPE_CODE_PTR):
            addr = str(sym.value(gdb.selected_frame()).address)
            return ("&{0:s}".format(symname), addr)
        if sym.type.code == gdb.TYPE_CODE_FUNC:
            long_int_t = gdb.Value(1).type
            return ("&{0:s}".format(symname), str(sym.value().cast(long_int_t)))
        return (str(symname), str(0))

    def invoke(self, arg, from_tty):
        """Invoked when the command is executed from GDB"""
        cur_proc = gdb.selected_inferior()
        if not cur_proc.is_valid() or cur_proc.pid <= 0:
            return
        self.read_procmaps(cur_proc.pid)
        args = gdb.string_to_argv(arg)
        if len(args) == 0 and from_tty:
            self.print_procmaps()
            return
        for a in args:
            addr = 0
            try:
                addr = int(a, 0)
            except ValueError:
                # a is a string
                (s1, s2) = self.get_symbol_addr(a)
                addr = int(s2, 0)
                print("{0:s}:".format(s1)),
            entry = self.find_containing_procentry(addr)
            if  entry != None:
              print("0x{0:x}, Offset: 0x{1:x}:\n{2:s}".format(addr, entry.offset(addr), str(entry)))
            else:
              print("0x{0:x}, Offset: None:\n{1:s}".format(addr, str(entry)))

CheckAddress()
