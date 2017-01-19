#!/usr/bin/python
"""GDB lfd command

List the proc fds of a given pid or the current inferior
process

To use this command, source it into your .gdbinit file:
   source /path/to/lfd.py
"""

import gdb

class Lfd(gdb.Command):
    """List the proc fds
    Usage: whereis [pid]
Prints the proc fd listing of the process with the given pid, or
prints the proc fd listing of the current inferior process if
no pid was specified.
    """

    def __init__(self):
        super(Lfd, self).__init__("lfd", gdb.COMMAND_USER)
        self.proc_map = []

    def get_procfds(self, pid):
        """Returns the proc fd listing of the process with the given pid"""
        return gdb.execute("shell ls -l /proc/{0:d}/fd".format(pid),
                           False,
                           True)

    def invoke(self, arg, from_tty):
        """Invoked when the command is executed from GDB"""
        args = gdb.string_to_argv(arg)
        cur_proc = gdb.selected_inferior()
        if not cur_proc.is_valid() and len(args) == 0:
            return
        pid = cur_proc.pid
        if len(args) > 0:
            pid = int(args[0], 0)
        out = self.get_procfds(pid)
        if from_tty:
            print(out)
        return out
Lfd()
