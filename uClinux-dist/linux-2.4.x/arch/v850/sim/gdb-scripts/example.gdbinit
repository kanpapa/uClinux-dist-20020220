# Copy this file to `.gdbinit' in the directory where you will run linux
# (for instance, the top-level of the kernel build tree).  Invoking gdb
# will then start the simulator and load linux into it.  You should
# start gdb using a command like `v850e-elf-gdb linux'.

set height 0
set pagination off

disp/i $pc

target sim
sim architecture v850e

sim memory delete all
sim memory region 0,0x800000
sim memory region 0xFFFF0000,0x10000

# Protect the kernel's text segment against writing.  These addresses
# are somewhat conservative, but might need to be changed if the kernel
# text-segment shrinks appreciably.
sim read-protect-low-memory 0x4a000
sim write-protect-low-memory 0x4a000

# 24Hz @1/10 speed = 2.4Hz
sim watch-clock-intov1 +420

sim stdio off

# Change `linux' to match the name of the file containing the kernel.
load linux
