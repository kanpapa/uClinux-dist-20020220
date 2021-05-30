#! /usr/bin/env python

# Print the product of age and size of each file, in suitable units.
#
# Usage: byteyears [ -a | -m | -c ] file ...
#
# Options -[amc] select atime, mtime (default) or ctime as age.

import sys, os, time
import string
from stat import *

# Use lstat() to stat files if it exists, else stat()
try:
	statfunc = os.lstat
except AttributeError:
	statfunc = os.stat

# Parse options
if sys.argv[1] == '-m':
	itime = ST_MTIME
	del sys.argv[1]
elif sys.argv[1] == '-c':
	itime = ST_CTIME
	del sys.argv[1]
elif sys.argv[1] == '-a':
	itime = ST_CTIME
	del sys.argv[1]
else:
	itime = ST_MTIME

secs_per_year = 365.0 * 24.0 * 3600.0	# Scale factor
now = time.time()			# Current time, for age computations
status = 0				# Exit status, set to 1 on errors

# Compute max file name length
maxlen = 1
for file in sys.argv[1:]:
	if len(file) > maxlen: maxlen = len(file)

# Process each argument in turn
for file in sys.argv[1:]:
	try:
		st = statfunc(file)
	except os.error, msg:
		sys.stderr.write('can\'t stat ' + `file` + ': ' + `msg` + '\n')
		status = 1
		st = ()
	if st:
		anytime = st[itime]
		size = st[ST_SIZE]
		age = now - anytime
		byteyears = float(size) * float(age) / secs_per_year
		print string.ljust(file, maxlen),
		print string.rjust(`int(byteyears)`, 8)

sys.exit(status)
