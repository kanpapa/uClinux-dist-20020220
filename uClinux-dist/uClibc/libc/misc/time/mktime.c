
/* This is adapted from glibc */
/* Copyright (C) 1993, 1994, 1995, 1996, 1997 Free Software Foundation, Inc. */


/* Assume that leap seconds are possible, unless told otherwise.
   If the host has a `zic' command with a -L leapsecondfilename' option,
   then it supports leap seconds; otherwise it probably doesn't.  */
#ifndef LEAP_SECONDS_POSSIBLE
#define LEAP_SECONDS_POSSIBLE 1
#endif

#include <sys/types.h>			/* Some systems define `time_t' here.  */
#include <time.h>

#if __STDC__ || __GNU_LIBRARY__ || STDC_HEADERS
#include <limits.h>
#endif

#if DEBUG
#include <stdio.h>
#if __STDC__ || __GNU_LIBRARY__ || STDC_HEADERS
#include <stdlib.h>
#endif
/* Make it work even if the system's libc has its own mktime routine.  */
#define mktime my_mktime
#endif							/* DEBUG */

#ifndef __P
#if defined (__GNUC__) || (defined (__STDC__) && __STDC__)
#define __P(args) args
#else
#define __P(args) ()
#endif							/* GCC.  */
#endif							/* Not __P.  */

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifndef INT_MIN
#define INT_MIN (~0 << (sizeof (int) * CHAR_BIT - 1))
#endif
#ifndef INT_MAX
#define INT_MAX (~0 - INT_MIN)
#endif

#ifndef TIME_T_MIN
#define TIME_T_MIN (0 < (time_t) -1 ? (time_t) 0 \
                    : ~ (time_t) 0 << (sizeof (time_t) * CHAR_BIT - 1))
#endif
#ifndef TIME_T_MAX
#define TIME_T_MAX (~ (time_t) 0 - TIME_T_MIN)
#endif

#define TM_YEAR_BASE 1900
#define EPOCH_YEAR 1970

#ifndef __isleap
/* Nonzero if YEAR is a leap year (every 4 years,
   except every 100th isn't, and every 400th is).  */
#define __isleap(year)  \
  ((year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0))
#endif

/* How many days come before each month (0-12).  */
const unsigned short int __mon_yday[2][13] = {
	/* Normal years.  */
	{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
	/* Leap years.  */
	{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
};

static time_t ydhms_tm_diff

__P((int, int, int, int, int, const struct tm *));
time_t __mktime_internal
__P((struct tm *, struct tm * (*)(const time_t *, struct tm *), time_t *));

/* Yield the difference between (YEAR-YDAY HOUR:MIN:SEC) and (*TP),
   measured in seconds, ignoring leap seconds.
   YEAR uses the same numbering as TM->tm_year.
   All values are in range, except possibly YEAR.
   If overflow occurs, yield the low order bits of the correct answer.  */
static time_t ydhms_tm_diff(year, yday, hour, min, sec, tp)
int year, yday, hour, min, sec;
const struct tm *tp;
{
	/* Compute intervening leap days correctly even if year is negative.
	   Take care to avoid int overflow.  time_t overflow is OK, since
	   only the low order bits of the correct time_t answer are needed.
	   Don't convert to time_t until after all divisions are done, since
	   time_t might be unsigned.  */
	int a4 = (year >> 2) + (TM_YEAR_BASE >> 2) - !(year & 3);
	int b4 = (tp->tm_year >> 2) + (TM_YEAR_BASE >> 2) - !(tp->tm_year & 3);
	int a100 = a4 / 25 - (a4 % 25 < 0);
	int b100 = b4 / 25 - (b4 % 25 < 0);
	int a400 = a100 >> 2;
	int b400 = b100 >> 2;
	int intervening_leap_days = (a4 - b4) - (a100 - b100) + (a400 - b400);
	time_t years = year - (time_t) tp->tm_year;
	time_t days = (365 * years + intervening_leap_days

				   + (yday - tp->tm_yday));
	return (60 * (60 * (24 * days + (hour - tp->tm_hour))
				  + (min - tp->tm_min))
			+ (sec - tp->tm_sec));
}


/* This structure contains all the information about a
   timezone given in the POSIX standard TZ envariable.  */
typedef struct
  {
    const char *name;

    /* When to change.  */
    enum { J0, J1, M } type;	/* Interpretation of:  */
    unsigned short int m, n, d;	/* Month, week, day.  */
    unsigned int secs;		/* Time of day.  */

    long int offset;		/* Seconds east of GMT (west if < 0).  */

    /* We cache the computed time of change for a
       given year so we don't have to recompute it.  */
    time_t change;	/* When to change to this zone.  */
    int computed_for;	/* Year above is computed for.  */
  } tz_rule;

/* tz_rules[0] is standard, tz_rules[1] is daylight.  */
static tz_rule tz_rules[2];

/* Warning -- this function is a stub andd always does UTC
 * no matter what it is given */
void tzset (void)
{
    tz_rules[0].name = tz_rules[1].name = "UTC";
    tz_rules[0].type = tz_rules[1].type = J0;
    tz_rules[0].m = tz_rules[0].n = tz_rules[0].d = 0;
    tz_rules[1].m = tz_rules[1].n = tz_rules[1].d = 0;
    tz_rules[0].secs = tz_rules[1].secs = 0;
    tz_rules[0].offset = tz_rules[1].offset = 0L;
    tz_rules[0].change = tz_rules[1].change = (time_t) -1;
    tz_rules[0].computed_for = tz_rules[1].computed_for = 0;
}



static time_t localtime_offset;

/* Convert *TP to a time_t value.  */
time_t mktime(tp)
struct tm *tp;
{
#ifdef _LIBC
	/* POSIX.1 8.1.1 requires that whenever mktime() is called, the
	   time zone names contained in the external variable `tzname' shall
	   be set as if the tzset() function had been called.  */
	tzset();
#endif

	return __mktime_internal(tp, localtime_r, &localtime_offset);
}

/* Convert *TP to a time_t value, inverting
   the monotonic and mostly-unit-linear conversion function CONVERT.
   Use *OFFSET to keep track of a guess at the offset of the result,
   compared to what the result would be for UTC without leap seconds.
   If *OFFSET's guess is correct, only one CONVERT call is needed.  */
time_t __mktime_internal(tp, convert, offset)
struct tm *tp;
struct tm *(*convert) __P((const time_t *, struct tm *));
time_t *offset;
{
	time_t t, dt, t0;
	struct tm tm;

	/* The maximum number of probes (calls to CONVERT) should be enough
	   to handle any combinations of time zone rule changes, solar time,
	   and leap seconds.  Posix.1 prohibits leap seconds, but some hosts
	   have them anyway.  */
	int remaining_probes = 4;

	/* Time requested.  Copy it in case CONVERT modifies *TP; this can
	   occur if TP is localtime's returned value and CONVERT is localtime.  */
	int sec = tp->tm_sec;
	int min = tp->tm_min;
	int hour = tp->tm_hour;
	int mday = tp->tm_mday;
	int mon = tp->tm_mon;
	int year_requested = tp->tm_year;
	int isdst = tp->tm_isdst;

	/* Ensure that mon is in range, and set year accordingly.  */
	int mon_remainder = mon % 12;
	int negative_mon_remainder = mon_remainder < 0;
	int mon_years = mon / 12 - negative_mon_remainder;
	int year = year_requested + mon_years;

	/* The other values need not be in range:
	   the remaining code handles minor overflows correctly,
	   assuming int and time_t arithmetic wraps around.
	   Major overflows are caught at the end.  */

	/* Calculate day of year from year, month, and day of month.
	   The result need not be in range.  */
	int yday = ((__mon_yday[__isleap(year + TM_YEAR_BASE)]
				 [mon_remainder + 12 * negative_mon_remainder])
				+ mday - 1);

#if LEAP_SECONDS_POSSIBLE
	/* Handle out-of-range seconds specially,
	   since ydhms_tm_diff assumes every minute has 60 seconds.  */
	int sec_requested = sec;

	if (sec < 0)
		sec = 0;
	if (59 < sec)
		sec = 59;
#endif

	/* Invert CONVERT by probing.  First assume the same offset as last time.
	   Then repeatedly use the error to improve the guess.  */

	tm.tm_year = EPOCH_YEAR - TM_YEAR_BASE;
	tm.tm_yday = tm.tm_hour = tm.tm_min = tm.tm_sec = 0;
	t0 = ydhms_tm_diff(year, yday, hour, min, sec, &tm);

	for (t = t0 + *offset;
		 (dt =
		  ydhms_tm_diff(year, yday, hour, min, sec, (*convert) (&t, &tm)));
		 t += dt)
		if (--remaining_probes == 0)
			return -1;

	/* Check whether tm.tm_isdst has the requested value, if any.  */
	if (0 <= isdst && 0 <= tm.tm_isdst) {
		int dst_diff = (isdst != 0) - (tm.tm_isdst != 0);

		if (dst_diff) {
			/* Move two hours in the direction indicated by the disagreement,
			   probe some more, and switch to a new time if found.
			   The largest known fallback due to daylight savings is two hours:
			   once, in Newfoundland, 1988-10-30 02:00 -> 00:00.  */
			time_t ot = t - 2 * 60 * 60 * dst_diff;

			while (--remaining_probes != 0) {
				struct tm otm;

				if (!(dt = ydhms_tm_diff(year, yday, hour, min, sec,
										 (*convert) (&ot, &otm)))) {
					t = ot;
					tm = otm;
					break;
				}
				if ((ot += dt) == t)
					break;		/* Avoid a redundant probe.  */
			}
		}
	}

	*offset = t - t0;

#if LEAP_SECONDS_POSSIBLE
	if (sec_requested != tm.tm_sec) {
		/* Adjust time to reflect the tm_sec requested, not the normalized value.
		   Also, repair any damage from a false match due to a leap second.  */
		t += sec_requested - sec + (sec == 0 && tm.tm_sec == 60);
		(*convert) (&t, &tm);
	}
#endif

#if 0
	if (TIME_T_MAX / INT_MAX / 366 / 24 / 60 / 60 < 3) {
		/* time_t isn't large enough to rule out overflows in ydhms_tm_diff,
		   so check for major overflows.  A gross check suffices,
		   since if t has overflowed, it is off by a multiple of
		   TIME_T_MAX - TIME_T_MIN + 1.  So ignore any component of
		   the difference that is bounded by a small value.  */

		double dyear = (double) year_requested + mon_years - tm.tm_year;
		double dday = 366 * dyear + mday;
		double dsec = 60 * (60 * (24 * dday + hour) + min) + sec_requested;

		if (TIME_T_MAX / 3 - TIME_T_MIN / 3 < (dsec < 0 ? -dsec : dsec))
			return -1;
	}
#endif

	*tp = tm;
	return t;
}
