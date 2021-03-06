#ifndef __ASM_ARM_UNISTD_H
#define __ASM_ARM_UNISTD_H

#define __NR_SYSCALL_BASE	0x900000

/*
 * This file contains the system call numbers.
 */

#define __NR_setup		__NR_SYSCALL_BASE+  0	/* used only by init, to get system going */
#define __NR_exit		__NR_SYSCALL_BASE+  1
#define __NR_fork		__NR_SYSCALL_BASE+  2
#define __NR_read		__NR_SYSCALL_BASE+  3
#define __NR_write		__NR_SYSCALL_BASE+  4
#define __NR_open		__NR_SYSCALL_BASE+  5
#define __NR_close		__NR_SYSCALL_BASE+  6
#define __NR_waitpid		__NR_SYSCALL_BASE+  7
#define __NR_creat		__NR_SYSCALL_BASE+  8
#define __NR_link		__NR_SYSCALL_BASE+  9
#define __NR_unlink		__NR_SYSCALL_BASE+ 10
#define __NR_execve		__NR_SYSCALL_BASE+ 11
#define __NR_chdir		__NR_SYSCALL_BASE+ 12
#define __NR_time		__NR_SYSCALL_BASE+ 13
#define __NR_mknod		__NR_SYSCALL_BASE+ 14
#define __NR_chmod		__NR_SYSCALL_BASE+ 15
#define __NR_chown		__NR_SYSCALL_BASE+ 16
#define __NR_break		__NR_SYSCALL_BASE+ 17
#define __NR_oldstat		__NR_SYSCALL_BASE+ 18
#define __NR_lseek		__NR_SYSCALL_BASE+ 19
#define __NR_getpid		__NR_SYSCALL_BASE+ 20
#define __NR_mount		__NR_SYSCALL_BASE+ 21
#define __NR_umount		__NR_SYSCALL_BASE+ 22
#define __NR_setuid		__NR_SYSCALL_BASE+ 23
#define __NR_getuid		__NR_SYSCALL_BASE+ 24
#define __NR_stime		__NR_SYSCALL_BASE+ 25
#define __NR_ptrace		__NR_SYSCALL_BASE+ 26
#define __NR_alarm		__NR_SYSCALL_BASE+ 27
#define __NR_oldfstat		__NR_SYSCALL_BASE+ 28
#define __NR_pause		__NR_SYSCALL_BASE+ 29
#define __NR_utime		__NR_SYSCALL_BASE+ 30
#define __NR_stty		__NR_SYSCALL_BASE+ 31
#define __NR_gtty		__NR_SYSCALL_BASE+ 32
#define __NR_access		__NR_SYSCALL_BASE+ 33
#define __NR_nice		__NR_SYSCALL_BASE+ 34
#define __NR_ftime		__NR_SYSCALL_BASE+ 35
#define __NR_sync		__NR_SYSCALL_BASE+ 36
#define __NR_kill		__NR_SYSCALL_BASE+ 37
#define __NR_rename		__NR_SYSCALL_BASE+ 38
#define __NR_mkdir		__NR_SYSCALL_BASE+ 39
#define __NR_rmdir		__NR_SYSCALL_BASE+ 40
#define __NR_dup		__NR_SYSCALL_BASE+ 41
#define __NR_pipe		__NR_SYSCALL_BASE+ 42
#define __NR_times		__NR_SYSCALL_BASE+ 43
#define __NR_prof		__NR_SYSCALL_BASE+ 44
#define __NR_brk		__NR_SYSCALL_BASE+ 45
#define __NR_setgid		__NR_SYSCALL_BASE+ 46
#define __NR_getgid		__NR_SYSCALL_BASE+ 47
#define __NR_signal		__NR_SYSCALL_BASE+ 48
#define __NR_geteuid		__NR_SYSCALL_BASE+ 49
#define __NR_getegid		__NR_SYSCALL_BASE+ 50
#define __NR_acct		__NR_SYSCALL_BASE+ 51
#define __NR_phys		__NR_SYSCALL_BASE+ 52
#define __NR_lock		__NR_SYSCALL_BASE+ 53
#define __NR_ioctl		__NR_SYSCALL_BASE+ 54
#define __NR_fcntl		__NR_SYSCALL_BASE+ 55
#define __NR_mpx		__NR_SYSCALL_BASE+ 56
#define __NR_setpgid		__NR_SYSCALL_BASE+ 57
#define __NR_ulimit		__NR_SYSCALL_BASE+ 58
#define __NR_oldolduname	__NR_SYSCALL_BASE+ 59
#define __NR_umask		__NR_SYSCALL_BASE+ 60
#define __NR_chroot		__NR_SYSCALL_BASE+ 61
#define __NR_ustat		__NR_SYSCALL_BASE+ 62
#define __NR_dup2		__NR_SYSCALL_BASE+ 63
#define __NR_getppid		__NR_SYSCALL_BASE+ 64
#define __NR_getpgrp		__NR_SYSCALL_BASE+ 65
#define __NR_setsid		__NR_SYSCALL_BASE+ 66
#define __NR_sigaction		__NR_SYSCALL_BASE+ 67
#define __NR_sgetmask		__NR_SYSCALL_BASE+ 68
#define __NR_ssetmask		__NR_SYSCALL_BASE+ 69
#define __NR_setreuid		__NR_SYSCALL_BASE+ 70
#define __NR_setregid		__NR_SYSCALL_BASE+ 71
#define __NR_sigsuspend		__NR_SYSCALL_BASE+ 72
#define __NR_sigpending		__NR_SYSCALL_BASE+ 73
#define __NR_sethostname	__NR_SYSCALL_BASE+ 74
#define __NR_setrlimit		__NR_SYSCALL_BASE+ 75
#define __NR_getrlimit		__NR_SYSCALL_BASE+ 76
#define __NR_getrusage		__NR_SYSCALL_BASE+ 77
#define __NR_gettimeofday	__NR_SYSCALL_BASE+ 78
#define __NR_settimeofday	__NR_SYSCALL_BASE+ 79
#define __NR_getgroups		__NR_SYSCALL_BASE+ 80
#define __NR_setgroups		__NR_SYSCALL_BASE+ 81
#define __NR_oldselect		__NR_SYSCALL_BASE+ 82
#define __NR_symlink		__NR_SYSCALL_BASE+ 83
#define __NR_oldlstat		__NR_SYSCALL_BASE+ 84
#define __NR_readlink		__NR_SYSCALL_BASE+ 85
#define __NR_uselib		__NR_SYSCALL_BASE+ 86
#define __NR_swapon		__NR_SYSCALL_BASE+ 87
#define __NR_reboot		__NR_SYSCALL_BASE+ 88
#define __NR_readdir		__NR_SYSCALL_BASE+ 89
#define __NR_mmap		__NR_SYSCALL_BASE+ 90
#define __NR_munmap		__NR_SYSCALL_BASE+ 91
#define __NR_truncate		__NR_SYSCALL_BASE+ 92
#define __NR_ftruncate		__NR_SYSCALL_BASE+ 93
#define __NR_fchmod		__NR_SYSCALL_BASE+ 94
#define __NR_fchown		__NR_SYSCALL_BASE+ 95
#define __NR_getpriority	__NR_SYSCALL_BASE+ 96
#define __NR_setpriority	__NR_SYSCALL_BASE+ 97
#define __NR_profil		__NR_SYSCALL_BASE+ 98
#define __NR_statfs		__NR_SYSCALL_BASE+ 99
#define __NR_fstatfs		__NR_SYSCALL_BASE+100
#define __NR_ioperm		__NR_SYSCALL_BASE+101
#define __NR_socketcall		__NR_SYSCALL_BASE+102
#define __NR_syslog		__NR_SYSCALL_BASE+103
#define __NR_setitimer		__NR_SYSCALL_BASE+104
#define __NR_getitimer		__NR_SYSCALL_BASE+105
#define __NR_stat		__NR_SYSCALL_BASE+106
#define __NR_lstat		__NR_SYSCALL_BASE+107
#define __NR_fstat		__NR_SYSCALL_BASE+108
#define __NR_olduname		__NR_SYSCALL_BASE+109
#define __NR_iopl		__NR_SYSCALL_BASE+110
#define __NR_vhangup		__NR_SYSCALL_BASE+111
#define __NR_idle		__NR_SYSCALL_BASE+112
#define __NR_syscall		__NR_SYSCALL_BASE+113 /* syscall to call a syscall! */
#define __NR_wait4		__NR_SYSCALL_BASE+114
#define __NR_swapoff		__NR_SYSCALL_BASE+115
#define __NR_sysinfo		__NR_SYSCALL_BASE+116
#define __NR_ipc		__NR_SYSCALL_BASE+117
#define __NR_fsync		__NR_SYSCALL_BASE+118
#define __NR_sigreturn		__NR_SYSCALL_BASE+119
#define __NR_clone		__NR_SYSCALL_BASE+120
#define __NR_setdomainname	__NR_SYSCALL_BASE+121
#define __NR_uname		__NR_SYSCALL_BASE+122
#define __NR_modify_ldt		__NR_SYSCALL_BASE+123
#define __NR_adjtimex		__NR_SYSCALL_BASE+124
#define __NR_mprotect		__NR_SYSCALL_BASE+125
#define __NR_sigprocmask	__NR_SYSCALL_BASE+126
#define __NR_create_module	__NR_SYSCALL_BASE+127
#define __NR_init_module	__NR_SYSCALL_BASE+128
#define __NR_delete_module	__NR_SYSCALL_BASE+129
#define __NR_get_kernel_syms	__NR_SYSCALL_BASE+130
#define __NR_quotactl		__NR_SYSCALL_BASE+131
#define __NR_getpgid		__NR_SYSCALL_BASE+132
#define __NR_fchdir		__NR_SYSCALL_BASE+133
#define __NR_bdflush		__NR_SYSCALL_BASE+134
#define __NR_sysfs		__NR_SYSCALL_BASE+135
#define __NR_personality	__NR_SYSCALL_BASE+136
#define __NR_afs_syscall	__NR_SYSCALL_BASE+137 /* Syscall for Andrew File System */
#define __NR_setfsuid		__NR_SYSCALL_BASE+138
#define __NR_setfsgid		__NR_SYSCALL_BASE+139
#define __NR__llseek		__NR_SYSCALL_BASE+140
#define __NR_getdents		__NR_SYSCALL_BASE+141
#define __NR__newselect		__NR_SYSCALL_BASE+142
#define __NR_flock		__NR_SYSCALL_BASE+143
#define __NR_msync		__NR_SYSCALL_BASE+144
#define __NR_readv		__NR_SYSCALL_BASE+145
#define __NR_writev		__NR_SYSCALL_BASE+146
#define __NR_getsid		__NR_SYSCALL_BASE+147
#define __NR_fdatasync		__NR_SYSCALL_BASE+148
#define __NR__sysctl		__NR_SYSCALL_BASE+149
#define __NR_mlock		__NR_SYSCALL_BASE+150
#define __NR_munlock		__NR_SYSCALL_BASE+151
#define __NR_mlockall		__NR_SYSCALL_BASE+152
#define __NR_munlockall		__NR_SYSCALL_BASE+153
#define __NR_sched_setparam	__NR_SYSCALL_BASE+154
#define __NR_sched_getparam	__NR_SYSCALL_BASE+155
#define __NR_sched_setscheduler	__NR_SYSCALL_BASE+156
#define __NR_sched_getscheduler	__NR_SYSCALL_BASE+157
#define __NR_sched_yield	__NR_SYSCALL_BASE+158
#define __NR_sched_get_priority_max	__NR_SYSCALL_BASE+159
#define __NR_sched_get_priority_min	__NR_SYSCALL_BASE+160
#define __NR_sched_rr_get_interval	__NR_SYSCALL_BASE+161
#define __NR_nanosleep		__NR_SYSCALL_BASE+162
#define __NR_mremap		__NR_SYSCALL_BASE+163
#define __NR_poll		__NR_SYSCALL_BASE+168
#define __NR_getpmsg		__NR_SYSCALL_BASE+188
#define __NR_putpmsg		__NR_SYSCALL_BASE+189

#define __NR_select __NR__newselect
#define __sys2(x) #x
#define __sys1(x) __sys2(x)

#ifndef __syscall
#define __syscall(name) "swi " __sys1(__NR_##name) "\n\t"
#endif

#define _syscall0(type,name)								\
type name(void) {									\
  long __res;										\
  __asm__ __volatile__ (								\
  __syscall(name)									\
  "mov %0,r0\n\t"									\
  :"=r" (__res) : : "r0","r1","r2","r3","lr");						\
  if (__res >= 0)									\
    return (type) __res;								\
  errno = -__res;									\
  return -1;										\
}

#define _syscall1(type,name,type1,arg1)							\
type name(type1 arg1) {									\
  long __res;										\
  __asm__ __volatile__ (								\
  "mov r0,%1\n\t"									\
  __syscall(name)									\
  "mov %0,r0\n\t"									\
        : "=r" (__res)									\
        : "r" ((long)(arg1))								\
	: "r0","r1","r2","r3","lr");							\
  if (__res >= 0)									\
    return (type) __res;								\
  errno = -__res;									\
  return -1;										\
}

#define _syscall2(type,name,type1,arg1,type2,arg2)					\
type name(type1 arg1,type2 arg2) {							\
  long __res;										\
  __asm__ __volatile__ (								\
  "mov r0,%1\n\t"									\
  "mov r1,%2\n\t"									\
  __syscall(name)									\
  "mov %0,r0\n\t"									\
        : "=r" (__res)									\
        : "r" ((long)(arg1)),"r" ((long)(arg2))						\
	: "r0","r1","r2","r3","lr");							\
  if (__res >= 0)									\
    return (type) __res;								\
  errno = -__res;									\
  return -1;										\
}


#define _syscall3(type,name,type1,arg1,type2,arg2,type3,arg3)				\
type name(type1 arg1,type2 arg2,type3 arg3) {						\
  long __res;										\
  __asm__ __volatile__ (								\
  "mov r0,%1\n\t"									\
  "mov r1,%2\n\t"									\
  "mov r2,%3\n\t"									\
  __syscall(name)									\
  "mov %0,r0\n\t"									\
        : "=r" (__res)									\
        : "r" ((long)(arg1)),"r" ((long)(arg2)),"r" ((long)(arg3))			\
        : "r0","r1","r2","r3","lr");							\
  if (__res >= 0)									\
    return (type) __res;								\
  errno=-__res;										\
  return -1;										\
}


#define _syscall4(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4)		\
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4) {				\
  long __res;										\
  __asm__ __volatile__ (								\
  "mov r0,%1\n\t"									\
  "mov r1,%2\n\t"									\
  "mov r2,%3\n\t"									\
  "mov r3,%4\n\t"									\
  __syscall(name)									\
  "mov %0,r0\n\t"									\
  	: "=r" (__res)									\
  	: "r" ((long)(arg1)),"r" ((long)(arg2)),"r" ((long)(arg3)),"r" ((long)(arg4))	\
  	: "r0","r1","r2","r3","lr");							\
  if (__res >= 0)									\
    return (type) __res;								\
  errno=-__res;										\
  return -1;										\
}
  

#define _syscall5(type,name,type1,arg1,type2,arg2,type3,arg3,type4,arg4,type5,arg5)	\
type name(type1 arg1, type2 arg2, type3 arg3, type4 arg4, type5 arg5) {			\
  long __res;										\
  __asm__ __volatile__ (								\
  "mov r0,%1\n\t"									\
  "mov r1,%2\n\t"									\
  "mov r2,%3\n\t"									\
  "mov r3,%4\n\t"									\
  "mov r4,%5\n\t"									\
  __syscall(name)									\
  "mov %0,r0\n\t"									\
  	: "=r" (__res)									\
  	: "r" ((long)(arg1)),"r" ((long)(arg2)),"r" ((long)(arg3)),"r" ((long)(arg4)),	\
	  "r" ((long)(arg5))								\
	: "r0","r1","r2","r3","r4","lr");						\
  if (__res >= 0)									\
    return (type) __res;								\
  errno=-__res;										\
  return -1;										\
}

#ifdef __KERNEL_SYSCALLS__
#define __NR__exit __NR_exit
static inline _syscall0(int,idle);
static inline _syscall0(int,fork);
static inline _syscall2(int,clone,unsigned long,flags,char *,esp);
static inline _syscall0(int,pause);
static inline _syscall0(int,setup);
static inline _syscall0(int,sync);
static inline _syscall0(pid_t,setsid);
static inline _syscall3(int,write,int,fd,const char *,buf,off_t,count);
static inline _syscall3(int,read,int,fd,char *,buf,off_t,count);
static inline _syscall1(int,dup,int,fd);
static inline _syscall3(int,execve,const char *,file,char **,argv,char **,envp);
static inline _syscall3(int,open,const char *,file,int,flag,int,mode);
static inline _syscall1(int,close,int,fd);
static inline _syscall1(int,_exit,int,exitcode);
static inline _syscall3(pid_t,waitpid,pid_t,pid,int *,wait_stat,int,options);
static inline _syscall3(int, ioctl, int, fd, int, options, int *, optval);
static inline _syscall5(int,select, int, __width, fd_set *, __readfds,
						 fd_set *, __writefds, fd_set *, __exceptfds,
						 struct timeval *, __timeout);

static inline pid_t wait(int * wait_stat)
{
	return waitpid(-1,wait_stat,0);
}

static inline _syscall2(int, gettimeofday, struct timeval*, _tv, struct timezone*, _tz);



/*
 * This is the mechanism for creating a new kernel thread.
 *
 * NOTE! Only a kernel-only process(ie the swapper or direct descendants
 * who haven't done an "execve()") should use this: it will work within
 * a system call from a "real" process, but the process memory space will
 * not be free'd until both the parent and the child have exited.
 */
static inline pid_t kernel_thread(int (*fn)(void *), void * arg, unsigned long flags)
{
	long retval;

	__asm__ __volatile__("
	mov	r0,%1
	mov	r1,%2
	"__syscall(clone)"
	teq	r0, #0
	bne	1f
	mov	r0,%4
	mov	lr, pc
	mov	pc, %3
	"__syscall(exit)"
1:	mov %0,r0"
        : "=r" (retval)
        : "Ir" (flags | CLONE_VM), "Ir" (NULL), "r" (fn), "Ir" (arg)
	: "r0","r1","r2","r3","lr");
	
	return retval;
}

#endif

#endif /* __ASM_ARM_UNISTD_H */



