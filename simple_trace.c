// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) "[simple]: " fmt

#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kfifo.h>
#include <linux/kallsyms.h>
#include "simple_trace.h"

#define kfifo_peek_out_start(fifo, tmp) \
((void)({ \
	typeof((fifo) + 1) __tmp = (fifo); \
	struct __kfifo *__kfifo = &__tmp->kfifo; \
	(tmp) = __kfifo->out; \
}))

#define kfifo_peek_out_end(fifo, tmp) \
((void)({ \
	typeof((fifo) + 1) __tmp = (fifo); \
	struct __kfifo *__kfifo = &__tmp->kfifo; \
	__kfifo->out = (tmp); \
}))

static void __kfifo_recover_r_len(struct __kfifo *fifo, size_t recsize, size_t len)
{
	unsigned int n;

	n = __kfifo_len_r(fifo, recsize);
	fifo->out = fifo->in - len * (n + recsize);
}

#define	kfifo_recover_len(fifo, len) \
((void)({ \
	typeof((fifo) + 1) __tmp = (fifo); \
	const size_t __recsize = sizeof(*__tmp->rectype); \
	struct __kfifo *__kfifo = &__tmp->kfifo; \
	if (__recsize) \
		__kfifo_recover_r_len(__kfifo, __recsize, (len)); \
	else \
		__kfifo->out = __kfifo->in - (len); \
}))

#define ST_LOG_SIZE (1 << CONFIG_SIMPLE_TRACE_LOGSIZE_SHIFT)

struct trace_item {
	struct kprobe kp[0];
	struct kretprobe rp[0];
	struct kretprobe kretprobe;

	char name[KSYM_NAME_LEN];
	unsigned char type;
	struct list_head node;
	ktime_t entry_stamp;
};

static spinlock_t log_fifo_lock;
static DECLARE_WAIT_QUEUE_HEAD(st_log_wait);
static struct kfifo trace_log;
static LIST_HEAD(sim_trace_list);

static int log_open_flag;
static char log_tmp[64];

static inline void wake_up_st_log(void)
{
	if (log_open_flag)
		wake_up_interruptible(&st_log_wait);
}

static void st_log_put(char *buf, int len)
{
	int tmp;

	spin_lock(&log_fifo_lock);
	if (kfifo_is_full(&trace_log)) {
		tmp = len;
		while (tmp--)
			kfifo_skip(&trace_log);
	}
	kfifo_in(&trace_log, buf, len);
	spin_unlock(&log_fifo_lock);
	wake_up_st_log();
}

static int ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);
	struct trace_item *ti = container_of(rp, struct trace_item, kretprobe);
	struct timespec64 ts;
	int len;

	ti->entry_stamp = ktime_get();
	ts = ktime_to_timespec64(ti->entry_stamp);
	len = snprintf(log_tmp, sizeof(log_tmp),
		"[%6lld.%06ld] ->> %s\n",
		ts.tv_sec, ts.tv_nsec / 1000,
		ti->name);

	st_log_put(log_tmp, len);
	PRT(DEBUG, "%s", log_tmp);

	return 0;
}
NOKPROBE_SYMBOL(ent_handler);

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);
	struct trace_item *ti = container_of(rp, struct trace_item, kretprobe);
	unsigned long retval = regs_return_value(regs);
	struct timespec64 ts;
	ktime_t now;
	s64 delta;
	int len;

	now = ktime_get();
	ts = ktime_to_timespec64(now);
	delta = ktime_to_ns(ktime_sub(now, ti->entry_stamp));
	len = snprintf(log_tmp, sizeof(log_tmp),
		"[%6lld.%06ld] <<- %s (%d)%lu (%lld)\n",
		ts.tv_sec, ts.tv_nsec / 1000,
		ti->name, (int)retval, retval,
		(long long)delta);

	st_log_put(log_tmp, len);
	PRT(DEBUG, "%s", log_tmp);

	return 0;
}
NOKPROBE_SYMBOL(ret_handler);

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct trace_item *ti = container_of((struct kretprobe *)p, struct trace_item, kretprobe);
	struct timespec64 ts;
	int len;

	ts = ktime_to_timespec64(ktime_get());
	len = snprintf(log_tmp, sizeof(log_tmp),
			"[%6lld.%06ld] ->> %s\n",
			ts.tv_sec, ts.tv_nsec / 1000,
			ti->name);

	st_log_put(log_tmp, len);
	PRT(DEBUG, "%s", log_tmp);

	return 0;
}

static struct trace_item *find_trace_item(struct sim_trace *p)
{
	struct trace_item *ti;

	list_for_each_entry(ti, &sim_trace_list, node) {
		if (ti->kp->addr == p->addr || !strcmp(ti->kp->symbol_name, p->sym))
			return ti;
	}

	return NULL;
}

int simple_trace_add(struct sim_trace *p, int count)
{
	int ret;
	struct trace_item *ti;

	while (count--) {
		if (p->sym == NULL) {
			PRT(ERR, "symbol is NULL!\n");
			return -EINVAL;
		}

		if (find_trace_item(p)) {
			PRT(ERR, "symbol %s already registered!\n", p->sym);
			return -EEXIST;
		}

		ti = kzalloc(sizeof(*ti), GFP_KERNEL);
		if (!ti)
			return -ENOMEM;

		snprintf(ti->name, sizeof(ti->name), "%s", p->sym);
		ti->type = p->type;
		ti->kp->addr = (kprobe_opcode_t *)p->addr;
		if (!ti->kp->addr)
			ti->kp->symbol_name = ti->name;
		p++;
#if IS_ENABLED(CONFIG_KRETPROBES)
		if (ti->type == TRACE_ENTRET) {
			ti->rp->entry_handler = ent_handler;
			ti->rp->handler = ret_handler;
			ti->rp->data_size = 0;
			/* Probe up to 20 instances concurrently. */
			ti->rp->maxactive = 20;
			ret = register_kretprobe(ti->rp);
		} else
#endif
		{
			ti->kp->pre_handler = handler_pre;
			ti->kp->post_handler = NULL;
			ret = register_kprobe(ti->kp);
		}

		if (ret < 0) {
			PRT(ERR, "failed, returned %d\n", ret);
			kfree(ti);
			return ret;
		}
		INIT_LIST_HEAD(&ti->node);
		list_add_tail(&ti->node, &sim_trace_list);
	}

	return 0;
}
EXPORT_SYMBOL(simple_trace_add);

int simple_trace_remove(struct sim_trace *p, int count)
{
	struct trace_item *ti;

	while (count--) {
		ti = find_trace_item(p++);
		if (!ti) {
			PRT(ERR, "symbol %px not registered!\n", p->addr);
			continue;
		}

#if IS_ENABLED(CONFIG_KRETPROBES)
		if (ti->type == TRACE_ENTRET) {
			unregister_kretprobe(ti->rp);
		} else
#endif
		{
			unregister_kprobe(ti->kp);
		}

		list_del(&ti->node);
		PRT(INFO, "trace remove [%px] %s!\n",
			ti->kp->addr, ti->name);
	}

	return 0;
}
EXPORT_SYMBOL(simple_trace_remove);

static struct proc_dir_entry *dir_entry = NULL;

static int st_info_show(struct seq_file *m, void *v)
{
	struct trace_item *st;
	struct kprobe *p;

	seq_printf(m, "[type]  [sym]\n");
	list_for_each_entry(st, &sim_trace_list, node) {
// #if IS_ENABLED(CONFIG_KRETPROBES)
//                 if (st->type == TRACE_ENTRET)
//                         p = get_kprobe(st->kp->addr);
// #endif
		p = st->kp;
		seq_printf(m, "%6s  [%px]%s\n", st->type == TRACE_ENTRET ? "ENTRET" : "ENTRY",
				p->addr, p->symbol_name);
	}

	return 0;
}

#define ST_LOG_BY_SINGLE 0

#if ST_LOG_BY_SINGLE
static int st_log_show(struct seq_file *m, void *v)
{
	int len;
	int ret;

	if (kfifo_is_empty(&trace_log)) {
		return 0;
	}

	len = kfifo_len(&trace_log);

	if (m->count + len >= m->size) {
		m->count = m->size;
		// seq_set_overflow(m);
		goto out;
	}
	ret = kfifo_out(&trace_log, m->buf + m->count, len);
	m->count += len;

out:
	return 0;
}
#else
static ssize_t st_log_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	unsigned int copied;
	int ret;

	if (kfifo_is_empty(&trace_log)) {
		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		ret = wait_event_interruptible(st_log_wait, !kfifo_is_empty(&trace_log));
		if (ret)
			return ret;
	}

	ret = kfifo_to_user(&trace_log, buf, count, &copied);
	if (ret)
		goto out;

	ret = copied;
out:
	return ret;
}
#endif

static int st_log_open(struct inode *inode, struct file *file)
{
	if (log_open_flag)
		return -EBUSY;

	log_open_flag = 1;

	PRT(DEBUG, "fifo->out = %d fifo->in = %d\n",
			trace_log.kfifo.out, trace_log.kfifo.in);

	spin_lock(&log_fifo_lock);
	kfifo_recover_len(&trace_log, (trace_log.kfifo.in < ST_LOG_SIZE ? trace_log.kfifo.in : ST_LOG_SIZE));
	spin_unlock(&log_fifo_lock);

	PRT(DEBUG, "fifo->out = %d fifo->in = %d\n",
		trace_log.kfifo.out, trace_log.kfifo.in);

#if ST_LOG_BY_SINGLE
	return single_open(file, st_log_show, inode->i_private);
#else
	return 0;
#endif
}

static int st_log_release(struct inode *inode, struct file *file)
{
	log_open_flag = 0;
#if ST_LOG_BY_SINGLE
	return single_release(inode, file);
#else
		return 0;
#endif
}

static const struct proc_ops st_log_fops = {
	.proc_open	= st_log_open,
	.proc_release	= st_log_release,
#if ST_LOG_BY_SINGLE
	.proc_read = seq_read,
	.proc_lseek	= seq_lseek,
#else
	.proc_read = st_log_read,
	.proc_lseek	= noop_llseek,
#endif
};

static ssize_t
st_ctrl_write(struct file *filp, const char *ubuf, size_t cnt, loff_t *data)
{
	char buf[KSYM_NAME_LEN];

	if (cnt >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	if (buf[cnt - 1] == '\n')
		buf[cnt - 1] = '\0';
	else
		buf[cnt] = '\0';

	if (buf[0] == '!') {
		simple_trace_remove_one(&buf[1], NULL);
	} else if (buf[0] == '@') {
		simple_trace_add_one(&buf[1], NULL, TRACE_ENTRET);
	} else {
		simple_trace_add_one(&buf[0], NULL, TRACE_ENTRY);
	}

	return cnt;
}

static int st_ctrl_show(struct seq_file *m, void *v)
{
	seq_puts(m, "---test---\n");

	return 0;
}

static int st_ctrl_open(struct inode *inode, struct file *file)
{
	return single_open(file, st_ctrl_show, inode->i_private);
}

static const struct proc_ops st_ctrl_fops = {
	.proc_open = st_ctrl_open,
	.proc_write = st_ctrl_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init simple_trace_init(void)
{
	int ret;

	spin_lock_init(&log_fifo_lock);
	ret = kfifo_alloc(&trace_log, ST_LOG_SIZE, GFP_KERNEL);
	kfifo_in(&trace_log, "init done!\n", 11);

	dir_entry = proc_mkdir("simple_trace", NULL);
	if (!dir_entry) {
		PRT(ERR, "Failed to create /proc/simple_trace entry\n");
		return -ENOMEM;
	}

	proc_create_single("info", 0440, dir_entry, st_info_show);
	proc_create("log", 0440, dir_entry, &st_log_fops);
	proc_create("ctrl", 0660, dir_entry, &st_ctrl_fops);

	PRT(INFO, "init log size is %d-byte!\n", ST_LOG_SIZE);

	return 0;
}

static void __exit simple_trace_exit(void)
{
	struct trace_item *ti, *tmp;

	proc_remove(dir_entry);

	list_for_each_entry_safe(ti, tmp, &sim_trace_list, node) {
		if (ti->type == TRACE_ENTRET)
			unregister_kretprobe(ti->rp);
		else
			unregister_kprobe(ti->kp);

		pr_info("kretprobe at %p unregistered\n", ti->kp->addr);
		list_del(&ti->node);
		kfree(ti);
	}
}

module_init(simple_trace_init)
module_exit(simple_trace_exit)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Casey");
