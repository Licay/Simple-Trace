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

#define PRT(levl, fmt, ...) \
	printk(KERN_##levl pr_fmt("%s:%d " fmt), __func__, __LINE__, ##__VA_ARGS__)

struct trace_item {
	struct kprobe kp[0];
	struct kretprobe rp[0];
	struct kretprobe kretprobe;

	char name[KSYM_NAME_LEN];
	unsigned char type;
	struct list_head node;
	ktime_t entry_stamp;
};

#define ST_LOG_SIZE (1 << CONFIG_SIMPLE_TRACE_LOGSIZE_SHIFT)
#define ENTRY 0
#define ENTRET 1

static char log_tmp[64];
spinlock_t log_fifo_lock;
static DECLARE_WAIT_QUEUE_HEAD(st_log_wait);
static int log_open_flag = 0;
struct kfifo trace_log;

static int sim_probe_kp_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	/* NO CODE THERE! */
	return 0;
}

unsigned long simple_lookup_name(const char *name)
{
	unsigned long symbol_addr = 0;
	int ret = 0;
	struct kprobe lookup_kp = {
		.symbol_name = name,
		.pre_handler = sim_probe_kp_pre_handler,
	};

	ret = register_kprobe(&lookup_kp);
	if (ret < 0) {
		return 0;
	}

	symbol_addr = (unsigned long)lookup_kp.addr;
	unregister_kprobe(&lookup_kp);
	return symbol_addr;
}
EXPORT_SYMBOL(simple_lookup_name);

static int ent_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);
	struct trace_item *ti = container_of(rp, struct trace_item, kretprobe);
	int len;
	struct timespec64 ts;

	// if (!current->mm)
	// 	return 1;	/* Skip kernel threads */

	ti->entry_stamp = ktime_get();
	ts = ktime_to_timespec64(ti->entry_stamp);

	spin_lock(&log_fifo_lock);
	len = snprintf(log_tmp, sizeof(log_tmp),
		"[%6lld.%06ld] ->> %s\n",
		ts.tv_sec, ts.tv_nsec / 1000,
		ti->name);
	kfifo_in(&trace_log, log_tmp, len);
	spin_unlock(&log_fifo_lock);

	PRT(ERR, "%s", log_tmp);

	return 0;
}
NOKPROBE_SYMBOL(ent_handler);

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct kretprobe *rp = get_kretprobe(ri);
	struct trace_item *ti = container_of(rp, struct trace_item, kretprobe);
	unsigned long retval = regs_return_value(regs);
	int len;
	struct timespec64 ts;
	s64 delta;
	ktime_t now;

	now = ktime_get();
	ts = ktime_to_timespec64(now);
	delta = ktime_to_ns(ktime_sub(now, ti->entry_stamp));

	spin_lock(&log_fifo_lock);
	len = snprintf(log_tmp, sizeof(log_tmp),
		"[%6lld.%06ld] ->> %s (%d)%lu (%lld)\n",
		ts.tv_sec, ts.tv_nsec / 1000,
		ti->name, (int)retval, retval,
		(long long)delta);
	kfifo_in(&trace_log, log_tmp, len);
	spin_unlock(&log_fifo_lock);

	PRT(ERR, "%s", log_tmp);

	return 0;
}
NOKPROBE_SYMBOL(ret_handler);

struct sim_trace {
	char *sym;
	void *addr;
	unsigned char type;
};

LIST_HEAD(sim_trace_list);

int simple_trace_add(struct sim_trace *p, int count);
int simple_trace_remove(struct sim_trace *p, int count);

static inline int simple_trace_add_one(char *sym, void *addr, unsigned char type)
{
	struct sim_trace s;
	int ret = 0;

	PRT(ERR, "enter\n");

	s.sym = sym;
	s.addr = addr;
	s.type = type;

	PRT(ERR, "enter\n");
	ret = simple_trace_add(&s, 1);
	PRT(INFO, "trace add [%s]->[%px] %s!\n",
		sym, addr,
		ret == 0 ? "ok" : "fail");

	return ret;
}

static inline void simple_trace_remove_by_sym(char *sym)
{
	struct sim_trace s;

	s.sym = sym;
	s.addr = 0;
	s.type = 0;

	simple_trace_remove(&s, 1);

}

static inline void simple_trace_remove_by_addr(void *addr)
{
	struct sim_trace s;

	s.sym = NULL;
	s.addr = addr;
	s.type = 0;

	simple_trace_remove(&s, 1);
}

static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	int len;
	struct trace_item *ti = container_of((struct kretprobe *)p, struct trace_item, kretprobe);
	struct timespec64 ts;

	ts = ktime_to_timespec64(ktime_get());

	spin_lock(&log_fifo_lock);
	len = snprintf(log_tmp, sizeof(log_tmp),
			"[%6lld.%06ld] ->> %s\n",
			ts.tv_sec, ts.tv_nsec / 1000,
			ti->name);
	kfifo_in(&trace_log, log_tmp, len);
	spin_unlock(&log_fifo_lock);

	PRT(ERR, "%s", log_tmp);

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

	PRT(ERR, "enter\n");
	while (count--) {
		if (p->sym == NULL) {
			PRT(ERR, "symbol is NULL!\n");
			return -EINVAL;
		}

		if (find_trace_item(p)) {
			PRT(ERR, "symbol %s already registered!\n", p->sym);
			return -EEXIST;
		}
		// if (p->addr == 0)
		//         p->addr = kallsyms_lookup_name(p->sym);

		PRT(ERR, "enter\n");
		ti = kzalloc(sizeof(*ti), GFP_KERNEL);
		if (!ti)
			return -ENOMEM;

		PRT(ERR, "enter\n");
		snprintf(ti->name, sizeof(ti->name), "%s", p->sym);
		ti->type = p->type;
		ti->kp->addr = (kprobe_opcode_t *)p->addr;
		if (!ti->kp->addr)
			ti->kp->symbol_name = ti->name;
		PRT(ERR, "enter\n");
		p++;
#if 1
		if (ti->type == ENTRET) {
			PRT(ERR, "enter\n");
			ti->rp->entry_handler = ent_handler;
			ti->rp->handler = ret_handler;
			ti->rp->data_size = 0;
			/* Probe up to 20 instances concurrently. */
			ti->rp->maxactive = 20;
			ret = register_kretprobe(ti->rp);
		} else
#endif
		{
			PRT(ERR, "enter\n");
			ti->kp->pre_handler = handler_pre;
			ti->kp->post_handler = NULL;
			ret = register_kprobe(ti->kp);
		}

		PRT(ERR, "enter\n");
		if (ret < 0) {
			PRT(ERR, "failed, returned %d\n", ret);
			kfree(ti);
			return ret;
		}
		PRT(ERR, "enter\n");
		INIT_LIST_HEAD(&ti->node);
		list_add_tail(&ti->node, &sim_trace_list);
	}
	PRT(ERR, "enter\n");

	return 0;
}

int simple_trace_remove(struct sim_trace *p, int count)
{
	struct trace_item *ti;

	PRT(ERR, "enter\n");
	while (count--) {
		PRT(ERR, "enter\n");
		ti = find_trace_item(p++);
		if (!ti) {
			PRT(ERR, "symbol %px not registered!\n", p->addr);
			continue;
		}

#if 1
		if (ti->type == ENTRET) {
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

static struct proc_dir_entry *dir_entry = NULL;

static int st_info_show(struct seq_file *m, void *v)
{
	struct trace_item *st;
	struct kprobe *p;

	seq_printf(m, "[type]  [sym]\n");
	list_for_each_entry(st, &sim_trace_list, node) {
// #if 1
//                 if (st->type == ENTRET)
//                         p = get_kprobe(st->kp->addr);
// #endif
			p = st->kp;

		seq_printf(m, "%6s  [%px]%s\n", st->type == ENTRET ? "ENTRET" : "ENTRY",
				p->addr, p->symbol_name);
	}

	return 0;
}

// static int st_log_show(struct seq_file *m, void *v)
// {
// 	// struct trace_item *st;
// 	// struct kprobe *p;
// 	// __kfifo_out_peek(&trace_log, kfifo_len(&trace_log))
// 	int ret;
// 	int len = kfifo_len(&trace_log);

// 	if (m->count + len >= m->size) {
// 		m->count = m->size;
// 		// seq_set_overflow(m);
// 		return 0;
// 	}
// 	ret = kfifo_out_peek(&trace_log, m->buf + m->count, len);
// 	// memcpy(m->buf + m->count, s, len);
// 	m->count += len;

// 	return 0;
// }

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

static int st_log_show(struct seq_file *m, void *v)
{
	int len;
	int ret;

	if (kfifo_is_empty(&trace_log)) {
		// if (file->f_flags & O_NONBLOCK)
		// 	return -EAGAIN;

		ret = wait_event_interruptible(st_log_wait, !kfifo_is_empty(&trace_log));
		if (ret)
			return ret;
	}

	spin_lock(&log_fifo_lock);
	len = kfifo_len(&trace_log);

	if (m->count + len >= m->size) {
		m->count = m->size;
		// seq_set_overflow(m);
		goto out;
	}
	ret = kfifo_out_peek(&trace_log, m->buf + m->count, len);
	// memcpy(m->buf + m->count, s, len);
	m->count += len;

out:
	spin_unlock(&log_fifo_lock);

	return ret;
}

static int st_log_open(struct inode *inode, struct file *file)
{
	if (log_open_flag)
		return -EBUSY;

	log_open_flag = 1;

	pr_err("%s %d: fifo->out = %d fifo->in = %d\n", __func__, __LINE__,
			trace_log.kfifo.out, trace_log.kfifo.in);
	// spin_lock(&log_fifo_lock);
	kfifo_recover_len(&trace_log, (trace_log.kfifo.in < ST_LOG_SIZE ? trace_log.kfifo.in : ST_LOG_SIZE));
	// spin_unlock(&log_fifo_lock);
	pr_err("%s %d: fifo->out = %d fifo->in = %d\n", __func__, __LINE__,
			trace_log.kfifo.out, trace_log.kfifo.in);

	return single_open(file, st_log_show, inode->i_private);
}

static int st_log_release(struct inode *inode, struct file *file)
{
	log_open_flag = 0;
	return single_release(inode, file);
}

static const struct proc_ops st_log_fops = {
	.proc_open	= st_log_open,
	.proc_read_iter = seq_read_iter,
	.proc_lseek	= seq_lseek,
	.proc_release	= st_log_release,
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
		simple_trace_remove_by_sym(&buf[1]);
	} else if (buf[0] == '@') {
		simple_trace_add_one(&buf[1], NULL, ENTRET);
	} else {
		simple_trace_add_one(&buf[0], NULL, ENTRY);
	}

	return cnt;
}

static int st_ctrl_show(struct seq_file *m, void *v)
{

	seq_puts(m, "---test---\n");
	// seq_puts(m, "----------------------------------------\n");
	// seq_printf(m, "%-10d BOOT PROF (unit:msec)\n", enabled);

	return 0;
}

/*** Seq operation of mtprof ****/
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

	dump_stack();
	ret = kfifo_alloc(&trace_log, ST_LOG_SIZE, GFP_KERNEL);
	kfifo_in(&trace_log, "init done!\n", 11);

	dir_entry = proc_mkdir("simple_trace", NULL);
	if (!dir_entry) {
		PRT(ERR, "Failed to create /proc/simple_trace entry\n");
		return -ENOMEM;
	}

	proc_create_single("info", 0440, dir_entry, st_info_show);
	// proc_create_single("log", 0440, dir_entry, st_log_show);

	proc_create("log", 0440, dir_entry, &st_log_fops);
	proc_create("ctrl", 0660, dir_entry, &st_ctrl_fops);

	// simple_lookup_name("st_info_show");
	// simple_trace_add_one("st_info_show", NULL, ENTRY);
	PRT(INFO, "init log size is %d-byte!\n", ST_LOG_SIZE);

	return 0;
}

static void __exit simple_trace_exit(void)
{
	struct trace_item *ti, *tmp;

	dump_stack();
	proc_remove(dir_entry);

	list_for_each_entry_safe(ti, tmp, &sim_trace_list, node) {
		if (ti->type == ENTRET)
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
