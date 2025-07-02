#ifndef __SIMPLE_TRACE_H__
#define __SIMPLE_TRACE_H__

#define PRT(levl, fmt, ...) \
	printk(KERN_##levl pr_fmt("%s:%d " fmt), __func__, __LINE__, ##__VA_ARGS__)

enum {
	TRACE_ENTRY = 0,
	TRACE_ENTRET,
#if IS_ENABLED(CONFIG_SIMPLE_TRACE_USE_TIME)
	TRACE_USE_TIME,
#endif

	TRACE_FLAG_MAX,
};

struct sim_trace {
	char *sym;
	void *addr;
	unsigned long type;
};

int simple_trace_add(struct sim_trace *p, int count);
int simple_trace_remove(struct sim_trace *p, int count);

static inline int simple_trace_add_one(char *sym, void *addr, unsigned char type)
{
	struct sim_trace s;
	int ret = 0;

	s.sym = sym;
	s.addr = addr;
	s.type = type;

	ret = simple_trace_add(&s, 1);
	PRT(INFO, "trace add [%s]->[%px] %s!\n",
		sym, addr,
		ret == 0 ? "ok" : "fail");

	return ret;
}

static inline void simple_trace_remove_one(char *sym, void *addr)
{
	struct sim_trace s;

	if ((sym && addr) || (!sym && !addr)) {
		PRT(ERR, "invalid remove sym=[%s] addr=[%px]\n",
			sym, addr);
		return;
	}

	s.sym = sym;
	s.addr = addr;
	s.type = 0;

	simple_trace_remove(&s, 1);
}

#endif /* __SIMPLE_TRACE_H__ */
