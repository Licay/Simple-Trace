#ifndef __SIMPLE_LOOKUP_NAME_H__
#define __SIMPLE_LOOKUP_NAME_H__

#if IS_ENABLED(CONFIG_KPROBES)

#include <linux/version.h>
#include <linux/kprobes.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))
#include <linux/kallsyms.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
static unsigned long (*kallsyms_lookup_name_sym)(const char *name) = NULL;

static int _kallsyms_lookup_kprobe(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

/**
 * get symbol of kallsyms_lookup_name() function
 *
 * Return: Address of kallsyms_lookup_name function
 */
static inline void *get_kallsyms_func(void)
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

/**
 * simple_kallsyms_lookup_name - Lookup kernel symbol address by name
 * @name: The name of the symbol to lookup
 *
 * Return: Address of the symbol if found, NULL otherwise
 */
__maybe_unused
static inline unsigned long simple_kallsyms_lookup_name(const char *name)
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
__maybe_unused
static inline unsigned long simple_kallsyms_lookup_name(const char *name)
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
__maybe_unused
static inline unsigned long simple_kallsyms_lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

/**
 * SIML_SYM - Declare a symbol pointer for SIML_GET_SYM
 * @sym: The symbol name of the variable or function
 */
#define SIML_SYM(sym) typeof(&sym) _siml_##sym

/**
 * SIML_DECLARE - If symbol is not declared, declare it
 * @dec: The declaration of the symbol
 */
#define SIML_DECLARE(dec) dec

/**
 * SIML_GET_SYM - Get the address of a symbol
 * @sym: The symbol name of the variable or function
 *
 * Return: 0 if the symbol was found, -ENOSYS if not found
 */
#define SIML_GET_SYM(sym)                                                                   \
	({                                                                                 \
		_siml_##sym = (typeof(_siml_##sym))simple_kallsyms_lookup_name(#sym);              \
		(_siml_##sym ?                                                               \
			 ({                                                                \
				 pr_info("SIML symbol %s successfully get\n",               \
					 #sym);                                            \
				 0;                                                        \
			 }) :                                                              \
			 ({                                                                \
				 pr_err("SIML symbol %s is not available in this kernel\n", \
					#sym);                                             \
				 -ENOSYS;                                                  \
			 }));                                                              \
	})

/**
 * SIML_SAFETY - Check if a symbol is available
 * @sym: The symbol name of the variable or function
 *
 * eg: SIML_SAFETY(func_name) { ... }
 */
#define SIML_SAFETY(sym)                                                        \
	if (unlikely(!_siml_##sym)) {                                            \
		pr_err("SIML call %s is not available in this kernel\n", #sym); \
	} else

/**
 * SIML_CALL - Call a function symbol
 * @func: The function name
 * @...: The arguments of the function
 *
 * Return: The return value of the function
 */
#define SIML_CALL(func, ...) (_siml_##func(__VA_ARGS__))

/**
 * SIML_VAR - Access a variable symbol
 * @sym: The symbol name of the variable
 *
 * eg: SIML_VAR(var_name) = value;
 */
#define SIML_VAR(sym) (*_siml_##sym)

/**
 * SIML_ONESHOT_VAR_SET - Set the value of a variable once
 * @sym: The symbol name of the variable
 * @val: The value to set
 *
 * This macro attempts to retrieve the address of the variable @sym using
 * simple_kallsyms_lookup_name. If successful, it sets the variable to @val.
 *
 * Return: 0 if the variable was set successfully, -ENOSYS if not found
 */
#define SIML_ONESHOT_VAR_SET(sym, val)                     \
	({                                                \
		SIML_SYM(sym);                             \
		(SIML_GET_SYM(sym) == 0 ? ({               \
			SIML_VAR(sym) = val;               \
			0;                                \
		}) :                                      \
					 ({ -ENOSYS; })); \
	})

/**
 * SIML_ONESHOT_VAR_GET - Get the value of a variable once
 * @fval: The fallback value to return if the symbol is not found
 * @sym: The symbol name of the variable
 *
 * This macro attempts to retrieve the address of the variable @sym using
 * simple_kallsyms_lookup_name. If successful, it Return the value of the variable.
 * If not found, it Return the provided fallback value @fval.
 *
 * Return: The value of the variable if found, otherwise @fval
 */
#define SIML_ONESHOT_VAR_GET(fval, sym)                                       \
	({                                                                   \
		SIML_SYM(sym);                                                \
		(SIML_GET_SYM(sym) == 0 ? ({ SIML_VAR(sym); }) : ({ fval; })); \
	})

/**
 * SIML_ONESHOT_FUNC_CALL_NORET - Call a function once without return value
 * @func: The function name
 * @...: The arguments of the function
 *
 * This macro attempts to retrieve the address of the function @func using
 * simple_kallsyms_lookup_name. If successful, it calls the function with the
 * provided arguments.
 *
 * Return: 0 if the function was called successfully, -ENOSYS if not found
 */
#define SIML_ONESHOT_FUNC_CALL_NORET(func, ...)             \
	({                                                 \
		SIML_SYM(func);                             \
		(SIML_GET_SYM(func) == 0 ? ({               \
			SIML_CALL(func, __VA_ARGS__);       \
			0;                                 \
		}) :                                       \
					  ({ -ENOSYS; })); \
	})

/**
 * SIML_ONESHOT_FUNC_CALL - Call a function once with return value
 * @fval: The fallback value to return if the symbol is not found
 * @func: The function name
 * @...: The arguments of the function
 *
 * This macro attempts to retrieve the address of the function @func using
 * simple_kallsyms_lookup_name. If successful, it calls the function with the
 * provided arguments and Return its result. If not found, it Return the
 * provided fallback value @fval.
 *
 * Return: The return value of the function if found, otherwise @fval
 */
#define SIML_ONESHOT_FUNC_CALL(fval, func, ...)                                 \
	({                                                                     \
		SIML_SYM(func);                                                 \
		(SIML_GET_SYM(func) == 0 ? ({ SIML_CALL(func, __VA_ARGS__); }) : \
					  ({ fval; }));                        \
	})
#else

static inline unsigned long simple_kallsyms_lookup_name(const char *name)
{
	return 0;
}

#define SIML_SYM(sym)
#define SIML_DECLARE(dec)
#define SIML_GET_SYM(sym) ({ 0; })
#define SIML_SAFETY(sym)
#define SIML_CALL(func, ...) ({ func(__VA_ARGS__); })
#define SIML_VAR(sym) (sym)
#define SIML_ONESHOT_VAR_SET(sym, val) ({ sym = val; 0; })
#define SIML_ONESHOT_VAR_GET(fval, sym) ({ sym; })
#define SIML_ONESHOT_FUNC_CALL_NORET(func, ...) ({ func(__VA_ARGS__); 0; })
#define SIML_ONESHOT_FUNC_CALL(fval, func, ...) ({ func(__VA_ARGS__); })
#endif

#endif /* __SIMPLE_LOOKUP_NAME_H__ */
