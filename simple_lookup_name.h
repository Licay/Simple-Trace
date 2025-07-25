#ifndef __SIMPLE_LOOKUP_NAME_H__
#define __SIMPLE_LOOKUP_NAME_H__

#if IS_ENABLED(CONFIG_SIMPLE_LOOKUP_NAME)
unsigned long simple_kallsyms_lookup_name(const char *name);

#define NGKI_SYM(sym) typeof(&sym) _ngki_##sym
#define NGKI_DECLARE(dec) dec

#define NGKI_GET_FUNC(func)                                                          \
	({                                                                           \
		_ngki_##func =                                                       \
			(typeof(_ngki_##func))simple_kallsyms_lookup_name(           \
				#func);                                              \
		if (!_ngki_##func) {                                                 \
			pr_err("NGKI function %s is not available in this kernel\n", \
			       #func);                                               \
			-ENOSYS;                                                     \
		}                                                                    \
		0;                                                                   \
	})

#define NGKI_GET_SYM(sym)                                                          \
	({                                                                         \
		_ngki_##sym =                                                      \
			(typeof(_ngki_##sym))simple_kallsyms_lookup_name(          \
				#sym);                                             \
		if (!_ngki_##sym) {                                                \
			pr_err("NGKI symbol %s is not available in this kernel\n", \
			       #sym);                                              \
			-ENOSYS;                                                   \
		}                                                                  \
		0;                                                                 \
	})

#define NGKI_SAFETY(sym)                                                 \
	if (unlikely(!_ngki_##sym)) {                                    \
		pr_err("NGKI call %s is not available in this kernel\n", \
		       #sym);                                            \
	} else
/* Maybe symbol is not available in this kernel, so you need to check
 * the return value of NGKI_GET_FUNC() or NGKI_GET_SYM() before using
 * NGKI_CALL() or NGKI_VAR().
 * you can use NGKI_SAFETY() to check the symbol is available
 * like this:
 * NGKI_SAFETY(func) {
 *     NGKI_CALL(func, ...);
 * }
 * or
 * NGKI_SAFETY(sym) {
 *     NGKI_VAR(sym) = ...;
 * }
 * If the symbol is not available, NGKI_SAFETY() will print an error message
 * and skip the code inside the block.
 */
#define NGKI_CALL(func, ...) (_ngki_##func(__VA_ARGS__))
#define NGKI_VAR(sym) (*_ngki_##sym)
#else
#define NGKI_SYM(sym)
#define NGKI_DECLARE(dec)
#define NGKI_GET_FUNC(func) ({ 0; })
#define NGKI_GET_SYM(sym) ({ 0; })
#define NGKI_SAFETY(sym)
#define NGKI_CALL(func, ...) ({ func(__VA_ARGS__); })
#define NGKI_VAR(sym) (sym)
#endif

#endif /* __SIMPLE_LOOKUP_NAME_H__ */
