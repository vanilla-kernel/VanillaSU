#ifndef __KSU_H_SECCOMP_CACHE
#define __KSU_H_SECCOMP_CACHE

#include <linux/fs.h>
#include <linux/seccomp.h>
#include <linux/version.h>

struct seccomp_filter;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
extern void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr);
extern void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr);
#else
static inline void ksu_seccomp_clear_cache(struct seccomp_filter *filter, int nr)
{
}

static inline void ksu_seccomp_allow_cache(struct seccomp_filter *filter, int nr)
{
}
#endif // #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)

#endif
