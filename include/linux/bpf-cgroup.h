#ifndef _BPF_CGROUP_H
#define _BPF_CGROUP_H

#include <linux/jump_label.h>
#include <uapi/linux/bpf.h>

struct sock;
struct cgroup;
struct sk_buff;
struct sockaddr;

#ifdef CONFIG_CGROUP_BPF

extern struct static_key_false cgroup_bpf_enabled_key;
#define cgroup_bpf_enabled static_branch_unlikely(&cgroup_bpf_enabled_key)

struct bpf_cgroup_link {
	struct bpf_prog *prog;
	u32 flags;
	struct bpf_cgroup_link __rcu *next;
	struct rcu_head rcu;
};
struct cgroup_bpf {
	struct bpf_cgroup_link __rcu *links[MAX_BPF_ATTACH_TYPE];
	u32 flags[MAX_BPF_ATTACH_TYPE];
};

void cgroup_bpf_put(struct cgroup *cgrp);
void cgroup_bpf_inherit(struct cgroup *cgrp, struct cgroup *parent);

int __cgroup_bpf_update(struct cgroup *cgrp, struct cgroup *parent,
			struct bpf_prog *prog, struct bpf_prog *old_prog,
			enum bpf_attach_type type, u32 flags);
int cgroup_bpf_update(struct cgroup *cgrp, struct bpf_prog *prog, struct bpf_prog *old_prog,
		      enum bpf_attach_type type, u32 flags);
int __cgroup_bpf_query(struct cgroup *cgrp, enum bpf_attach_type type,
		      bool effective, u32 *flags, u32 *ids, u32 capacity);
int cgroup_bpf_query(struct cgroup *cgrp, enum bpf_attach_type type,
		     bool effective, u32 *flags, u32 *ids, u32 capacity);
int bpf_cgroup_run_array(struct cgroup *cgrp, enum bpf_attach_type type, void *ctx, bool skb);
bool bpf_cgroup_has_program(struct sock *sk, enum bpf_attach_type type);
int bpf_cgroup_socket_create(struct sock *sk);
void bpf_cgroup_socket_release(struct sock *sk);
int bpf_cgroup_sock_addr(struct sock *sk, struct sockaddr *addr, int len,
			enum bpf_attach_type type, void *source);
int bpf_cgroup_setsockopt(struct sock *sk, int *level, int *optname,
			 char __user *optval, int *optlen, char **kernel_optval);
int bpf_cgroup_getsockopt(struct sock *sk, int level, int optname,
			 char __user *optval, int __user *optlen, int capacity, int retval);

int __cgroup_bpf_run_filter(struct sock *sk,
			    struct sk_buff *skb,
			    enum bpf_attach_type type);

/* Wrappers for __cgroup_bpf_run_filter() guarded by cgroup_bpf_enabled. */
#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk,skb)			\
({									\
	int __ret = 0;							\
	if (cgroup_bpf_enabled)						\
		__ret = __cgroup_bpf_run_filter(sk, skb,		\
						BPF_CGROUP_INET_INGRESS); \
									\
	__ret;								\
})

#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk,skb)				\
({									\
	int __ret = 0;							\
	if (cgroup_bpf_enabled && sk && sk == skb->sk) {		\
		typeof(sk) __sk = sk_to_full_sk(sk);			\
		if (sk_fullsock(__sk))					\
			__ret = __cgroup_bpf_run_filter(__sk, skb,	\
						BPF_CGROUP_INET_EGRESS); \
	}								\
	__ret;								\
})

#else

struct cgroup_bpf {};
static inline bool bpf_cgroup_has_program(struct sock *sk, enum bpf_attach_type type) { return false; }
static inline int bpf_cgroup_socket_create(struct sock *sk) { return 0; }
static inline void bpf_cgroup_socket_release(struct sock *sk) {}
static inline int bpf_cgroup_sock_addr(struct sock *sk, struct sockaddr *addr, int len,
				     enum bpf_attach_type type, void *source) { return 0; }
static inline int bpf_cgroup_setsockopt(struct sock *sk, int *level, int *optname,
		 char __user *optval, int *optlen, char **value) { *value = NULL; return 0; }
static inline int bpf_cgroup_getsockopt(struct sock *sk, int level, int optname,
		 char __user *optval, int __user *optlen, int capacity, int retval) { return retval; }
static inline void cgroup_bpf_put(struct cgroup *cgrp) {}
static inline void cgroup_bpf_inherit(struct cgroup *cgrp,
				      struct cgroup *parent) {}

#define BPF_CGROUP_RUN_PROG_INET_INGRESS(sk,skb) ({ 0; })
#define BPF_CGROUP_RUN_PROG_INET_EGRESS(sk,skb) ({ 0; })

#endif /* CONFIG_CGROUP_BPF */

#endif /* _BPF_CGROUP_H */
