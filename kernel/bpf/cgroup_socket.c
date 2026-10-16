/* SPDX-License-Identifier: GPL-2.0 */
/* Cgroup socket-hook backport. ABI/semantics reference: Linux v5.10,
 * 2c85ebc57b3e1817b6ce1a6b703928e113a90442 kernel/bpf/cgroup.c.
 */
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/ipv6.h>

static bool inet_socket(const struct sock *sk)
{
	return sk && (sk->sk_family == AF_INET || sk->sk_family == AF_INET6);
}

static void sock_context(struct bpf_sock *ctx, struct sock *sk)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->bound_dev_if = sk->sk_bound_dev_if;
	ctx->family = sk->sk_family;
	ctx->type = sk->sk_type;
	ctx->protocol = sk->sk_protocol;
	ctx->mark = sk->sk_mark;
	ctx->priority = sk->sk_priority;
	ctx->src_ip4 = sk->sk_rcv_saddr;
	ctx->dst_ip4 = sk->sk_daddr;
	ctx->src_port = sk->sk_num;
	ctx->dst_port = sk->sk_dport;
	ctx->state = sk->sk_state;
#if IS_ENABLED(CONFIG_IPV6)
	memcpy(ctx->src_ip6, &sk->sk_v6_rcv_saddr, sizeof(ctx->src_ip6));
	memcpy(ctx->dst_ip6, &sk->sk_v6_daddr, sizeof(ctx->dst_ip6));
#endif
}

int bpf_cgroup_socket_create(struct sock *sk)
{
	struct bpf_sock_kern ctx;
	int ret;

	if (!inet_socket(sk) || !cgroup_bpf_enabled)
		return 0;
	sock_context(&ctx.user, sk);
	ctx.sk = sk;
	rcu_read_lock();
	ret = bpf_cgroup_run_array(sock_cgroup_ptr(&sk->sk_cgrp_data),
				   BPF_CGROUP_INET_SOCK_CREATE, &ctx, false);
	rcu_read_unlock();
	if (!ret)
		return -EPERM;
	sk->sk_bound_dev_if = ctx.user.bound_dev_if;
	sk->sk_mark = ctx.user.mark;
	sk->sk_priority = ctx.user.priority;
	return 0;
}

void bpf_cgroup_socket_release(struct sock *sk)
{
	struct bpf_sock_kern ctx;

	if (!inet_socket(sk) || !cgroup_bpf_enabled)
		return;
	sock_context(&ctx.user, sk);
	ctx.sk = sk;
	rcu_read_lock();
	bpf_cgroup_run_array(sock_cgroup_ptr(&sk->sk_cgrp_data),
			     BPF_CGROUP_INET_SOCK_RELEASE, &ctx, false);
	rcu_read_unlock();
}

int bpf_cgroup_sock_addr(struct sock *sk, struct sockaddr *addr, int len,
			enum bpf_attach_type type, void *source)
{
	struct bpf_sock_addr_kern ctx;
	struct sockaddr_storage unspec;
	bool synthetic = !addr;
	struct sockaddr_in *v4 = (void *)addr;
	struct sockaddr_in6 *v6 = (void *)addr;
	bool ipv6;
	int ret;

	if (!inet_socket(sk) || !cgroup_bpf_enabled)
		return 0;
	if (!addr) {
		memset(&unspec, 0, sizeof(unspec));
		addr = (struct sockaddr *)&unspec;
		len = sizeof(unspec);
		v4 = (void *)addr; v6 = (void *)addr;
	}
	ipv6 = type == BPF_CGROUP_INET6_BIND || type == BPF_CGROUP_INET6_CONNECT ||
	       type == BPF_CGROUP_UDP6_SENDMSG || type == BPF_CGROUP_UDP6_RECVMSG;
	if (!synthetic && addr->sa_family != (ipv6 ? AF_INET6 : AF_INET) &&
	    !(addr->sa_family == AF_UNSPEC && type == BPF_CGROUP_INET4_BIND))
		return 0;
	if (len < (ipv6 ? SIN6_LEN_RFC2133 : sizeof(*v4)))
		return -EINVAL;
	memset(&ctx, 0, sizeof(ctx));
	ctx.sk = sk;
	ctx.user.sk = (unsigned long)sk;
	ctx.user.user_family = addr->sa_family;
	ctx.user.family = sk->sk_family;
	ctx.user.type = sk->sk_type;
	ctx.user.protocol = sk->sk_protocol;
	if (ipv6) {
		memcpy(ctx.user.user_ip6, &v6->sin6_addr, sizeof(ctx.user.user_ip6));
		ctx.user.user_port = v6->sin6_port;
		if (source)
			memcpy(ctx.user.msg_src_ip6, source, sizeof(ctx.user.msg_src_ip6));
	} else {
		ctx.user.user_ip4 = v4->sin_addr.s_addr;
		ctx.user.user_port = v4->sin_port;
		if (source)
			ctx.user.msg_src_ip4 = *(__be32 *)source;
	}
	rcu_read_lock();
	ret = bpf_cgroup_run_array(sock_cgroup_ptr(&sk->sk_cgrp_data), type, &ctx, false);
	rcu_read_unlock();
	if (!ret && type != BPF_CGROUP_UDP4_RECVMSG && type != BPF_CGROUP_UDP6_RECVMSG)
		return -EPERM;
	/* UDP receive hooks cannot reject a datagram already copied. */
	/* The verifier permits writes only to address/source/port fields. */
	if (ipv6) {
		memcpy(&v6->sin6_addr, ctx.user.user_ip6, sizeof(v6->sin6_addr));
		v6->sin6_port = ctx.user.user_port;
		if (source)
			memcpy(source, ctx.user.msg_src_ip6, sizeof(ctx.user.msg_src_ip6));
	} else {
		v4->sin_addr.s_addr = ctx.user.user_ip4;
		v4->sin_port = ctx.user.user_port;
		if (source)
			*(__be32 *)source = ctx.user.msg_src_ip4;
	}
	return 0;
}

int bpf_cgroup_setsockopt(struct sock *sk, int *level, int *optname,
			 char __user *optval, int *optlen, char **kernel_optval)
{
	struct bpf_sockopt_kern ctx;
	int capacity, ret;

	*kernel_optval = NULL;
	if (!inet_socket(sk) || in_compat_syscall() || !cgroup_bpf_enabled ||
	    !bpf_cgroup_has_program(sk, BPF_CGROUP_SETSOCKOPT))
		return 0;
	if (*optlen < 0)
		return -EINVAL;
	capacity = min_t(int, max_t(int, *optlen, 16), PAGE_SIZE);
	memset(&ctx, 0, sizeof(ctx));
	ctx.sk = sk;
	ctx.user.sk = (unsigned long)sk;
	ctx.optval = kzalloc(capacity, GFP_KERNEL);
	if (!ctx.optval)
		return -ENOMEM;
	ctx.user.optval = (unsigned long)ctx.optval;
	ctx.user.optval_end = (unsigned long)(ctx.optval + capacity);
	ctx.user.level = *level;
	ctx.user.optname = *optname;
	ctx.user.optlen = *optlen;
	if (copy_from_user(ctx.optval, optval, min_t(int, *optlen, capacity))) {
		ret = -EFAULT;
		goto out;
	}
	lock_sock(sk);
	rcu_read_lock();
	ret = bpf_cgroup_run_array(sock_cgroup_ptr(&sk->sk_cgrp_data),
				   BPF_CGROUP_SETSOCKOPT, &ctx, false);
	rcu_read_unlock();
	release_sock(sk);
	if (!ret) {
		ret = -EPERM;
		goto out;
	}
	if (ctx.user.optlen == -1) {
		ret = 1;
		goto out;
	}
	if (ctx.user.optlen < -1 || ctx.user.optlen > capacity) {
		ret = -EFAULT;
		goto out;
	}
	*level = ctx.user.level;
	*optname = ctx.user.optname;
	if (ctx.user.optlen) {
		*optlen = ctx.user.optlen;
		*kernel_optval = ctx.optval;
		return 0;
	}
	ret = 0;
out:
	kfree(ctx.optval);
	return ret;
}

int bpf_cgroup_getsockopt(struct sock *sk, int level, int optname,
			 char __user *optval, int __user *optlen,
			 int original_capacity, int retval)
{
	struct bpf_sockopt_kern ctx;
	int capacity, ret;

	if (!inet_socket(sk) || in_compat_syscall() || !cgroup_bpf_enabled ||
	    !bpf_cgroup_has_program(sk, BPF_CGROUP_GETSOCKOPT))
		return retval;
	if (original_capacity < 0)
		return -EINVAL;
	capacity = min_t(int, original_capacity, PAGE_SIZE);
	memset(&ctx, 0, sizeof(ctx));
	ctx.sk = sk;
	ctx.user.sk = (unsigned long)sk;
	ctx.optval = kzalloc(max_t(int, capacity, 1), GFP_KERNEL);
	if (!ctx.optval)
		return -ENOMEM;
	ctx.user.optval = (unsigned long)ctx.optval;
	ctx.user.optval_end = (unsigned long)(ctx.optval + capacity);
	ctx.user.level = level;
	ctx.user.optname = optname;
	ctx.user.retval = retval;
	ctx.user.optlen = original_capacity;
	if (!retval) {
		if (get_user(ctx.user.optlen, optlen) || ctx.user.optlen < 0 ||
		    ctx.user.optlen > original_capacity ||
		    copy_from_user(ctx.optval, optval, min_t(int, ctx.user.optlen, capacity))) {
			ret = -EFAULT;
			goto out;
		}
	}
	lock_sock(sk);
	rcu_read_lock();
	ret = bpf_cgroup_run_array(sock_cgroup_ptr(&sk->sk_cgrp_data),
				   BPF_CGROUP_GETSOCKOPT, &ctx, false);
	rcu_read_unlock();
	release_sock(sk);
	if (!ret) {
		ret = -EPERM;
		goto out;
	}
	if (ctx.user.optlen < 0 || ctx.user.optlen > capacity ||
	    (ctx.user.retval && ctx.user.retval != retval)) {
		ret = -EFAULT;
		goto out;
	}
	if (ctx.user.optlen &&
	    (copy_to_user(optval, ctx.optval, ctx.user.optlen) ||
	     put_user(ctx.user.optlen, optlen))) {
		ret = -EFAULT;
		goto out;
	}
	ret = ctx.user.retval;
out:
	kfree(ctx.optval);
	return ret;
}
