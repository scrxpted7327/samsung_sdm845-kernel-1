/* SPDX-License-Identifier: GPL-2.0 */
/* Cgroup attachment lifetime/inheritance adapted to the 4.9 cgroup lock. */
#include <linux/kernel.h>
#include <linux/cgroup.h>
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <net/sock.h>

DEFINE_STATIC_KEY_FALSE(cgroup_bpf_enabled_key);
EXPORT_SYMBOL(cgroup_bpf_enabled_key);

static struct cgroup *bpf_parent(struct cgroup *cgrp)
{
	return cgrp->self.parent ? cgrp->self.parent->cgroup : NULL;
}

static void link_free(struct rcu_head *rcu)
{
	struct bpf_cgroup_link *link = container_of(rcu, struct bpf_cgroup_link, rcu);
	bpf_prog_put(link->prog);
	kfree(link);
}

void cgroup_bpf_put(struct cgroup *cgrp)
{
	unsigned int type;
	for (type = 0; type < MAX_BPF_ATTACH_TYPE; type++) {
		struct bpf_cgroup_link *link, *next;
		link = rcu_dereference_protected(cgrp->bpf.links[type], 1);
		RCU_INIT_POINTER(cgrp->bpf.links[type], NULL);
		while (link) {
			next = rcu_dereference_protected(link->next, 1);
			static_branch_dec(&cgroup_bpf_enabled_key);
			call_rcu(&link->rcu, link_free);
			link = next;
		}
	}
}

void cgroup_bpf_inherit(struct cgroup *cgrp, struct cgroup *parent)
{
	/* Parent CSS lifetime is pinned by the child; runtime traversal under RCU
	 * observes parent updates without copying dangling program pointers. */
}

int __cgroup_bpf_update(struct cgroup *cgrp, struct cgroup *parent,
			struct bpf_prog *prog, struct bpf_prog *old_prog,
			enum bpf_attach_type type, u32 flags)
{
	struct bpf_cgroup_link *head, *link, *prev = NULL, *new = NULL;
	struct cgroup *ancestor;
	u32 old_flags;
	unsigned int count = 0;

	if (type >= MAX_BPF_ATTACH_TYPE ||
	    flags & ~(BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI) ||
	    flags == (BPF_F_ALLOW_OVERRIDE | BPF_F_ALLOW_MULTI))
		return -EINVAL;
	head = rcu_dereference_protected(cgrp->bpf.links[type], 1);
	old_flags = cgrp->bpf.flags[type];
	if (prog && head && old_flags != flags)
		return -EPERM;
	if (prog) {
		/* Upstream: the nearest attached ancestor controls permission. */
		for (ancestor = parent; ancestor; ancestor = bpf_parent(ancestor)) {
			struct bpf_cgroup_link *al = rcu_dereference_protected(ancestor->bpf.links[type], 1);
			if (!al) continue;
			if (!al->flags) return -EPERM;
			break;
		}
	}
	for (link = head; link; link = rcu_dereference_protected(link->next, 1)) {
		count++;
		if (prog && flags == BPF_F_ALLOW_MULTI && link->prog == prog)
			return -EINVAL;
	}
	if (prog && count >= 64)
		return -E2BIG;
	if (prog) {
		new = kzalloc(sizeof(*new), GFP_KERNEL);
		if (!new)
			return -ENOMEM;
		new->prog = prog;
		new->flags = flags;
		if (flags != BPF_F_ALLOW_MULTI) {
			if (head && rcu_access_pointer(head->next)) {
				kfree(new);
				return -EINVAL;
			}
			rcu_assign_pointer(cgrp->bpf.links[type], new);
			if (head) {
				call_rcu(&head->rcu, link_free);
			} else {
				static_branch_inc(&cgroup_bpf_enabled_key);
			}
		} else {
			if (!head)
				rcu_assign_pointer(cgrp->bpf.links[type], new);
			else {
				link = head;
				while (rcu_access_pointer(link->next))
					link = rcu_dereference_protected(link->next, 1);
				rcu_assign_pointer(link->next, new);
			}
			static_branch_inc(&cgroup_bpf_enabled_key);
		}
		cgrp->bpf.flags[type] = flags;
		return 0;
	}
	if (!head)
		return -ENOENT;
	if (old_flags == BPF_F_ALLOW_MULTI && !old_prog)
		return -EINVAL;
	link = head;
	while (link && old_prog && link->prog != old_prog) {
		prev = link;
		link = rcu_dereference_protected(link->next, 1);
	}
	if (!link)
		return -ENOENT;
	if (prev)
		rcu_assign_pointer(prev->next, rcu_dereference_protected(link->next, 1));
	else
		rcu_assign_pointer(cgrp->bpf.links[type], rcu_dereference_protected(link->next, 1));
	static_branch_dec(&cgroup_bpf_enabled_key);
	call_rcu(&link->rcu, link_free);
	if (!rcu_access_pointer(cgrp->bpf.links[type])) cgrp->bpf.flags[type] = 0;
	return 0;
}

/* Caller holds cgroup_mutex, so a query returns one coherent ID snapshot. */
int __cgroup_bpf_query(struct cgroup *cgrp, enum bpf_attach_type type,
		      bool effective, u32 *flags, u32 *ids, u32 capacity)
{
	struct bpf_cgroup_link *link;
	u32 count = 0;
	bool selected = false;

	*flags = effective ? 0 : cgrp->bpf.flags[type];
	for (; cgrp; cgrp = effective ? bpf_parent(cgrp) : NULL) {
		link = rcu_dereference_protected(cgrp->bpf.links[type], 1);
		if (selected && link && link->flags != BPF_F_ALLOW_MULTI)
			continue;
		if (link) selected = true;
		for (; link; link = rcu_dereference_protected(link->next, 1)) {
			if (count < capacity)
				ids[count] = link->prog->aux->id;
			count++;
		}
	}
	return count;
}

int bpf_cgroup_run_array(struct cgroup *cgrp, enum bpf_attach_type type,
			void *ctx, bool skb)
{
	struct bpf_cgroup_link *link;
	bool selected = false;
	int result = 1;

	for (; cgrp; cgrp = bpf_parent(cgrp)) {
		link = rcu_dereference(cgrp->bpf.links[type]);
		if (selected && link && link->flags != BPF_F_ALLOW_MULTI)
			continue;
		if (link) selected = true;
		for (; link; link = rcu_dereference(link->next)) {
			u32 ret = skb ? bpf_prog_run_save_cb(link->prog, ctx) :
					BPF_PROG_RUN(link->prog, ctx);
			if (!(ret & 1))
				result = 0;
		}
	}
	return result;
}

bool bpf_cgroup_has_program(struct sock *sk, enum bpf_attach_type type)
{
	struct cgroup *cgrp;
	bool present = false;
	if (!sk || !sk_fullsock(sk) || (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)) return false;
	rcu_read_lock();
	for (cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data); cgrp; cgrp = bpf_parent(cgrp))
		if (rcu_access_pointer(cgrp->bpf.links[type])) {
			present = true;
			break;
		}
	rcu_read_unlock();
	return present;
}

int __cgroup_bpf_run_filter(struct sock *sk, struct sk_buff *skb,
			    enum bpf_attach_type type)
{
	struct sock *save_sk;
	unsigned int offset;
	int ret;

	if (!sk || !sk_fullsock(sk) ||
	    (sk->sk_family != AF_INET && sk->sk_family != AF_INET6))
		return 0;
	offset = skb->data - skb_network_header(skb);
	save_sk = skb->sk;
	skb->sk = sk;
	__skb_push(skb, offset);
	rcu_read_lock();
	ret = bpf_cgroup_run_array(sock_cgroup_ptr(&sk->sk_cgrp_data), type, skb, true);
	rcu_read_unlock();
	__skb_pull(skb, offset);
	skb->sk = save_sk;
	return ret ? 0 : -EPERM;
}
EXPORT_SYMBOL(__cgroup_bpf_run_filter);
