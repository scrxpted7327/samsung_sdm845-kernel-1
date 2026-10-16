/* SPDX-License-Identifier: GPL-2.0 */
/* Scoped opaque SK_STORAGE backport: no BTF spinlocks or clone-on-accept.
 * Canonical map/helper ABI follows Linux v5.10, type24/helpers107,108.
 */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/rculist.h>
#include <linux/resource.h>
#include <net/sock.h>

struct bpf_sk_storage_map {
	struct bpf_map map;
	struct list_head entries;
	struct user_struct *owner;
	unsigned long memlock_limit;
	bool dead;
};

struct bpf_sk_storage_elem {
	struct list_head global;
	struct list_head map_link;
	struct rcu_head rcu;
	struct sock *sk;
	struct bpf_sk_storage_map *storage;
	struct user_struct *owner;
	u32 pages;
	u8 data[];
};

static LIST_HEAD(storage_elems);
static DEFINE_SPINLOCK(storage_lock);

static void elem_free(struct rcu_head *rcu)
{
	struct bpf_sk_storage_elem *elem = container_of(rcu, struct bpf_sk_storage_elem, rcu);
	atomic_long_sub(elem->pages, &elem->owner->locked_vm);
	free_uid(elem->owner);
	kfree(elem);
}

static void elem_unlink(struct bpf_sk_storage_elem *elem)
{
	list_del_rcu(&elem->global);
	list_del(&elem->map_link);
	call_rcu(&elem->rcu, elem_free);
}

void bpf_sk_storage_free(struct sock *sk)
{
	struct bpf_sk_storage_elem *elem, *next;
	unsigned long flags;

	spin_lock_irqsave(&storage_lock, flags);
	list_for_each_entry_safe(elem, next, &storage_elems, global)
		if (elem->sk == sk)
			elem_unlink(elem);
	spin_unlock_irqrestore(&storage_lock, flags);
}

static struct bpf_sk_storage_elem *storage_find(struct bpf_sk_storage_map *storage,
					      struct sock *sk)
{
	struct bpf_sk_storage_elem *elem;
	list_for_each_entry_rcu(elem, &storage_elems, global)
		if (elem->storage == storage && elem->sk == sk)
			return elem;
	return NULL;
}

/* All returned values require caller RCU protection. The program/map FD
 * pins the map and a borrowed/owned full socket pins sk across this call.
 * Storage deliberately holds no socket ref: that would form a lifetime cycle.
 * Updates serialize flags and publication with deletion/socket destruction.
 */
static void *storage_get(struct bpf_map *map, struct sock *sk, void *value,
			bool create, u64 update_flags, bool update)
{
	struct bpf_sk_storage_map *storage;
	struct bpf_sk_storage_elem *elem, *fresh = NULL;
	unsigned long irqflags;
	u32 bytes, pages;
	void *result;

	if (map->map_type != BPF_MAP_TYPE_SK_STORAGE || !sk || !sk_fullsock(sk))
		return ERR_PTR(-EINVAL);
	storage = container_of(map, struct bpf_sk_storage_map, map);
retry:
	spin_lock_irqsave(&storage_lock, irqflags);
	if (storage->dead) {
		result = ERR_PTR(-ENOENT);
		goto unlock;
	}
	elem = storage_find(storage, sk);
	if (elem) {
		if (update && update_flags == BPF_NOEXIST) {
			result = ERR_PTR(-EEXIST);
			goto unlock;
		}
		if (update) memcpy(elem->data, value, map->value_size);
		result = elem->data;
		goto unlock;
	}
	if (!create || (update && update_flags == BPF_EXIST)) {
		result = ERR_PTR(-ENOENT);
		goto unlock;
	}
	if (fresh) {
		list_add_rcu(&fresh->global, &storage_elems);
		list_add(&fresh->map_link, &storage->entries);
		result = fresh->data;
		fresh = NULL;
		goto unlock;
	}
	spin_unlock_irqrestore(&storage_lock, irqflags);
	bytes = sizeof(*elem) + map->value_size;
	pages = DIV_ROUND_UP(bytes, PAGE_SIZE);
	if (atomic_long_add_return(pages, &storage->owner->locked_vm) > storage->memlock_limit) {
		atomic_long_sub(pages, &storage->owner->locked_vm);
		return ERR_PTR(-ENOMEM);
	}
	fresh = kzalloc(bytes, GFP_ATOMIC | __GFP_NOWARN);
	if (!fresh) {
		atomic_long_sub(pages, &storage->owner->locked_vm);
		return ERR_PTR(-ENOMEM);
	}
	fresh->sk = sk;
	fresh->storage = storage;
	fresh->owner = get_uid(storage->owner);
	fresh->pages = pages;
	if (value) memcpy(fresh->data, value, map->value_size);
	goto retry;
unlock:
	spin_unlock_irqrestore(&storage_lock, irqflags);
	if (fresh) {
		atomic_long_sub(fresh->pages, &fresh->owner->locked_vm);
		free_uid(fresh->owner);
		kfree(fresh);
	}
	return result;
}

void *bpf_sk_storage_get_value(struct bpf_map *map, struct sock *sk,
			      void *value, u64 flags)
{
	void *result;
	if (flags & ~BPF_SK_STORAGE_GET_F_CREATE) return NULL;
	result = storage_get(map, sk, value, flags & BPF_SK_STORAGE_GET_F_CREATE, 0, false);
	return IS_ERR(result) ? NULL : result;
}

int bpf_sk_storage_delete_value(struct bpf_map *map, struct sock *sk)
{
	struct bpf_sk_storage_map *storage;
	struct bpf_sk_storage_elem *elem;
	unsigned long flags;
	int ret = -ENOENT;

	if (map->map_type != BPF_MAP_TYPE_SK_STORAGE || !sk || !sk_fullsock(sk))
		return -EINVAL;
	storage = container_of(map, struct bpf_sk_storage_map, map);
	spin_lock_irqsave(&storage_lock, flags);
	elem = storage_find(storage, sk);
	if (elem) {
		elem_unlink(elem);
		ret = 0;
	}
	spin_unlock_irqrestore(&storage_lock, flags);
	return ret;
}

static struct bpf_map *storage_alloc(union bpf_attr *attr)
{
	struct bpf_sk_storage_map *storage;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);
	/* Fixed opaque values have no BTF/spinlock layout and no mmap ABI. */
	if (attr->key_size != sizeof(u32) || !attr->value_size ||
	    attr->value_size > 4096 || attr->max_entries ||
	    attr->map_flags != BPF_F_NO_PREALLOC)
		return ERR_PTR(-EINVAL);
	storage = kzalloc(sizeof(*storage), GFP_USER);
	if (!storage)
		return ERR_PTR(-ENOMEM);
	storage->map.map_type = BPF_MAP_TYPE_SK_STORAGE;
	storage->map.key_size = attr->key_size;
	storage->map.value_size = attr->value_size;
	storage->map.map_flags = attr->map_flags;
	storage->map.pages = DIV_ROUND_UP(sizeof(*storage), PAGE_SIZE);
	ret = bpf_map_precharge_memlock(storage->map.pages);
	if (ret) {
		kfree(storage);
		return ERR_PTR(ret);
	}
	storage->owner = get_current_user();
	storage->memlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	INIT_LIST_HEAD(&storage->entries);
	return &storage->map;
}

static void storage_free(struct bpf_map *map)
{
	struct bpf_sk_storage_map *storage = container_of(map, struct bpf_sk_storage_map, map);
	struct bpf_sk_storage_elem *elem, *next;
	unsigned long flags;

	spin_lock_irqsave(&storage_lock, flags);
	storage->dead = true;
	list_for_each_entry_safe(elem, next, &storage->entries, map_link)
		elem_unlink(elem);
	spin_unlock_irqrestore(&storage_lock, flags);
	synchronize_rcu();
	free_uid(storage->owner);
	kfree(storage);
}

static void *storage_lookup(struct bpf_map *map, void *key)
{
	struct socket *socket;
	struct bpf_sk_storage_elem *elem;
	void *result = NULL;
	int error;

	socket = sockfd_lookup(*(u32 *)key, &error);
	if (!socket)
		return ERR_PTR(error);
	if (socket->sk && sk_fullsock(socket->sk)) {
		elem = storage_find(container_of(map, struct bpf_sk_storage_map, map), socket->sk);
		if (elem)
			result = elem->data;
	}
	sockfd_put(socket);
	return result;
}

static int storage_update(struct bpf_map *map, void *key, void *value, u64 flags)
{
	struct socket *socket;
	void *result;
	int error;

	if (flags > BPF_EXIST) return -EINVAL;
	socket = sockfd_lookup(*(u32 *)key, &error);
	if (!socket) return error;
	result = storage_get(map, socket->sk, value, true, flags, true);
	error = IS_ERR(result) ? PTR_ERR(result) : 0;
	sockfd_put(socket);
	return error;
}

static int storage_delete(struct bpf_map *map, void *key)
{
	struct socket *socket;
	int error;

	socket = sockfd_lookup(*(u32 *)key, &error);
	if (!socket)
		return error;
	error = bpf_sk_storage_delete_value(map, socket->sk);
	sockfd_put(socket);
	return error;
}

static int storage_next_key(struct bpf_map *map, void *key, void *next)
{
	return -EOPNOTSUPP;
}

static const struct bpf_map_ops storage_ops = {
	.map_alloc = storage_alloc,
	.map_free = storage_free,
	.map_lookup_elem = storage_lookup,
	.map_update_elem = storage_update,
	.map_delete_elem = storage_delete,
	.map_get_next_key = storage_next_key,
};

static struct bpf_map_type_list storage_type __read_mostly = {
	.ops = &storage_ops,
	.type = BPF_MAP_TYPE_SK_STORAGE,
};

static int __init register_sk_storage(void)
{
	bpf_register_map_type(&storage_type);
	return 0;
}
late_initcall(register_sk_storage);
