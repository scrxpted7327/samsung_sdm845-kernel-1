/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2016 Facebook
 *
 * LRU hash implementation adapted from upstream hashtab.c.
 */
#include <linux/bpf.h>
#include <linux/jhash.h>
#include <linux/filter.h>
#include <linux/rculist_nulls.h>
#include "bpf_lru_list.h"

struct bucket {
	struct hlist_nulls_head head;
	raw_spinlock_t lock;
};

struct bpf_htab {
	struct bpf_map map;
	struct bucket *buckets;
	void *elems;
	struct bpf_lru lru;
	u32 n_buckets;
	u32 elem_size;
};

struct htab_elem {
	struct hlist_nulls_node hash_node;
	struct bpf_lru_node lru_node;
	u32 hash;
	char key[0] __aligned(8);
};

static bool htab_lru_map_delete_node(void *arg, struct bpf_lru_node *node);

static struct bpf_map *htab_lru_map_alloc(union bpf_attr *attr)
{
	struct bpf_htab *htab;
	u64 cost;
	int err, i;

	if (!capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);
	/* LRU preallocation is mandatory; preserve supported FD access flags. */
	if (attr->map_flags & ~(BPF_F_NO_COMMON_LRU | BPF_F_RDONLY | BPF_F_WRONLY))
		return ERR_PTR(-EINVAL);
	if (!attr->max_entries || !attr->key_size || !attr->value_size)
		return ERR_PTR(-EINVAL);
	if (attr->key_size > MAX_BPF_STACK ||
	    attr->value_size >= (1 << (KMALLOC_SHIFT_MAX - 1)) -
		MAX_BPF_STACK - sizeof(struct htab_elem))
		return ERR_PTR(-E2BIG);

	htab = kzalloc(sizeof(*htab), GFP_USER);
	if (!htab)
		return ERR_PTR(-ENOMEM);
	htab->map.map_type = attr->map_type;
	htab->map.key_size = attr->key_size;
	htab->map.value_size = attr->value_size;
	htab->map.max_entries = attr->max_entries;
	htab->map.map_flags = attr->map_flags;
	if (attr->map_flags & BPF_F_NO_COMMON_LRU) {
		htab->map.max_entries = roundup(attr->max_entries, num_possible_cpus());
		if (htab->map.max_entries < attr->max_entries) {
			err = -E2BIG;
			goto free_htab;
		}
	}
	htab->n_buckets = roundup_pow_of_two(htab->map.max_entries);
	htab->elem_size = sizeof(struct htab_elem) + round_up(attr->key_size, 8) +
			 round_up(attr->value_size, 8);
	err = -E2BIG;
	if (!htab->n_buckets || htab->n_buckets > U32_MAX / sizeof(struct bucket) ||
	    htab->map.max_entries > U32_MAX / htab->elem_size)
		goto free_htab;
	/* Cover separately allocated pools and both LRU-manager variants. */
	cost = round_up((u64)sizeof(*htab), PAGE_SIZE) +
	       round_up((u64)htab->n_buckets * sizeof(struct bucket), PAGE_SIZE) +
	       round_up((u64)htab->elem_size * htab->map.max_entries, PAGE_SIZE) +
	       round_up((u64)num_possible_cpus() *
			(attr->map_flags & BPF_F_NO_COMMON_LRU ?
			 sizeof(struct bpf_lru_list) : sizeof(struct bpf_lru_locallist)),
			PAGE_SIZE);
	if (cost >= U32_MAX - PAGE_SIZE)
		goto free_htab;
	htab->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;
	err = bpf_map_precharge_memlock(htab->map.pages);
	if (err)
		goto free_htab;
	err = -ENOMEM;
	htab->buckets = bpf_map_area_alloc(htab->n_buckets * sizeof(struct bucket));
	if (!htab->buckets)
		goto free_htab;
	htab->elems = bpf_map_area_alloc(htab->elem_size * htab->map.max_entries);
	if (!htab->elems)
		goto free_buckets;
	for (i = 0; i < htab->n_buckets; i++) {
		INIT_HLIST_NULLS_HEAD(&htab->buckets[i].head, i);
		raw_spin_lock_init(&htab->buckets[i].lock);
	}
	err = bpf_lru_init(&htab->lru, attr->map_flags & BPF_F_NO_COMMON_LRU,
			   offsetof(struct htab_elem, hash) -
			   offsetof(struct htab_elem, lru_node),
			   htab_lru_map_delete_node, htab);
	if (err)
		goto free_elems;
	bpf_lru_populate(&htab->lru, htab->elems,
			offsetof(struct htab_elem, lru_node),
			htab->elem_size, htab->map.max_entries);
	return &htab->map;
free_elems:
	bpf_map_area_free(htab->elems);
free_buckets:
	bpf_map_area_free(htab->buckets);
free_htab:
	kfree(htab);
	return ERR_PTR(err);
}

static inline u32 htab_map_hash(const void *key, u32 key_len)
{
	return jhash(key, key_len, 0);
}

static inline struct bucket *__select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &htab->buckets[hash & (htab->n_buckets - 1)];
}

static inline struct hlist_nulls_head *select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &__select_bucket(htab, hash)->head;
}

static struct htab_elem *lookup_elem_raw(struct hlist_nulls_head *head, u32 hash,
					 void *key, u32 key_size)
{
	struct hlist_nulls_node *n;
	struct htab_elem *l;

	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;

	return NULL;
}

static struct htab_elem *lookup_nulls_elem_raw(struct hlist_nulls_head *head,
					       u32 hash, void *key,
					       u32 key_size, u32 n_buckets)
{
	struct hlist_nulls_node *n;
	struct htab_elem *l;

again:
	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;

	if (unlikely(get_nulls_value(n) != (hash & (n_buckets - 1))))
		goto again;

	return NULL;
}

static void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct htab_elem *l;
	u32 hash, key_size;

	/* Must be called with rcu_read_lock. */
	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size);

	head = select_bucket(htab, hash);

	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);

	return l;
}

static void *htab_lru_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct htab_elem *l = __htab_map_lookup_elem(map, key);

	if (l) {
		bpf_lru_node_set_ref(&l->lru_node);
		return l->key + round_up(map->key_size, 8);
	}

	return NULL;
}

static bool htab_lru_map_delete_node(void *arg, struct bpf_lru_node *node)
{
	struct bpf_htab *htab = (struct bpf_htab *)arg;
	struct htab_elem *l = NULL, *tgt_l;
	struct hlist_nulls_head *head;
	struct hlist_nulls_node *n;
	unsigned long flags;
	struct bucket *b;

	tgt_l = container_of(node, struct htab_elem, lru_node);
	b = __select_bucket(htab, tgt_l->hash);
	head = &b->head;

	raw_spin_lock_irqsave(&b->lock, flags);

	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (l == tgt_l) {
			hlist_nulls_del_rcu(&l->hash_node);
			break;
		}

	raw_spin_unlock_irqrestore(&b->lock, flags);

	return l == tgt_l;
}

static int htab_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct htab_elem *l, *next_l;
	u32 hash, key_size;
	int i = 0;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	if (!key)
		goto find_first_elem;

	hash = htab_map_hash(key, key_size);

	head = select_bucket(htab, hash);

	/* lookup the key */
	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);

	if (!l)
		goto find_first_elem;

	/* key was found, get next key in the same bucket */
	next_l = hlist_nulls_entry_safe(rcu_dereference_raw(hlist_nulls_next_rcu(&l->hash_node)),
				  struct htab_elem, hash_node);

	if (next_l) {
		/* if next elem in this hash list is non-zero, just return it */
		memcpy(next_key, next_l->key, key_size);
		return 0;
	}

	/* no more elements in this hash list, go to the next bucket */
	i = hash & (htab->n_buckets - 1);
	i++;

find_first_elem:
	/* iterate over buckets */
	for (; i < htab->n_buckets; i++) {
		head = select_bucket(htab, i);

		/* pick first element in the bucket */
		next_l = hlist_nulls_entry_safe(rcu_dereference_raw(hlist_nulls_first_rcu(head)),
					  struct htab_elem, hash_node);
		if (next_l) {
			/* if it's not empty, just return it */
			memcpy(next_key, next_l->key, key_size);
			return 0;
		}
	}

	/* iterated over all buckets and all elements */
	return -ENOENT;
}

static struct htab_elem *prealloc_lru_pop(struct bpf_htab *htab, void *key,
					  u32 hash)
{
	struct bpf_lru_node *node = bpf_lru_pop_free(&htab->lru, hash);
	struct htab_elem *l;

	if (node) {
		l = container_of(node, struct htab_elem, lru_node);
		memcpy(l->key, key, htab->map.key_size);
		return l;
	}

	return NULL;
}

static int check_flags(struct htab_elem *l_old,
		       u64 map_flags)
{
	if (l_old && map_flags == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!l_old && map_flags == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static int htab_lru_map_update_elem(struct bpf_map *map, void *key, void *value,
				    u64 map_flags)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct htab_elem *l_new, *l_old = NULL;
	struct hlist_nulls_head *head;
	unsigned long flags;
	struct bucket *b;
	u32 key_size, hash;
	int ret;

	if (unlikely(map_flags > BPF_EXIST))
		/* unknown flags */
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size);

	b = __select_bucket(htab, hash);
	head = &b->head;

	/* For LRU, we need to alloc before taking bucket's
	 * spinlock because getting free nodes from LRU may need
	 * to remove older elements from htab and this removal
	 * operation will need a bucket lock.
	 */
	l_new = prealloc_lru_pop(htab, key, hash);
	if (!l_new)
		return -ENOMEM;
	memcpy(l_new->key + round_up(map->key_size, 8), value, map->value_size);

	/* bpf_map_update_elem() can be called in_irq() */
	raw_spin_lock_irqsave(&b->lock, flags);

	l_old = lookup_elem_raw(head, hash, key, key_size);

	ret = check_flags(l_old, map_flags);
	if (ret)
		goto err;

	/* add new element to the head of the list, so that
	 * concurrent search will find it before old elem
	 */
	hlist_nulls_add_head_rcu(&l_new->hash_node, head);
	if (l_old) {
		bpf_lru_node_set_ref(&l_new->lru_node);
		hlist_nulls_del_rcu(&l_old->hash_node);
	}
	ret = 0;

err:
	raw_spin_unlock_irqrestore(&b->lock, flags);

	if (ret)
		bpf_lru_push_free(&htab->lru, &l_new->lru_node);
	else if (l_old)
		bpf_lru_push_free(&htab->lru, &l_old->lru_node);

	return ret;
}

static int htab_lru_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct bucket *b;
	struct htab_elem *l;
	unsigned long flags;
	u32 hash, key_size;
	int ret = -ENOENT;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size);
	b = __select_bucket(htab, hash);
	head = &b->head;

	raw_spin_lock_irqsave(&b->lock, flags);

	l = lookup_elem_raw(head, hash, key, key_size);

	if (l) {
		hlist_nulls_del_rcu(&l->hash_node);
		ret = 0;
	}

	raw_spin_unlock_irqrestore(&b->lock, flags);
	if (l)
		bpf_lru_push_free(&htab->lru, &l->lru_node);
	return ret;
}

static void htab_lru_map_free(struct bpf_map *map)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);

	synchronize_rcu();
	bpf_lru_destroy(&htab->lru);
	bpf_map_area_free(htab->elems);
	bpf_map_area_free(htab->buckets);
	kfree(htab);
}

static const struct bpf_map_ops htab_lru_ops = {
	.map_alloc = htab_lru_map_alloc,
	.map_free = htab_lru_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_lru_map_lookup_elem,
	.map_update_elem = htab_lru_map_update_elem,
	.map_delete_elem = htab_lru_map_delete_elem,
};

static struct bpf_map_type_list htab_lru_type __read_mostly = {
	.ops = &htab_lru_ops,
	.type = BPF_MAP_TYPE_LRU_HASH,
};

static int __init register_lru_hash_map(void)
{
	bpf_register_map_type(&htab_lru_type);
	return 0;
}
late_initcall(register_lru_hash_map);
