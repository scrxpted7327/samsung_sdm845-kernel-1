obj-y := core.o
CFLAGS_core.o += $(call cc-disable-warning, override-init)

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o ringbuf.o lpm_trie.o lru_hash.o bpf_lru_list.o
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
endif
obj-$(CONFIG_CGROUP_BPF) += cgroup.o cgroup_socket.o
obj-$(CONFIG_BPF_SYSCALL) += sk_storage.o
