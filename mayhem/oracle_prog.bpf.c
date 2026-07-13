/* Minimal known-answer BPF program used by mayhem/libbpf_oracle.c.
 * Compiled with clang -target bpf; the oracle opens the resulting object with
 * libbpf and asserts its programs/maps/BTF parse to these exact values.
 * Self-contained (no libc/kernel headers — the bpf target has no libc). */
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

#define BPF_MAP_TYPE_ARRAY 2
#define XDP_PASS 2

struct xdp_md;

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 7);
	__type(key, __u32);
	__type(value, __u64);
} counter_map SEC(".maps");

SEC("xdp")
int oracle_xdp(struct xdp_md *ctx)
{
	__u32 key = 0;
	__u64 *val = bpf_map_lookup_elem(&counter_map, &key);

	if (val)
		__sync_fetch_and_add(val, 1);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
