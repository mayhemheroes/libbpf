/* AUTHORED behavioral oracle for libbpf (mayhem/test.sh).
 *
 * Upstream libbpf ships NO in-repo runnable test suite: its CI (libbpf-ci /
 * vmtest.yml) boots a VM with a freshly built kernel and runs the KERNEL's
 * selftests/bpf tree — that requires KVM/root and the kernel sources, neither
 * available in the commit image. This oracle is therefore a hand-written
 * known-answer test over libbpf's userspace API (the same ELF/BTF parsing
 * paths the fuzz target exercises): it opens a BPF object built at image-build
 * time from mayhem/oracle_prog.bpf.c and asserts exact parsed values.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libbpf.h"
#include "libbpf_version.h"
#include "btf.h"

static int npass, nfail;

#define CHECK(name, cond) do {                        \
	if (cond) { printf("PASS %s\n", name); npass++; } \
	else      { printf("FAIL %s\n", name); nfail++; } \
} while (0)

static int quiet_print(enum libbpf_print_level level, const char *fmt, va_list args)
{
	return 0;
}

int main(int argc, char **argv)
{
	char verbuf[32];

	if (argc != 2) {
		fprintf(stderr, "usage: %s <oracle_prog.bpf.o>\n", argv[0]);
		return 2;
	}

	libbpf_set_print(quiet_print);

	/* 1-4: string-table known answers */
	snprintf(verbuf, sizeof(verbuf), "v%d.%d", LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION);
	CHECK("version_string", strcmp(libbpf_version_string(), verbuf) == 0);
	CHECK("prog_type_str_xdp", strcmp(libbpf_bpf_prog_type_str(BPF_PROG_TYPE_XDP), "xdp") == 0);
	CHECK("map_type_str_array", strcmp(libbpf_bpf_map_type_str(BPF_MAP_TYPE_ARRAY), "array") == 0);
	CHECK("attach_type_str_ingress",
	      strcmp(libbpf_bpf_attach_type_str(BPF_CGROUP_INET_INGRESS), "cgroup_inet_ingress") == 0);

	/* 5-14: parse a known BPF ELF object from file */
	struct bpf_object *obj = bpf_object__open(argv[1]);
	CHECK("open_file", obj != NULL);
	if (obj) {
		struct bpf_program *prog = bpf_object__find_program_by_name(obj, "oracle_xdp");
		CHECK("prog_found", prog != NULL);
		CHECK("prog_section", prog && strcmp(bpf_program__section_name(prog), "xdp") == 0);
		CHECK("prog_type", prog && bpf_program__type(prog) == BPF_PROG_TYPE_XDP);
		CHECK("prog_insn_cnt", prog && bpf_program__insn_cnt(prog) > 0);

		struct bpf_map *map = bpf_object__find_map_by_name(obj, "counter_map");
		CHECK("map_found", map != NULL);
		CHECK("map_type", map && bpf_map__type(map) == BPF_MAP_TYPE_ARRAY);
		CHECK("map_max_entries", map && bpf_map__max_entries(map) == 7);
		CHECK("map_key_size", map && bpf_map__key_size(map) == 4);
		CHECK("map_value_size", map && bpf_map__value_size(map) == 8);
		CHECK("btf_present", bpf_object__btf(obj) != NULL);
		bpf_object__close(obj);
	} else {
		nfail += 11;
		printf("FAIL open_file_dependents (11 checks skipped as failed)\n");
	}

	/* 16-17: same object through bpf_object__open_mem */
	FILE *f = fopen(argv[1], "rb");
	long len = 0;
	char *buf = NULL;
	if (f) {
		fseek(f, 0, SEEK_END);
		len = ftell(f);
		fseek(f, 0, SEEK_SET);
		buf = malloc(len);
		if (buf && fread(buf, 1, len, f) != (size_t)len) { free(buf); buf = NULL; }
		fclose(f);
	}
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts, .object_name = "oracle-mem");
	struct bpf_object *memobj = buf ? bpf_object__open_mem(buf, len, &opts) : NULL;
	CHECK("open_mem_valid", memobj != NULL);
	CHECK("open_mem_name", memobj && strcmp(bpf_object__name(memobj), "oracle-mem") == 0);
	if (memobj)
		bpf_object__close(memobj);
	free(buf);

	/* 18: garbage must be rejected */
	static const char garbage[] = "this is definitely not a valid ELF/BPF object 0123456789";
	struct bpf_object *bad = bpf_object__open_mem(garbage, sizeof(garbage), NULL);
	CHECK("open_mem_garbage_rejected", bad == NULL);
	if (bad)
		bpf_object__close(bad);

	printf("ORACLE TOTAL %d PASS %d FAIL %d\n", npass + nfail, npass, nfail);
	return nfail ? 1 : 0;
}
