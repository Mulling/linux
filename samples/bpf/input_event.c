#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"

#include <linux/userio.h>
#include <linux/serio.h>

int main(const int argc, const char **argv)
{
	char filename[256];

	snprintf(filename, sizeof filename, "%s.bpf.o", argv[0]);

	struct bpf_object *obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	int mapfd = bpf_object__find_map_fd_by_name(obj, "queue");

	if (mapfd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

	struct bpf_program *prog;
	struct bpf_link *link;

	bpf_object__for_each_program(prog, obj) {
		link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			link = NULL;
			goto cleanup;
		}
	}

	//int fd = open("/dev/userio", O_RDWR);
	//if (fd < 0) {
	//	fprintf(stderr, "ERROR: fail to open /dev/userio");
	//	return EXIT_FAILURE;
	//}

	while (1) {
		int value = 3;
		if (bpf_map_lookup_and_delete_elem(mapfd, NULL, &value) == 0) {
			fprintf(stdout, "input_event %d\n", value);
		}
	}

cleanup:

	bpf_link__destroy(link);
	bpf_object__close(obj);

	return 0;
}
