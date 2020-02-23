
/*
 * Copyright (c) 2018, 2019 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <time.h>

#include "/sys/dev/acct.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#define DEV_ACCT "/dev/acct"

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-v] [/dev/acct]\n", __progname);
	exit(1);
}

static uint8_t buffer[65536];
static int verbose = 0;

static void handle_fork(void *msg);
static void handle_exec(void *msg);
static void handle_exit(void *msg);

struct acct_msg_type {
	const char *name;
	unsigned short len;
	void (*print)(void *);
};

static const struct acct_msg_type acct_msg_types[] = {
	[ACCT_MSG_FORK] = { "fork", sizeof(struct acct_fork), handle_fork },
	[ACCT_MSG_EXEC] = { "exec", sizeof(struct acct_exec), handle_exec },
	[ACCT_MSG_EXIT] = { "exit", sizeof(struct acct_exit), handle_exit },
};

void
print_etime(const struct acct_common *comm)
{
	printf(" at +%lld", comm->ac_etime.tv_sec);
	if (verbose > 1)
		printf(".%09ld", comm->ac_etime.tv_nsec);
}

static void
handle_fork(void *msg)
{
	struct acct_fork *fork = msg;
	struct acct_common *comm = &fork->ac_common;

	printf("fork: %5d (%s) forked %5d", comm->ac_pid, comm->ac_comm,
	    fork->ac_cpid);
	if (verbose)
		print_etime(comm);
	printf("\n");
}

static void
handle_exec(void *msg)
{
	struct acct_exec *exec = msg;
	struct acct_common *comm = &exec->ac_common;

	printf("exec: %5d (%s)", comm->ac_pid, comm->ac_comm);
	if (verbose)
		print_etime(comm);
	printf("\n");
}

static void
handle_exit(void *msg)
{
	struct acct_exit *exit = msg;
	struct acct_common *comm = &exit->ac_common;

	printf("exit: %5d (%s)", comm->ac_pid, comm->ac_comm);
	if (verbose)
		print_etime(comm);
	printf("\n");
}

static void
acct_read(int fd, unsigned int *seqp)
{
	ssize_t rv;
	struct acct_common *comm;
	const struct acct_msg_type *type;
	unsigned int seq;

	rv = read(fd, buffer, sizeof(buffer));
	switch (rv) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			warn("read");
			return;
		default:
			break;
		}
		err(1, "read");
		/* NOTREACHED */
	default:
		break;
	}

	if (rv < sizeof(*comm))
		errx(1, "short read: %zu < %zu", rv, sizeof(*comm));

	comm = (struct acct_common *)buffer;
	if (comm->ac_len != rv)
		errx(1, "inconsistent len: %zd < %u", rv, comm->ac_len);
	if (comm->ac_type >= nitems(acct_msg_types))
		errx(1, "invalid type: %u\n", comm->ac_type);

	type = &acct_msg_types[comm->ac_type];
	if (comm->ac_len < type->len) {
		errx(1, "short %s message: %u < %u", type->name, comm->ac_len,
		    type->len);
	}

	seq = *seqp;
	if (seq != comm->ac_seq) {
		warnx("%s message: unexpected seq number %u != %u", type->name,
		    comm->ac_seq, seq);
	}
	*seqp = comm->ac_seq + 1;

	(*type->print)(comm);
}

int
main(int argc, char *argv[])
{
	const char *dev_acct = DEV_ACCT;
	int fd;
	unsigned int seq = 0;

	int ch;

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		dev_acct = argv[0];
		/* FALLTHROUGH */
	case 0:
		break;
	default:
		usage();
	}

	fd = open(dev_acct, O_RDONLY);
	if (fd == -1)
		err(1, "%s", dev_acct);

	for (;;) {
		acct_read(fd, &seq);
	}

	return (0);
}
