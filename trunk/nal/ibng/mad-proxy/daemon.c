/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the version 2 of the GNU General Public License
 *   as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/* Copyright 2008-2011 NEC Deutschland GmbH, NEC HPC Europe */

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>

#include <p3utils.h>
#include <portals3.h>

#include <map-types.h>
#include <dbg.h>
#include "netmap.h"

#define MAX_CONNECTION_QUEUE_SIZE 5
#define NUM_LID_GID_MAPS USHRT_MAX

static int mad_proxy_live = 0;
static int worker_thread_live = 0;

unsigned int ibng_debug_level = PTL_DBG_NI_ALL;

#define CACHE_UPDATE_DEF 600
#define CACHE_UPDATE_MIN 10
int daemonize = 1; /* run as daemon is default */
int cache_update_tm = CACHE_UPDATE_DEF;

pthread_mutex_t cached_lid_gid_maps_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mappings_create_mutex = PTHREAD_MUTEX_INITIALIZER;
uint64_t *cached_lid_gid_maps = NULL;

static inline void
madplog(int level, const char *format, ...)
{
	va_list arglist;
	va_start(arglist, format);

	if (daemonize)
		vsyslog(level, format, arglist);
	else
		vfprintf(stderr, format, arglist);

	va_end(arglist);
}

static inline bool
receive_string(int socket_fd, char *str, int max_size)
{
	uint32_t str_len;

	if (read(socket_fd, &str_len, sizeof(str_len)) < 0)
		return false;
	if (str_len > max_size)
		return false;
	if (read(socket_fd, str, str_len) < 0)
		return false;
	str[str_len] = '\0';

	return true;
}

static uint64_t *
get_cached_lid_gid_mappings()
{
	const int SLEEP_SECONDS = 2;
	uint64_t * lid_gid_maps;

	/* if the cached mappings don't exist (the
	 * "mad_proxy_lid_gid_mappings_create" function needs some time
	 * to finish executing), wait until they appear.*/
	while (cached_lid_gid_maps == NULL)
		sleep(SLEEP_SECONDS);

	pthread_mutex_lock(&cached_lid_gid_maps_mutex);

	lid_gid_maps = calloc(NUM_LID_GID_MAPS, sizeof(uint64_t));
	if (lid_gid_maps)
		memcpy(lid_gid_maps, cached_lid_gid_maps,
		       NUM_LID_GID_MAPS * sizeof(uint64_t));

	pthread_mutex_unlock(&cached_lid_gid_maps_mutex);

	return lid_gid_maps;
}

static bool
handle_op_lid_gid_mappings_get(int connection_fd)
{
	int i;
	uint64_t *lid_gid_maps;
	int mapping_len;
	uint32_t all_mappings_len;

	const int BUFFER_SIZE = 256;
	char buffer[BUFFER_SIZE + 1];

	char dev_name[BUFFER_SIZE + 1];
	int32_t dev_port;

	char *serialized_mappings;
	char *curr_pos;

	ssize_t num_written, num_left;

	if (!receive_string(connection_fd, buffer, BUFFER_SIZE))
		return false;

	sscanf(buffer, "%d:%s", &dev_port, dev_name);
	if (strcmp(dev_name, "NULL") == 0 && dev_port == 0) {
		/* use the cached mappings. */
		lid_gid_maps = get_cached_lid_gid_mappings();
	} else {
		pthread_mutex_lock(&mappings_create_mutex);
		lid_gid_maps = mad_proxy_lid_gid_mappings_create(NULL, dev_port,
														 NUM_LID_GID_MAPS);
		pthread_mutex_unlock(&mappings_create_mutex);
	}

	if (!lid_gid_maps) {
		madplog(LOG_WARNING, "Failed to create LID <-> GID mapping for "
				"device %s, port %d.", dev_name, dev_port);
		return false;
	}

	/* serialize the LID->GID mappings. */

	/* first, calculate the buffer size. */
	all_mappings_len = NUM_LID_GID_MAPS * (4 /* lid */ + 16 /* gid */ + 1 + 1);

	/* create a buffer for max size of mappings serialization. */
	serialized_mappings = calloc(all_mappings_len, sizeof(char));
	if (!serialized_mappings) {
		free(lid_gid_maps);
		return false;
	}

	/* serialize the mappings into the buffer. */
	curr_pos = serialized_mappings;
	for (i = 0; i < NUM_LID_GID_MAPS; i++)
		if (lid_gid_maps[i] != 0) {
			mapping_len = snprintf(curr_pos, 4 + 1 + 16 + 1 + 1,
								   "%04x:%016llx;",
								   i, lid_gid_maps[i]);
			curr_pos += mapping_len;
		}

	/* compute real size of the response */
	all_mappings_len = curr_pos - serialized_mappings + 1;
	/*remove the last ';' separator. */
	*(curr_pos - 1) = '\0';

	free(lid_gid_maps);

	if (write(connection_fd, &all_mappings_len,
			  sizeof(all_mappings_len)) < 0) {
		free(lid_gid_maps);
		return false;
	}

	num_left = all_mappings_len;
	curr_pos = serialized_mappings;
	while (num_left > 0) {
		num_written = write(connection_fd, curr_pos,
							all_mappings_len);
		if (num_written < 0) {
			free(serialized_mappings);
			return false;
		}
		num_left -= num_written;
		curr_pos += num_written;
	}

	free(serialized_mappings);

	return true;
}

static bool
connection_handler(int connection_fd) {
	const int BUFFER_SIZE = 64;
	char cmd_op[BUFFER_SIZE + 1];

	uint32_t read_len;
	ssize_t bytes_read;

	bytes_read = read(connection_fd, &read_len, sizeof(read_len));
	if (bytes_read < 0)
		return false;
	else if (bytes_read == 0)
		return false;

	if (read_len > BUFFER_SIZE) {
		madplog(LOG_WARNING, "Received too long command: %d\n", read_len);
		return false;
	}

	if ((bytes_read = read(connection_fd, cmd_op, read_len)) <= 0)
		return false;

	cmd_op[bytes_read] = '\0';
	if (strncmp(cmd_op, NETMAP_OP_LID_GID_MAPPINGS_GET,
				strlen(NETMAP_OP_LID_GID_MAPPINGS_GET)) == 0)
		return handle_op_lid_gid_mappings_get(connection_fd);
	else {
		madplog(LOG_WARNING, "Unrecognized command '%s'.", cmd_op);
		return false;
	}
}

static inline bool
dir_exists(char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

static inline bool
dir_create(char *path)
{
	return mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) == 0;
}

static bool
server_domain_socket_create(char *domain_socket_path,
			    int *socket_fd, struct sockaddr_un *address)
{
	*socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (*socket_fd < 0)
		return false;

	unlink(domain_socket_path);
	address->sun_family = AF_UNIX;
	strncpy(address->sun_path, domain_socket_path, sizeof(address->sun_path));

	if (bind(*socket_fd, (struct sockaddr *) address, sizeof(*address)) != 0)
		return false;

	if (chmod(domain_socket_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
			  S_IROTH | S_IWOTH))
		return false;

	if (listen(*socket_fd, MAX_CONNECTION_QUEUE_SIZE) != 0)
		return false;

	return true;
}

static void *
update_cached_lid_gid_mappings(void *threadid)
{
	uint64_t *lid_gid_maps;
	/* do the cache update every 10 minutes. */

	struct timespec sleep_time, remaining_time;

	worker_thread_live = 1;
	while (worker_thread_live) {
		madplog(LOG_INFO, "Performing lid->gid mappings update.\n");

		pthread_mutex_lock(&mappings_create_mutex);
		lid_gid_maps = mad_proxy_lid_gid_mappings_create(NULL, 0,
														 NUM_LID_GID_MAPS);
		pthread_mutex_unlock(&mappings_create_mutex);

		pthread_mutex_lock(&cached_lid_gid_maps_mutex);
		if (cached_lid_gid_maps)
			free(cached_lid_gid_maps);

		cached_lid_gid_maps = lid_gid_maps;
		pthread_mutex_unlock(&cached_lid_gid_maps_mutex);

		sleep_time.tv_nsec = 0;
		sleep_time.tv_sec = cache_update_tm;

		/* wait for the specified period before the next updating is
		 * initiated.*/
		while (nanosleep(&sleep_time, &remaining_time) != 0) {
			if (errno == EINTR) {
				/* if the nanosleep was interrupted by a signal
				 * handler, sleep for the remaining duration. */
				sleep_time = remaining_time;
			} else {
				madplog(LOG_ERR, "nanosleep failed: errno=%d.\n", errno);
				worker_thread_live = 0;
				break;
			}
		}

	}
	pthread_exit(NULL);
}

static int
mad_proxy(void) {
	struct sockaddr_un address;
	socklen_t address_length;
	int socket_fd, connection_fd, live = 1;

	const int BUFFER_SIZE = 256;
	char domain_socket_path[BUFFER_SIZE];

	int max_socket_fd = 0;
	int fd;
	fd_set set, read_set;

	int rc;
	pthread_t worker_thread;

	/* create the subdirectory in "/var/run" for the daemon. */
	if (!dir_exists(NETMAP_VAR_RUN_DIR) && !dir_create(NETMAP_VAR_RUN_DIR)) {
		madplog(LOG_ERR, "Cannot create directory \"%s\".", NETMAP_VAR_RUN_DIR);
		return -1;
	}

	snprintf(domain_socket_path, BUFFER_SIZE, "%s/%s", NETMAP_VAR_RUN_DIR,
			 NETMAP_SERVER_SOCKET_FILENAME);

	if (!server_domain_socket_create(domain_socket_path, &socket_fd,
									 &address)) {
		madplog(LOG_ERR, "Failed to create server socket.");
		return -1;
	}

	rc = pthread_create(&worker_thread, NULL, update_cached_lid_gid_mappings,
						NULL);
	if (rc) {
		madplog(LOG_ERR, "Failed to create worker thread: %d\n", rc);
		return -1;
	}

	if (socket_fd > max_socket_fd)
		max_socket_fd = socket_fd;
	FD_ZERO(&set);
	FD_SET(socket_fd, &set);

	mad_proxy_live = 1;
	while (mad_proxy_live) {
		read_set = set;
		if (select(max_socket_fd + 1, &read_set, NULL, NULL, NULL) < 0) {
			if (EINTR == errno) {
				madplog(LOG_WARNING, "Failed to select.");
				break;
			}
		}

		/* check if the server socket received new connection. */
		if (FD_ISSET(socket_fd, &read_set)) {
			if ((connection_fd = accept(socket_fd, NULL, 0)) < 0) {
				madplog(LOG_WARNING, "Failed to accept a connection.");
				continue;
			}
			FD_SET(connection_fd, &set);
			if (connection_fd > max_socket_fd)
				max_socket_fd = connection_fd;
		}

		/* check also the client sockets. */
		for (fd = 0; fd <= max_socket_fd; fd++)
			if (fd != socket_fd && FD_ISSET(fd, &read_set))
				/* handle the client request. */
				if (!connection_handler(fd)) {
					FD_CLR(fd, &set);
					if (fd == max_socket_fd)
						max_socket_fd--;
					close(fd);
				}
	}

	/* close all the client sockets */
	for (fd = 0; fd <= max_socket_fd; fd++) {
		if (fd != socket_fd && FD_ISSET(fd, &set))
			close(fd);
	}

	close(socket_fd);
	unlink(domain_socket_path);

	return 0;
}

static void
signal_handler(int signo)
{
	switch(signo) {
	case SIGHUP:
		/* we could reload config here, but currently, we have none */
		break;
	case SIGTERM:
		/* signal will also interrupt a select */
		mad_proxy_live = 0;
		worker_thread_live = 0;
		break;
	}
}

int
main(int argc, char **argv)
{
	int rv, opt;
	int i, fd;

	while ((opt = getopt(argc, argv, "hft:")) != -1) {
		switch (opt) {
		case 'f':
			daemonize = 0;
			break;
		case 't':
			cache_update_tm = atoi(optarg);
			if (cache_update_tm < CACHE_UPDATE_MIN)
				cache_update_tm = CACHE_UPDATE_DEF;

			madplog(LOG_INFO, "Cache update interval set to %d s.\n",
					cache_update_tm);
			break;
		case 'h':
		default:
			fprintf(stderr, "Usage: %s [-hf]\n", argv[0]);
			fprintf(stderr, "-h\tthis blurb\n");
			fprintf(stderr, "-f\trun in foreground\n");
			fprintf(stderr, "-t <val>\tcache update interval"
					" (default 600 s)\n");
			return EXIT_FAILURE;
		}
	}

	p3utils_init();

	if (daemonize) {
		rv = fork();
		if (rv == -1)
			exit(42);
		else if (rv > 0) {
			/* parent: exit */
			_exit(0);
		}

		if (setsid() < 0) {
			exit(42);
		}

		rv = fork();
		if (rv < 0)
			exit(42);
		else if (rv > 0) {
			/* intermediate process: exit */
			_exit(0);
		}

		/* actual daemon process */
		chdir("/");
		umask(0);

		/* close all open fds */
		for (i = getdtablesize(); i >= 0; --i)
			close(i);

		/* redirect std fds to/from /dev/null */
		for (i = 0; i <= 2; i++) {
			fd = open("/dev/null", (i == 0) ? O_RDONLY : O_WRONLY);
			if (fd != i) {
				dup2(fd, i);
				close(fd);
			}
		}
		signal(SIGCHLD, SIG_IGN); /* ignore child */
		signal(SIGTSTP, SIG_IGN); /* ignore tty signals */
		signal(SIGTTOU, SIG_IGN);
		signal(SIGTTIN, SIG_IGN);
		signal(SIGHUP, signal_handler); /* catch hangup signal */
		signal(SIGTERM, signal_handler); /* catch kill signal */

		openlog("ibng-mad-proxy", LOG_PID, LOG_DAEMON);
	}

	madplog(LOG_INFO, "Daemon initialized.");
	mad_proxy();
	madplog(LOG_INFO, "Daemon terminating.");

	if (daemonize)
		closelog();

	return 0;
}
