#define LISTEN_PORT 31337
#define BUFLEN 0x100000

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdint.h>


static int backd_errno;
#define SYS_ERRNO backd_errno
#include "linux_syscall_support.h"

// these aren't in LSS, for whatever reason
LSS_INLINE _syscall5(int, setsockopt, int, sockfd, int, level, int, optname, const void*, optval, socklen_t, optlen)
LSS_INLINE _syscall3(int, bind, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)
LSS_INLINE _syscall2(int, listen, int, sockfd, int, backlog)
LSS_INLINE _syscall3(int, accept, int, sockfd, struct sockaddr *, addr, socklen_t *, addrlen)
LSS_INLINE _syscall3(int, connect, int, sockfd, const struct sockaddr *, addr, socklen_t, addrlen)

static unsigned char buffer[BUFLEN];

struct request {
	uint16_t cmd_id;
	uint16_t hdr_len;
	uint32_t body_len;
};

struct server_hello {
	uint32_t hello_len;
	uint32_t buf_len;
	uint64_t buf_addr;
};

// aarch64-specific...
uint64_t do_syscall(int sysno, uint64_t args[6])
{
	LSS_REG(0, args[0]);
	LSS_REG(1, args[1]);
	LSS_REG(2, args[2]);
	LSS_REG(3, args[3]);
	LSS_REG(4, args[4]);
	LSS_REG(5, args[5]);
	register int64_t __res_x0 __asm__("x0");
	register int64_t nr_x8 __asm__("x8");
	int64_t __res;
	nr_x8 = sysno;
	__asm__ __volatile__ (
		"svc 0x0\n"
		: "=r"(__res_x0)
		: "r"(nr_x8), "r"(__r0), "r"(__r1), "r"(__r2), "r"(__r3), "r"(__r4), "r"(__r5)
		: "memory"
	);
	__res = __res_x0;
	return __res;
}

size_t recvn(int s, void* buf, size_t len)
{
	size_t received = 0;
	while (received < len) {
		ssize_t res = sys_read(s, buf + received, len - received);
		if (res < 1) {
			break;
		}
		received += res;
	}
	return received;
}

void _start(void)
{
	int s = sys_socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	sys_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	sys_setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port = htons(LISTEN_PORT),
		.sin_addr.s_addr = htonl(INADDR_ANY)
	};

	sys_bind(s, (void*)&sin, sizeof(sin));
	sys_listen(s, 10);

	while (1) {
		int client = sys_accept(s, NULL, NULL);
		if (client < 0) {
			break;
		}
		int child = sys_fork();
		if (child < 0) {
			break;
		}
		if (child > 0) {
			continue;
		}
		// handle client
		struct server_hello hi = {
			.hello_len = 12,
			.buf_addr = (uintptr_t)buffer,
			.buf_len = sizeof(buffer)
		};
		sys_write(client, &hi, sizeof(hi));

		while (1) {
			int32_t reslen;
			struct request req;
			if(recvn(client, &req, sizeof(req)) != sizeof(req)) {
				break;
			}
			switch (req.cmd_id)
			{
			case 0: // write_mem
				void *write_addr; // TODO check request length
				recvn(client, &write_addr, sizeof(write_addr));
				recvn(client, write_addr, req.body_len);
				reslen = 0;
				sys_write(client, &reslen, sizeof(reslen));
				break;
			case 1: // read_mem
				void *read_addr; // TODO check request length
				uint32_t read_len;
				recvn(client, &read_addr, sizeof(read_addr));
				recvn(client, &read_len, sizeof(read_len));
				sys_sendto(client, (void*)&read_len, sizeof(read_len), MSG_MORE, NULL, 0);
				sys_write(client, read_addr, read_len);
				break;
			case 2: // syscall
				int16_t sysno; // TODO check request lengths
				u_int64_t sysargs[6];
				recvn(client, &sysno, sizeof(sysno));
				recvn(client, sysargs, req.hdr_len - 2);
				uint64_t sysres = do_syscall(sysno, sysargs);
				reslen = sizeof(sysres);
				sys_sendto(client, (void*)&reslen, sizeof(reslen), MSG_MORE, NULL, 0);
				sys_write(client, &sysres, sizeof(sysres));
				break;

			default: // error
				// TODO: still consume request header/body in error state
				reslen = -1;
				sys_write(client, &reslen, sizeof(reslen));
				break;
			}
		}
		sys__exit(0);
	}

	// we only get here if something bad happens
	sys__exit(-1);
}
