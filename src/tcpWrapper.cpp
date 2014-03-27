/*
 * tcpWrapper.cpp
 *
 *  Created on: 19/03/2014
 *      Author: michael
 */

#include "tcpWrapper.h"
#include "err.hpp"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <iostream>

namespace zmq {

Tcp_Wrapper::Tcp_Wrapper() {
	// TODO Auto-generated constructor stub

}

Tcp_Wrapper::~Tcp_Wrapper() {
	// TODO Auto-generated destructor stub
}

int Tcp_Wrapper::tx_socket(int domain, int type, int protocol)
{
	//std::cout << "Using wrapper socket" << std::endl;
	return socket(domain, type, protocol);
}

int Tcp_Wrapper::tx_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	//std::cout << "Using wrapper connect" << std::endl;
	return connect(sockfd, addr, addrlen);
}

int Tcp_Wrapper::tx_listen(int sockfd, int backlog)
{
	//std::cout << "Using wrapper listen" << std::endl;
	return listen(sockfd, backlog);
}

int Tcp_Wrapper::tx_bind(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	//std::cout << "Using wrapper bind" << std::endl;
	return bind(sockfd, addr, addrlen);
}

int Tcp_Wrapper::tx_accept(int sockfd, struct sockaddr *addr,
		socklen_t *addrlen)
{
	//std::cout << "Using wrapper accept" << std::endl;
	return accept(sockfd, addr, addrlen);
}

int Tcp_Wrapper::tx_send(int sockfd, const void *buf, size_t len, int flags)
{
	//std::cout << "Using wrapper send" << std::endl;
	return send(sockfd, buf, len, flags);
}

int Tcp_Wrapper::tx_recv(int sockfd, void *buf, size_t len, int flags)
{
	//std::cout << "Using wrapper recv" << std::endl;
	return recv(sockfd, buf, len, flags);
}

int Tcp_Wrapper::tx_close(int fd)
{
	//std::cout << "Using wrapper close" << std::endl;
	return close(fd);
}

int Tcp_Wrapper::tx_getsockopt(int sockfd, int level, int optname,
		void *optval, socklen_t *optlen)
{
	//std::cout << "Using wrapper getsockotpt" << std::endl;
	return getsockopt(sockfd, level, optname, optval, optlen);
}

int Tcp_Wrapper::tx_setsockopt(int sockfd, int level, int optname,
		const void *optval, socklen_t optlen)
{
	//std::cout << "Using wrapper setsockopt" << std::endl;
	return setsockopt(sockfd, level, optname, optval, optlen);
}

void Tcp_Wrapper::tx_set_receive_buffer(int sockfd, int bufsize)
{

	const int rc = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
			(char*)&bufsize, sizeof bufsize);

	errno_assert(rc == 0);
}

void Tcp_Wrapper::tx_set_send_buffer(int sockfd, int bufsize)
{
	const int rc = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
			(char*)&bufsize, sizeof bufsize);

	errno_assert(rc == 0);
}

void Tcp_Wrapper::tx_set_keepalives(int sockfd, int keepalive, int keepalive_cnt,
		int keepalive_idle, int keepalive_intvl)
{
#ifdef ZMQ_HAVE_SO_KEEPALIVE
	if (keepalive != -1) {
		int rc = setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &keepalive, sizeof (int));
		errno_assert (rc == 0);

#ifdef ZMQ_HAVE_TCP_KEEPCNT
	if (keepalive_cnt != -1) {
		int rc = setsockopt (sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepalive_cnt, sizeof (int));
		errno_assert (rc == 0);
	}
#endif // ZMQ_HAVE_TCP_KEEPCNT

#ifdef ZMQ_HAVE_TCP_KEEPIDLE
	if (keepalive_idle != -1) {
		int rc = setsockopt (sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepalive_idle, sizeof (int));
		errno_assert (rc == 0);
	}
#else // ZMQ_HAVE_TCP_KEEPIDLE
#ifdef ZMQ_HAVE_TCP_KEEPALIVE
	if (keepalive_idle_ != -1) {
		int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPALIVE, &keepalive_idle_, sizeof (int));
		errno_assert (rc == 0);
	}
#endif // ZMQ_HAVE_TCP_KEEPALIVE
#endif // ZMQ_HAVE_TCP_KEEPIDLE

#ifdef ZMQ_HAVE_TCP_KEEPINTVL
	if (keepalive_intvl != -1) {
		int rc = setsockopt (sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof (int));
		errno_assert (rc == 0);
	}
#endif // ZMQ_HAVE_TCP_KEEPINTVL
	}
#endif // ZMQ_HAVE_SO_KEEPALIVE
}

void Tcp_Wrapper::tx_tune_socket(int sockfd)
{
	int nodelay = 1;

	int rc = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay,
			sizeof(int));

	errno_assert(rc == 0);
}

} /* namespace zmq */
