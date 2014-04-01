/*
 * sctpwrapper.cpp
 *
 *  Created on: 27/03/2014
 *      Author: michael
 */

#include "sctpwrapper.h"
#include "ip.hpp"
#include "tcp.hpp"
#include "err.hpp"
#include "netinet/sctp.h"

#include <string>
#include <iostream>

namespace zmq {

sctp_wrapper::sctp_wrapper() {
	// TODO Auto-generated constructor stub

}

sctp_wrapper::~sctp_wrapper() {
	// TODO Auto-generated destructor stub
}

int sctp_wrapper::tx_socket(int domain, int type, int protocol)
{
	std::cout << "Using sctp socket" << std::endl;
	return socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
}

int sctp_wrapper::tx_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	std::cout << "Using sctp connect" << std::endl;
	return connect(sockfd, addr, addrlen);
}

int sctp_wrapper::tx_listen(int sockfd, int backlog)
{
	std::cout << "Using sctp listen" << std::endl;
	return listen(sockfd, backlog);
}

int sctp_wrapper::tx_bind(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	std::cout << "Using sctp bind" << std::endl;
	return bind(sockfd, addr, addrlen);
}

int sctp_wrapper::tx_accept(int sockfd, struct sockaddr *addr,
		socklen_t *addrlen)
{
	std::cout << "Using sctp accept" << std::endl;
	return accept(sockfd, addr, addrlen);
}

int sctp_wrapper::tx_send(int sockfd, const void *buf, size_t len, int flags)
{
	std::cout << "Using sctp send" << std::endl;
	return send(sockfd, buf, len, flags);
}

int sctp_wrapper::tx_recv(int sockfd, void *buf, size_t len, int flags)
{
	std::cout << "Using sctp recv" << std::endl;
	return recv(sockfd, buf, len, flags);
}

int sctp_wrapper::tx_close(int fd)
{
	std::cout << "Using sctp close" << std::endl;
	return close(fd);
}

int sctp_wrapper::tx_getsockopt(int sockfd, int level, int optname,
		void *optval, socklen_t *optlen)
{
	std::cout << "Using sctp getsockotpt" << std::endl;
	return getsockopt(sockfd, level, optname, optval, optlen);
}

int sctp_wrapper::tx_setsockopt(int sockfd, int level, int optname,
		const void *optval, socklen_t optlen)
{
	std::cout << "Using sctp setsockopt" << std::endl;
	return setsockopt(sockfd, level, optname, optval, optlen);
}

void sctp_wrapper::tx_set_receive_buffer(int sockfd, int bufsize)
{
	std::cout << "Using sctp set_receive_buffer" << std::endl;
	set_tcp_receive_buffer(sockfd, bufsize);
}

void sctp_wrapper::tx_set_send_buffer(int sockfd, int bufsize)
{
	std::cout << "Using sctp set_send_buffer" << std::endl;
	set_tcp_send_buffer(sockfd, bufsize);
}

void sctp_wrapper::tx_set_keepalives(int sockfd, int keepalive, int keepalive_cnt,
		int keepalive_idle, int keepalive_intv)
{

#ifdef ZMQ_HAVE_SO_KEEPALIVE
	std::cout << "Using sctp set_keepalives" << std::endl;
    if (keepalive != -1)
    {
        int rc = setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &keepalive, sizeof (int));
        errno_assert (rc == 0);
    }
#endif

}

void sctp_wrapper::tx_tune_socket(int sockfd)
{
	std::cout << "Using sctp tune_socket" << std::endl;
	int nodelay = 1;
	int rc = setsockopt(sockfd, IPPROTO_SCTP, SCTP_NODELAY, (char*) &nodelay,
			sizeof(int));

	errno_assert(rc == 0);
}

void sctp_wrapper::tx_unblock_socket(int sockfd)
{
	std::cout << "Using sctp ublock socket" << std::endl;
	unblock_socket(sockfd);
}

void sctp_wrapper::tx_enable_ipv4_mapping(int sockfd)
{
	std::cout << "Using sctp enable_ipv4_mapping" << std::endl;
	enable_ipv4_mapping(sockfd);
}

void sctp_wrapper::tx_get_peer_ip_address(int sockfd, std::string &ip_addr)
{
	std::cout << "Using get_peer_ip_address" << std::endl;
	get_peer_ip_address(sockfd, ip_addr);
}

void sctp_wrapper::tx_set_ip_type_of_service(int sockfd, int iptos)
{
	std::cout << "Using set_ip_type_of_service" << std::endl;
	set_ip_type_of_service(sockfd, iptos);
}

} /* namespace zmq */
