/*
 * tcpWrapper.cpp
 *
 *  Created on: 19/03/2014
 *      Author: michael
 */

#include "tcp_transport.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <iostream>
#include <string>

namespace zmq {

tcp_transport::tcp_transport() {
	// TODO Auto-generated constructor stub

}

tcp_transport::~tcp_transport() {
	// TODO Auto-generated destructor stub
}

int tcp_transport::tx_socket(int domain, int type, int protocol)
{
	//std::cout << "Using wrapper socket" << std::endl;
	return socket(domain, type, protocol);
}

int tcp_transport::tx_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	//std::cout << "Using wrapper connect" << std::endl;
	return connect(sockfd, addr, addrlen);
}

int tcp_transport::tx_listen(int sockfd, int backlog)
{
	//std::cout << "Using wrapper listen" << std::endl;
	return listen(sockfd, backlog);
}

int tcp_transport::tx_bind(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	//std::cout << "Using wrapper bind" << std::endl;
	return bind(sockfd, addr, addrlen);
}

int tcp_transport::tx_accept(int sockfd, struct sockaddr *addr,
		socklen_t *addrlen)
{
	//std::cout << "Using wrapper accept" << std::endl;
	return accept(sockfd, addr, addrlen);
}

int tcp_transport::tx_send(int sockfd, const void *buf, size_t len, int flags)
{
	//std::cout << "Using wrapper send" << std::endl;
	return send(sockfd, buf, len, flags);
}

int tcp_transport::tx_recv(int sockfd, void *buf, size_t len, int flags)
{
	//std::cout << "Using wrapper recv" << std::endl;
	return recv(sockfd, buf, len, flags);
}

int tcp_transport::tx_close(int fd)
{
	//std::cout << "Using wrapper close" << std::endl;
	return close(fd);
}

int tcp_transport::tx_getsockopt(int sockfd, int level, int optname,
		void *optval, socklen_t *optlen)
{
	//std::cout << "Using wrapper getsockotpt" << std::endl;
	return getsockopt(sockfd, level, optname, optval, optlen);
}

int tcp_transport::tx_setsockopt(int sockfd, int level, int optname,
		const void *optval, socklen_t optlen)
{
	//std::cout << "Using wrapper setsockopt" << std::endl;
	return setsockopt(sockfd, level, optname, optval, optlen);
}

void tcp_transport::tx_set_receive_buffer(int sockfd, int bufsize)
{
	set_tcp_receive_buffer(sockfd, bufsize);
}

void tcp_transport::tx_set_send_buffer(int sockfd, int bufsize)
{
	set_tcp_send_buffer(sockfd, bufsize);
}

void tcp_transport::tx_set_keepalives(int sockfd, int keepalive, int keepalive_cnt,
		int keepalive_idle, int keepalive_intvl)
{
	tune_tcp_keepalives(sockfd, keepalive, keepalive_cnt, keepalive_idle,
			keepalive_intvl);
}

void tcp_transport::tx_tune_socket(int sockfd)
{
	tune_tcp_socket(sockfd);
}

void tcp_transport::tx_unblock_socket(int sockfd)
{
	unblock_socket(sockfd);
}

void tcp_transport::tx_enable_ipv4_mapping(int sockfd)
{
	enable_ipv4_mapping(sockfd);
}

void tcp_transport::tx_get_peer_ip_address(int sockfd, std::string &ip_addr)
{
	get_peer_ip_address(sockfd, ip_addr);
}

void tcp_transport::tx_set_ip_type_of_service(int sockfd, int iptos)
{
	set_ip_type_of_service(sockfd, iptos);
}

transport_options_t *tcp_transport::tx_get_options()
{
	return NULL;
}

void tcp_transport::tx_set_options(int sockd, transport_options_t *option)
{

}

} /* namespace zmq */
