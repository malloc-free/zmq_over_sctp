/*
 * tcpWrapper.cpp
 *
 *  Created on: 19/03/2014
 *      Author: michael
 */

#include "tcpWrapper.h"

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
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

} /* namespace zmq */
