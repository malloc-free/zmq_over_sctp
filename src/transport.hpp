/*
 * transport.hpp
 *
 *  Created on: 19/03/2014
 *      Author: Michael Holmwood
 *
 *      The purpose of this interface is to provide general access to
 *      the network functionality of a protocol, maintaining the same
 *      API as Berkley Sockets.
 */

#ifndef TRANSPORT_HPP_
#define TRANSPORT_HPP_

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string>
#include <../include/zmq.h>

namespace zmq
{

//Passed into setSockOpt to set the specified option


class transport_options_t
{
public:
	virtual ~transport_options_t (){};

	virtual int setsockopt(const void *optval_, size_t optvallen_) = 0;

	virtual int getsockopt(void *optval_, size_t *optvallen_) = 0;
};

/**
 * Interface for transport protocols.
 */
class transport
{
public:

	virtual ~transport() {};

	virtual int tx_socket(int domain, int type, int protocol) = 0;

	virtual int tx_connect(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen) = 0;

	virtual int tx_listen(int sockfd, int backlog) = 0;

	virtual int tx_bind(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen) = 0;

	virtual int tx_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = 0;

	virtual int tx_send(int sockfd, const void *buf, size_t len, int flags) = 0;

	virtual int tx_recv(int sockfd, void *buf, size_t len, int flags) = 0;

	virtual int tx_close(int fd) = 0;

	virtual int tx_getsockopt(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen) = 0;

	virtual int tx_setsockopt(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen) = 0;

	virtual void tx_set_receive_buffer(int sockfd, int bufsize) = 0;

	virtual void tx_set_send_buffer(int sockfd, int bufsize) = 0;

	virtual void tx_set_keepalives(int sockfd, int keepalive,
			int keepalive_cnt, int keepalive_idle, int keepalive_intv) = 0;

	virtual void tx_tune_socket(int sockfd) = 0;

	virtual void tx_unblock_socket(int sockfd) = 0;

	virtual void tx_enable_ipv4_mapping(int sockfd) = 0;

	virtual void tx_get_peer_ip_address(int sockfd, std::string &ip_addr_) = 0;

	virtual void tx_set_ip_type_of_service(int sockfd, int iptos) = 0;

	virtual transport_options_t *tx_get_options() = 0;

	virtual void tx_set_options(int sockd, transport_options_t *options) = 0;
};

} /* namespace zmq */

#endif /* TRANSPORT_HPP_ */
