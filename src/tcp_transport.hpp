/*
 * tcp_transport.hpp
 *
 *  Created on: 19/03/2014
 *      Author: Michael Holmwood
 */

#ifndef TCP_TRANSPORT_HPP_
#define TCP_TRANSPORT_HPP_

#include "transport.hpp"

#include <string>
#include <sys/socket.h>

namespace zmq {

class tcp_transport : public transport
{

public:
	tcp_transport();

	virtual ~tcp_transport();

	int tx_socket(int domain, int type, int protocol);

	int tx_connect(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen);

	int tx_listen(int sockfd, int backlog);

	int tx_bind(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen);

	int tx_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

	int tx_send(int sockfd, const void *buf, size_t len, int flags);

	int tx_recv(int sockfd, void *buf, size_t len, int flags);

	int tx_close(int fd);

	int tx_getsockopt(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen);

	int tx_setsockopt(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen);

	void tx_set_receive_buffer(int sockfd, int bufsize);

	void tx_set_send_buffer(int sockfd, int bufsize);

	void tx_set_keepalives(int sockfd, int keepalive, int keepalive_cnt,
			int keepalive_idle, int keepalive_intv);

	void tx_tune_socket(int sockfd);

	void tx_unblock_socket(int sockfd);

	void tx_enable_ipv4_mapping(int sockfd);

	void tx_get_peer_ip_address(int sockfd, std::string &ip_addr);

	void tx_set_ip_type_of_service(int sockfd, int iptos);

	transport_options_t *tx_get_options();

	void tx_set_options(int sockd, transport_options_t *option);
};

} /* namespace zmq */

#endif /* TCP_TRANSPORT_HPP_ */
