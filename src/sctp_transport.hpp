/*
 * sctp_transport.h
 *
 *  Created on: 27/03/2014
 *      Author: michael
 */

#ifndef SCTP_TRANSPORT_HPP_
#define SCTP_TRANSPORT_HPP_

#include "transport.h"
#include "tcp_address.hpp"
#include "../include/zmq.h"

#include <string>
#include <vector>

namespace zmq {

#define DEFAULT_RTO			2000
#define DEFAULT_HB			5000
#define DEFAULT_MAX_IN		5
#define DEFAULT_MAX_OUT		5
#define DEFAULT_MAX_ATT		2

class sctp_options_t : public zmq::transport_options_t
{
	friend class sctp_wrapper;

public:
	sctp_options_t();

public:
	int setsockopt(const void *optval_, size_t optvallen_);

	int getsockopt(void *optval_, size_t *optvallen_);

	int tx_add_address(char *addr_str);

	int tx_remove_address(char *addr_str);

	int tx_set_rto(int rto);

private:
	int heartbeat_intvl;
	int rto_max;
	int stream_num_out;
	int stream_num_in;
	std::vector<tcp_address_t*> addresses;
};

class sctp_wrapper : public zmq::Transport
{

public:
	sctp_wrapper();
	virtual ~sctp_wrapper();

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

	void tx_set_options(int sockd, transport_options_t *options);

private:
	sctp_options_t *options;

	int tx_set_heartbeat_intvl(int sockfd, int value);

	int tx_set_addresses(int sockfd, std::vector<tcp_address_t*> *addresses);

	int tx_set_rto(int sockfd, int value);

	int tx_set_num_streams(int sockfd, int in, int out);
};

} /* namespace zmq */

#endif /* SCTP_TRANSPORT_HPP_ */
