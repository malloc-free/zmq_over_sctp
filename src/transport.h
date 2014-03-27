/*
 * transport.h
 *
 *  Created on: 19/03/2014
 *      Author: michael
 */

#ifndef TRANSPORT_H_
#define TRANSPORT_H_

#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>

namespace zmq {

class Transport {
public:

	virtual ~Transport() {};

	virtual int tx_socket(int domain, int type, int protocol) = 0;

	virtual int tx_connect(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen) = 0;

	virtual int tx_listen(int sockfd, int backlog) = 0;

	virtual int tx_bind(int sockfd, const struct sockaddr *addr,
			socklen_t addrlen) = 0;

	virtual int tx_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = 0;

	virtual int tx_send(int sockfd, const void *buf, size_t len, int flags) = 0 ;

	virtual int tx_recv(int sockfd, void *buf, size_t len, int flags) = 0;

	virtual int tx_close(int fd) = 0;

	virtual int tx_getsockopt(int sockfd, int level, int optname,
			void *optval, socklen_t *optlen) = 0;

	virtual int tx_setsockopt(int sockfd, int level, int optname,
			const void *optval, socklen_t optlen) = 0;

};

} /* namespace zmq */

#endif /* TRANSPORT_H_ */
