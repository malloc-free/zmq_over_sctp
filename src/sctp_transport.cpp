/*
 * sctp_transport.cpp
 *
 *  Created on: 27/03/2014
 *      Author: Michael Holmwood
 */

#include "sctp_transport.hpp"
#include "transport.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "err.hpp"
#include "netinet/sctp.h"
#include "sys/socket.h"
#include "../include/zmq.h"

#include <errno.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <assert.h>

namespace zmq {

///////////////////// sctp_options_t member functions ////////////////////

sctp_options_t::sctp_options_t() :
		heartbeat_intvl(-1),
		rto_max(-1),
		stream_num_out(DEFAULT_MAX_OUT),
		stream_num_in(DEFAULT_MAX_IN)
{
}

int sctp_options_t::setsockopt(const void *optval_, size_t optvallen_)
{
	t_option_t *t_opt = (t_option_t*)optval_;

	if(!(t_opt->optval_)) {
		return -1;
	}

	bool is_int = (optvallen_ == sizeof(int));
	int value;

	switch(t_opt->option_)
	{
	case ZMQ_SCTP_HB_INTVL :

		value = *((int*)t_opt->optval_);

		if(value > 0 && is_int) {
			heartbeat_intvl = *((int*)t_opt->optval_);
			return 0;
		}

		break;

	case ZMQ_SCTP_ADD_IP :
		return tx_add_address((char*)t_opt->optval_);

	case ZMQ_SCTP_RTO :

		value = *((int*)t_opt->optval_);

		if(value > 0 && is_int) {
			rto_max = *((int*)t_opt->optval_);
			return 0;
		}

		break;

	case ZMQ_SCTP_MAX_IN :
		stream_num_in = *((int*)t_opt->optval_);
		return 0;

	case ZMQ_SCTP_MAX_OUT :
		stream_num_out = *((int*)t_opt->optval_);
		return 0;

	default : break;

	}

	return -1;
}

int sctp_options_t::getsockopt(void *optval_, size_t *optvallen_)
{
	std::cout << "Getting sctp options" << std::endl;

	t_option_t *t_opt = (t_option_t*)optval_;

	switch(t_opt->option_)
		{
		case ZMQ_SCTP_HB_INTVL :
			*((int*)t_opt->optval_) = heartbeat_intvl;
			std::cout << "setting sctp heartbeat value: " << *((int*)t_opt->optval_)
					<< std::endl;
			return 0;

		case ZMQ_SCTP_ADD_IP :
			return -1;

		case ZMQ_SCTP_RTO :
			std::cout << "Getting sctp rto value: " << *((int*)t_opt->optval_)
				<< std::endl;
			*((int*)t_opt->optval_) = rto_max;

			return 0;

		case ZMQ_SCTP_MAX_IN :
			*((int*)t_opt->optval_) = stream_num_in;
			return 0;

		case ZMQ_SCTP_MAX_OUT :
			*((int*)t_opt->optval_) = stream_num_out;
			return 0;

		default : break;

		}

		return -1;
}

int sctp_options_t::tx_add_address(char *addr_str)
{
	tcp_address_t *addr = new tcp_address_t();

	int rc = addr->resolve(addr_str, true, false);

	if(rc != 0) {
		delete(addr);
		return rc;
	}

	addresses.push_back(addr);

	return 0;
}

int sctp_options_t::tx_remove_address(char *addr_str)
{
	return 0;
}

int sctp_options_t::tx_set_rto(int rto)
{
	return 0;
}

////////////////// sctp_wrapper member functions ////////////////////////

sctp_transport::sctp_transport() :
	options()
{
	options = new sctp_options_t;
}

sctp_transport::~sctp_transport()
{
	delete(options);
}

int sctp_transport::tx_socket(int domain, int type, int protocol)
{
	int rc;
	std::cout << "Using sctp socket" << std::endl;
	rc =  socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);

	P_N_ERR(rc, "tx_socket");

	return rc;
}

int sctp_transport::tx_connect(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	int rc;
	std::cout << "Using sctp connect" << std::endl;
	rc = connect(sockfd, addr, addrlen);

	P_Z_ERR(rc, "tx_connect");

	return rc;
}

int sctp_transport::tx_listen(int sockfd, int backlog)
{
	int rc;
	std::cout << "Using sctp listen" << std::endl;
	rc = listen(sockfd, backlog);

	P_Z_ERR(rc, "tx_listen");

	return rc;
}

int sctp_transport::tx_bind(int sockfd, const struct sockaddr *addr,
		socklen_t addrlen)
{
	std::cout << "Using sctp bind" << std::endl;
	int rc = bind(sockfd, addr, addrlen);

	if(options->addresses.size() != 0) {
		tx_set_addresses(sockfd, &options->addresses);
	}

	P_Z_ERR(rc, "tx_bind");

	return rc;
}

int sctp_transport::tx_accept(int sockfd, struct sockaddr *addr,
		socklen_t *addrlen)
{
	int rc;
	std::cout << "Using sctp accept" << std::endl;
	rc = accept(sockfd, addr, addrlen);

	P_N_ERR(rc, "tx_accept");

	return rc;
}

int sctp_transport::tx_send(int sockfd, const void *buf, size_t len, int flags)
{
	int rc;
	std::cout << "Using sctp send" << std::endl;
	rc = send(sockfd, buf, len, flags);

	P_N_ERR(rc, "tx_send");

	return rc;
}

int sctp_transport::tx_recv(int sockfd, void *buf, size_t len, int flags)
{
	int rc;
	std::cout << "Using sctp recv" << std::endl;
	rc = recv(sockfd, buf, len, flags);

	P_N_ERR(rc, "tx_recv");

	return rc;
}

int sctp_transport::tx_close(int fd)
{
	int rc;
	std::cout << "Using sctp close" << std::endl;
	rc = close(fd);

	P_Z_ERR(rc, "tx_close");

	return rc;
}

int sctp_transport::tx_getsockopt(int sockfd, int level, int optname,
		void *optval, socklen_t *optlen)
{
	int rc;
	std::cout << "Using sctp getsockotpt" << std::endl;
	rc = getsockopt(sockfd, level, optname, optval, optlen);

	P_Z_ERR(rc, "tx_getsockopt");

	return rc;
}

int sctp_transport::tx_setsockopt(int sockfd, int level, int optname,
		const void *optval, socklen_t optlen)
{
	int rc;
	std::cout << "Using sctp setsockopt" << std::endl;

	rc = setsockopt(sockfd, level, optname, optval, optlen);

	P_Z_ERR(rc, "tx_setsockopt");

	return rc;
}

void sctp_transport::tx_set_receive_buffer(int sockfd, int bufsize)
{
	std::cout << "Using sctp set_receive_buffer" << std::endl;
	set_tcp_receive_buffer(sockfd, bufsize);
}

void sctp_transport::tx_set_send_buffer(int sockfd, int bufsize)
{
	std::cout << "Using sctp set_send_buffer" << std::endl;
	set_tcp_send_buffer(sockfd, bufsize);
}

void sctp_transport::tx_set_keepalives(int sockfd, int keepalive, int keepalive_cnt,
		int keepalive_idle, int keepalive_intv)
{

#ifdef ZMQ_HAVE_SO_KEEPALIVE

    if (keepalive != -1)
    {
    	std::cout << "Using sctp set_keepalives" << std::endl;
        int rc = setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (char*) &keepalive, sizeof (int));
        errno_assert (rc == 0);
    }
#endif

}

void sctp_transport::tx_tune_socket(int sockfd)
{
	std::cout << "Using sctp tune_socket" << std::endl;
	int nodelay = 1;
	int rc = setsockopt(sockfd, IPPROTO_SCTP, SCTP_NODELAY, (char*) &nodelay,
			sizeof(int));

	errno_assert(rc == 0);
}

void sctp_transport::tx_unblock_socket(int sockfd)
{
	std::cout << "Using sctp ublock socket" << std::endl;
	unblock_socket(sockfd);
}

void sctp_transport::tx_enable_ipv4_mapping(int sockfd)
{
	std::cout << "Using sctp enable_ipv4_mapping" << std::endl;
	enable_ipv4_mapping(sockfd);
}

void sctp_transport::tx_get_peer_ip_address(int sockfd, std::string &ip_addr)
{
	std::cout << "Using get_peer_ip_address" << std::endl;
	get_peer_ip_address(sockfd, ip_addr);
}

void sctp_transport::tx_set_ip_type_of_service(int sockfd, int iptos)
{
	std::cout << "Using set_ip_type_of_service" << std::endl;
	set_ip_type_of_service(sockfd, iptos);
}

transport_options_t *sctp_transport::tx_get_options()
{
	return options;
}

int sctp_transport::tx_set_heartbeat_intvl(int sockfd, int value)
{

//	if(getsockopt(sockfd, SOL_SOCKET, SCTP_PEER_ADDR_PARAMS, &hb, &l) == -1) {
//			perror("sctp_wrapper: getsockopt");
//	}
//	else {
//		std::cout << "heartbeat def = " << hb.spp_hbinterval << std::endl;
//	}
	std::cout << "hb to set = " << value << std::endl;

	struct sctp_paddrparams heartbeat;
	memset(&heartbeat, 0 ,sizeof(struct sctp_paddrparams));

	heartbeat.spp_hbinterval = value;
	heartbeat.spp_flags = SPP_HB_ENABLE;
	heartbeat.spp_pathmaxrxt = 1;

	if(setsockopt(sockfd, SOL_SCTP, SCTP_PEER_ADDR_PARAMS, &heartbeat,
			sizeof(struct sctp_paddrparams)) == -1) {
		perror("sctp_wrapper: tx_set_heartbeat_intvl");
	}

	struct sctp_paddrparams hb;
	memset(&hb, 0, sizeof(struct sctp_paddrparams));
	socklen_t l = sizeof(struct sctp_paddrparams);


	if(getsockopt(sockfd, SOL_SCTP, SCTP_PEER_ADDR_PARAMS, &hb, &l) == -1) {
		perror("sctp_wrapper: getsockopt");
	}
	else {
		std::cout << "heartbeat new = " << hb.spp_hbinterval << std::endl;
	}

	return 0;
}

int sctp_transport::tx_set_addresses(int sockfd, std::vector<tcp_address_t*> *addresses)
{
	std::cout << "setting addresses" << std::endl;
	std::vector<tcp_address_t*>::iterator it = addresses->begin();
	//std::vector<struct sockaddr*> res_addr;

	for(;it != addresses->end(); ++it) {
		std::string add_str;
		(*it)->to_string(add_str);
		std::cout << "adding address" << add_str << std::endl;
		//res_addr.push_back((struct sockaddr*)((*it)->addr()));
		int rc = sctp_bindx(sockfd, (struct sockaddr*)((*it)->addr()),
					1, SCTP_BINDX_ADD_ADDR);

		if(rc != 0) {
			perror("Setting addresses");

			return rc;
		}
	}

	return 0;
}

int sctp_transport::tx_set_rto(int sockfd, int value)
{
	std::cout << "Setting rto: " << value << std::endl;
	struct sctp_rtoinfo rtoinfo;
	memset(&rtoinfo, 0, sizeof(rtoinfo));
	rtoinfo.srto_max = value;

	int rc = setsockopt(sockfd, SOL_SCTP, SCTP_RTOINFO,
			&rtoinfo, sizeof(struct sctp_rtoinfo));

	if(rc != 0) {
		perror("Setting rto");
		return rc;
	}

	return 0;
}

int sctp_transport::tx_set_num_streams(int sockfd, int in, int out)
{
	struct sctp_initmsg init;
	memset(&init, 0, sizeof(init));

	init.sinit_max_instreams = in;
	init.sinit_num_ostreams = out;

	int rc = setsockopt(sockfd, IPPROTO_SCTP, SCTP_INITMSG,
			&init, sizeof(init));

	if(rc != 0) {
		perror("Setting num streams");
		return rc;
	}

	return 0;
}

void sctp_transport::tx_set_options(int sockfd, transport_options_t *options_)
{

	sctp_options_t *sctp_opt = (sctp_options_t*)options_;
	options = sctp_opt;

	struct sctp_event_subscribe events;
	memset(&events, 0, sizeof(events));
	events.sctp_data_io_event = 1;

	if(setsockopt(sockfd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof(events)) == -1) {
		perror("set events");
	}

	std::cout << "Setting options" << std::endl;
	std::cout << "heartbeat = " << sctp_opt->heartbeat_intvl << std::endl;
	if(sctp_opt->heartbeat_intvl != -1) {
		tx_set_heartbeat_intvl(sockfd, sctp_opt->heartbeat_intvl);
		std::cout << "heartbeat set to :" << sctp_opt->heartbeat_intvl
				<< std::endl;
	}

	std::cout << "rto = " << sctp_opt->rto_max << std::endl;
	if(sctp_opt->rto_max != -1) {
		tx_set_rto(sockfd, sctp_opt->rto_max);
	}

	std::cout << "max streams out = " << sctp_opt->stream_num_out
			<< std::endl;
	std::cout << "max streams in = " << sctp_opt->stream_num_in
			<< std::endl;

	tx_set_num_streams(sockfd, sctp_opt->stream_num_in,
			sctp_opt->stream_num_out);
}

} /* namespace zmq */
