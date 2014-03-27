
#include "../src/tcpWrapper.h"
//#include "../src/transport.h"

#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <cstdio>
#include <pthread.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <iostream>

#define error_check(n, s) if(n == -1) { perror(s); return 1; }
#define f_error_check(n, s, r) if(n == -1) { perror(s); *r = 1; pthread_exit(r); }
#define prt_info(s) fprintf(stdout, "[INFO] %s\n", s)

using namespace zmq;

struct End_Point
{
	int sock_d;
	Transport *wrapper;
	struct addrinfo *addr;
	pthread_t thread;
	int initalized;
};

void *client(void *point);
void *server(void *point);

int main(void)
{
	struct End_Point *ep_client = new End_Point();
	struct End_Point *ep_server = new End_Point();

	int rc, *ret_val;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;


	prt_info("Resolving Server address");
	rc = getaddrinfo("127.0.0.1", "5000", &hints, &ep_server->addr);
	error_check(rc, "resolve_address: server");

	prt_info("Resolving Client address");
	rc = getaddrinfo("127.0.0.1", "5000", &hints, &ep_client->addr);
	error_check(rc, "resolve_address: client");

	prt_info("Creating wrapper object");
	Transport *wrapper = (Transport*)new Tcp_Wrapper();

	ep_client->wrapper = wrapper;
	ep_server->wrapper = wrapper;

	fprintf(stdout, "ai_family = %d\n", ep_server->addr->ai_family);
	fprintf(stdout, "ai_sock_type = %d\n", ep_server->addr->ai_socktype);
	fprintf(stdout, "ai_protocol = %d\n", ep_server->addr->ai_protocol);

	fprintf(stdout, "ai_family = %d\n", ep_client->addr->ai_family);
	fprintf(stdout, "ai_sock_type = %d\n", ep_client->addr->ai_socktype);
	fprintf(stdout, "ai_protocol = %d\n", ep_client->addr->ai_protocol);

	prt_info("Creating Server Socket");
	ep_server->sock_d = wrapper->tx_socket(ep_server->addr->ai_family,
			ep_server->addr->ai_socktype,
			ep_server->addr->ai_protocol);
	error_check(ep_server->sock_d, "tx_socket: server");

	prt_info("Creating Client Socket");
	ep_client->sock_d = wrapper->tx_socket(ep_client->addr->ai_family,
			ep_client->addr->ai_socktype,
			ep_client->addr->ai_protocol);
	error_check(ep_client->sock_d, "tx_socket: client");

	ep_server->initalized = 0;

	prt_info("Creating Server Thread");
	pthread_create(&ep_server->thread, NULL, &server, (void*)ep_server);

	prt_info("Waiting for server to start");
	while(!ep_server->initalized);

	prt_info("Creating client thread");
	pthread_create(&ep_client->thread, NULL, &client, (void*)ep_client);

	prt_info("Waiting for server to finish");
	pthread_join(ep_server->thread, (void**)&ret_val);

	prt_info("Deleting objects");
	freeaddrinfo(ep_server->addr);
	freeaddrinfo(ep_client->addr);
	delete(ep_client);
	delete(ep_server);
	delete(wrapper);

	return 0;
}

void *client(void *point)
{
	int rc, *ret_val = new int(0);

	prt_info("Client Started");
	End_Point *ep_client = static_cast<End_Point*>(point);

	Transport *wrapper = ep_client->wrapper;

	rc = wrapper->tx_connect(ep_client->sock_d, ep_client->addr->ai_addr,
			ep_client->addr->ai_addrlen);

	f_error_check(rc, "connect: client", ret_val);

	rc = wrapper->tx_send(ep_client->sock_d, "hello", 6, 0);

	f_error_check(rc, "send: client", ret_val);

	rc = wrapper->tx_close(ep_client->sock_d);

	f_error_check(rc, "close: client", ret_val);

	pthread_exit(static_cast<void*>(ret_val));
}

void *server(void *point)
{
	int rc, n_sock, *ret_val = new int(0);

	prt_info("Server Started");
	End_Point *ep_server = static_cast<End_Point*>(point);

	Transport *wrapper = ep_server->wrapper;

	rc = wrapper->tx_bind(ep_server->sock_d, ep_server->addr->ai_addr,
			ep_server->addr->ai_addrlen);
	f_error_check(rc, "bind: server", ret_val);

	rc = wrapper->tx_listen(ep_server->sock_d, 10);
	f_error_check(rc, "listen: server", ret_val);

	ep_server->initalized = 1;

	struct sockaddr_storage storage;

	socklen_t len = sizeof(storage);
	n_sock = wrapper->tx_accept(ep_server->sock_d,
			(sockaddr*)&storage, &len);

	char addr_s[INET_ADDRSTRLEN];

	struct sockaddr *in = (sockaddr*)&storage;
	inet_ntop(AF_INET, (void*)&((sockaddr_in*)in)->sin_addr, addr_s, INET_ADDRSTRLEN);

	f_error_check(n_sock, "accept: server", ret_val);

	std::cout << "Received connection from : " << addr_s << std::endl;

	char buff[100];

	rc = wrapper->tx_recv(n_sock, static_cast<void*>(buff), 100, 0);

	f_error_check(n_sock, "receive: server", ret_val);

	std::cout << "Received : " << buff << std::endl;

	rc = wrapper->tx_close(n_sock);

	f_error_check(rc, "close: server: n_sock", ret_val);

	rc = wrapper->tx_close(ep_server->sock_d);

	f_error_check(rc, "close: server: sock_d", ret_val);

	pthread_exit(static_cast<void*>(ret_val));
}
