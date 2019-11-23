/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//socketopt.h

#ifndef _SOCKETOPT_H_
#define _SOCKETOPT_H_

#include <net/if.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include "common_define.h"

#define FAST_WRITE_BUFF_SIZE  (256 * 1024)

typedef struct fast_if_config {
    char name[IF_NAMESIZE];    //if name
    char mac[32];
    char ipv4[IP_ADDRESS_SIZE];
    char ipv6[48];
} FastIFConfig;

typedef struct ip_addr_s {
    char ip_addr[INET6_ADDRSTRLEN];
    int socket_domain;
} ip_addr_t;

typedef struct sockaddr_convert_s {
    socklen_t len;
    union {
        struct sockaddr addr;
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
    } sa;
} sockaddr_convert_t;

#ifdef SO_NOSIGPIPE
#define SET_SOCKOPT_NOSIGPIPE(sock) \
    do { \
    int set = 1;  \
    setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(int)); \
    } while (0)
#else
#define SET_SOCKOPT_NOSIGPIPE(sock)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*getnamefunc)(int socket, struct sockaddr *address, \
		socklen_t *address_len);

typedef int (*tcpsenddatafunc)(int sock, void* data, const int size, \
		const int timeout);

typedef int (*tcprecvdata_exfunc)(int sock, void *data, const int size, \
		const int timeout, int *count);

#define getSockIpaddr(sock, buff, bufferSize) \
	getIpaddr(getsockname, sock, buff, bufferSize)

#define getPeerIpaddr(sock, buff, bufferSize) \
	getIpaddr(getpeername, sock, buff, bufferSize)

/** get a line from socket
 *  parameters:
 *          sock: the socket
 *          s: the buffer
 *          size: buffer size (max bytes can receive)
 *          timeout: read timeout
 *  return: error no, 0 success, != 0 fail
*/
int tcpgets(int sock, char *s, const int size, const int timeout);

/** recv data (block mode)
 *  parameters:
 *          sock: the socket
 *          data: the buffer
 *          size: buffer size (max bytes can receive)
 *          timeout: read timeout
 *          count: store the bytes recveived
 *  return: error no, 0 success, != 0 fail
*/
int tcprecvdata_ex(int sock, void *data, const int size, \
		const int timeout, int *count);

/** recv data (non-block mode)
 *  parameters:
 *          sock: the socket
 *          data: the buffer
 *          size: buffer size (max bytes can receive)
 *          timeout: read timeout in seconds
 *          count: store the bytes recveived
 *  return: error no, 0 success, != 0 fail
*/
int tcprecvdata_nb_ex(int sock, void *data, const int size, \
		const int timeout, int *count);

/** recv data (non-block mode) in ms
 *  parameters:
 *          sock: the socket
 *          data: the buffer
 *          size: buffer size (max bytes can receive)
 *          timeout: read timeout in milliseconds
 *          count: store the bytes recveived
 *  return: error no, 0 success, != 0 fail
*/
int tcprecvdata_nb_ms(int sock, void *data, const int size, \
		const int timeout_ms, int *count);

/** send data (block mode)
 *  parameters:
 *          sock: the socket
 *          data: the buffer to send
 *          size: buffer size
 *          timeout: write timeout
 *  return: error no, 0 success, != 0 fail
*/
int tcpsenddata(int sock, void* data, const int size, const int timeout);

/** send data (non-block mode)
 *  parameters:
 *          sock: the socket
 *          data: the buffer to send
 *          size: buffer size
 *          timeout: write timeout
 *  return: error no, 0 success, != 0 fail
*/
int tcpsenddata_nb(int sock, void* data, const int size, const int timeout);

/** connect to server by block mode
 *  parameters:
 *          sock: the socket
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *  return: error no, 0 success, != 0 fail
*/
int connectserverbyip(int sock, const char *server_ip, const short server_port);

/** connect to server by non-block mode
 *  parameters:
 *          sock: the socket
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *          auto_detect: if detect and adjust the block mode of the socket
 *  return: error no, 0 success, != 0 fail
*/
int connectserverbyip_nb_ex(int sock, const char *server_ip, \
		const short server_port, const int timeout, \
		const bool auto_detect);

/** connect to server by non-block mode, the socket must be set to non-block
 *  parameters:
 *          sock: the socket,  must be set to non-block
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *  return: error no, 0 success, != 0 fail
*/
#define connectserverbyip_nb(sock, server_ip, server_port, timeout) \
	connectserverbyip_nb_ex(sock, server_ip, server_port, timeout, false)

/** connect to server by non-block mode, auto detect socket block mode
 *  parameters:
 *          sock: the socket, can be block mode
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *  return: error no, 0 success, != 0 fail
*/
#define connectserverbyip_nb_auto(sock, server_ip, server_port, timeout) \
	connectserverbyip_nb_ex(sock, server_ip, server_port, timeout, true)

/** accept client connect request
 *  parameters:
 *          sock: the server socket
 *          timeout: read timeout
 *          err_no: store the error no, 0 for success
 *  return: client socket, < 0 for error
*/
int nbaccept(int sock, const int timeout, int *err_no);

/** set socket options
 *  parameters:
 *          sock: the socket
 *          timeout: read & write timeout
 *  return: error no, 0 success, != 0 fail
*/
int tcpsetserveropt(int fd, const int timeout);

/** set socket non-block options
 *  parameters:
 *          sock: the socket
 *  return: error no, 0 success, != 0 fail
*/
int tcpsetnonblockopt(int fd);

/** set socket no delay on send data
 *  parameters:
 *          sock: the socket
 *          timeout: read & write timeout
 *  return: error no, 0 success, != 0 fail
*/
int tcpsetnodelay(int fd, const int timeout);

/** set socket keep-alive
 *  parameters:
 *          sock: the socket
 *          idleSeconds: max idle time (seconds)
 *  return: error no, 0 success, != 0 fail
*/
int tcpsetkeepalive(int fd, const int idleSeconds);

/** print keep-alive related parameters
 *  parameters:
 *          sock: the socket
 *  return: error no, 0 success, != 0 fail
*/
int tcpprintkeepalive(int fd);

/** get ip address
 *  parameters:
 *          getname: the function name, should be getpeername or getsockname
 *          sock: the socket
 *          buff: buffer to store the ip address
 *          bufferSize: the buffer size (max bytes)
 *  return: in_addr_t, INADDR_NONE for fail
*/
in_addr_t getIpaddr(getnamefunc getname, int sock, \
		char *buff, const int bufferSize);

/** get hostname by it's ip address
 *  parameters:
 *          szIpAddr: the ip address
 *          buff: buffer to store the hostname
 *          bufferSize: the buffer size (max bytes)
 *  return: hostname, empty buffer for error
*/
char *getHostnameByIp(const char *szIpAddr, char *buff, const int bufferSize);

/** get by IPv4 address by it's hostname
 *  parameters:
 *          name: the hostname 
 *          buff: buffer to store the ip address
 *          bufferSize: the buffer size (max bytes)
 *  return: in_addr_t, INADDR_NONE for fail
*/
in_addr_t getIpaddrByName(const char *name, char *buff, const int bufferSize);

/** get by ip addresses by it's hostname
 *  parameters:
 *          name: the hostname
 *          ip_addr_arr: ip address array to store the ip address
 *          ip_addr_arr_size: ip address array size
 *  return: ip address count
*/
int getIpaddrsByName(const char *name, ip_addr_t *ip_addr_arr, const int ip_addr_arr_size);

/** bind wrapper for IPv4
 *  parameters:
 *          sock: the socket
 *          bind_ipaddr: the ip address to bind
 *          port: the port to bind
 *  return: error no, 0 success, != 0 fail
*/
int socketBind(int sock, const char *bind_ipaddr, const int port);

/** bind wrapper for IPv6
 *  parameters:
 *          sock: the socket
 *          bind_ipaddr: the ip address to bind
 *          port: the port to bind
 *  return: error no, 0 success, != 0 fail
*/
int socketBindIPv6(int sock, const char *bind_ipaddr, const int port);

/** bind wrapper for IPv4 or IPv6
 *  parameters:
 *          af: family, AF_INET or AF_INET6
 *          sock: the socket
 *          bind_ipaddr: the ip address to bind
 *          port: the port to bind
 *  return: error no, 0 success, != 0 fail
*/
int socketBind2(int af, int sock, const char *bind_ipaddr, const int port);

/** start a socket server for IPv4 (socket, bind and listen)
 *  parameters:
 *          sock: the socket
 *          bind_ipaddr: the ip address to bind
 *          port: the port to bind
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
int socketServer(const char *bind_ipaddr, const int port, int *err_no);

/** start a socket server for IPv6 (socket, bind and listen)
 *  parameters:
 *          sock: the socket
 *          bind_ipaddr: the ip address to bind
 *          port: the port to bind
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
int socketServerIPv6(const char *bind_ipaddr, const int port, int *err_no);

/** start a socket server for IPv4 or IPv6 (socket, bind and listen)
 *  parameters:
 *          af: family, AF_INET or AF_INET6
 *          sock: the socket
 *          bind_ipaddr: the ip address to bind
 *          port: the port to bind
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
int socketServer2(int af, const char *bind_ipaddr, const int port, int *err_no);

/** create socket (NOT connect to server yet)
 *  parameters:
 *          af: family, AF_UNSPEC (auto dectect), AF_INET or AF_INET6
 *          server_ip: ip address of the server to detect family when af == AF_UNSPEC
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          bind_ipaddr: the ip address to bind, NULL or empty for bind ANY
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
int socketCreateEx2(int af, const char *server_ip,
		const int timeout, const int flags,
        const char *bind_ipaddr, int *err_no);

/** create socket (NOT connect to server yet)
 *  parameters:
 *          server_ip: ip address of the server to detect family
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          bind_ipaddr: the ip address to bind, NULL or empty for bind ANY
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
static inline int socketCreateExAuto(const char *server_ip,
		const int timeout, const int flags,
        const char *bind_ipaddr, int *err_no)
{
    return socketCreateEx2(AF_UNSPEC, server_ip, timeout, flags,
            bind_ipaddr, err_no);
}

/** connect to server
 *  parameters:
 *          af: family, AF_UNSPEC (auto dectect), AF_INET or AF_INET6
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          bind_ipaddr: the ip address to bind, NULL or empty for bind ANY
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
int socketClientEx2(int af, const char *server_ip,
		const short server_port, const int timeout,
		const int flags, const char *bind_ipaddr, int *err_no);

/** connect to server
 *  parameters:
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          bind_ipaddr: the ip address to bind, NULL or empty for bind ANY
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
static inline int socketClientExAuto(const char *server_ip,
		const short server_port, const int timeout,
		const int flags, const char *bind_ipaddr, int *err_no)
{
    return socketClientEx2(AF_UNSPEC, server_ip, server_port,
            timeout, flags, bind_ipaddr, err_no);
}

/** connect to server
 *  parameters:
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          bind_ipaddr: the ip address to bind, NULL or empty for bind ANY
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
static inline int socketClientAuto(const char *server_ip,
		const short server_port, const int timeout,
		const int flags, int *err_no)
{
    return socketClientEx2(AF_UNSPEC, server_ip, server_port,
            timeout, flags, NULL, err_no);
}

/** connect to server
 *  parameters:
 *          af: family, AF_UNSPEC (auto dectect), AF_INET or AF_INET6
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
static inline int socketClient2(int af, const char *server_ip,
		const short server_port, const int timeout,
		const int flags, int *err_no)
{
    return socketClientEx2(af, server_ip, server_port,
            timeout, flags, NULL, err_no);
}

/** connect to server with IPv4 socket
 *  parameters:
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
static inline int socketClient(const char *server_ip,
		const short server_port, const int timeout,
		const int flags, int *err_no)
{
    return socketClient2(AF_INET, server_ip, server_port,
            timeout, flags, err_no);
}

/** connect to server with IPv6 socket
 *  parameters:
 *          server_ip: ip address of the server
 *          server_port: port of the server
 *          timeout: connect timeout in seconds
 *          flags: socket flags such as O_NONBLOCK for non-block socket
 *          err_no: store the error no
 *  return: >= 0 server socket, < 0 fail
*/
static inline int socketClientIPv6(const char *server_ip,
		const short server_port, const int timeout,
		const int flags, int *err_no)
{
    return socketClient2(AF_INET6, server_ip, server_port,
            timeout, flags, err_no);
}

#define tcprecvdata(sock, data, size, timeout) \
	tcprecvdata_ex(sock, data, size, timeout, NULL)

#define tcpsendfile(sock, filename, file_bytes, timeout, total_send_bytes) \
	tcpsendfile_ex(sock, filename, 0, file_bytes, timeout, total_send_bytes)

#define tcprecvdata_nb(sock, data, size, timeout) \
	tcprecvdata_nb_ex(sock, data, size, timeout, NULL)

/** send a file
 *  parameters:
 *          sock: the socket
 *          filename: the file to send
 *          file_offset: file offset, start position
 *          file_bytes: send file length
 *          timeout: write timeout
 *          total_send_bytes: store the send bytes
 *  return: error no, 0 success, != 0 fail
*/
int tcpsendfile_ex(int sock, const char *filename, const int64_t file_offset, \
	const int64_t file_bytes, const int timeout, int64_t *total_send_bytes);

/** receive data to a file
 *  parameters:
 *          sock: the socket
 *          filename: the file to write
 *          file_bytes: file size (bytes) 
 *          fsync_after_written_bytes: call fsync every x bytes
 *          timeout: read/recv timeout
 *          true_file_bytes: store the true file bytes
 *  return: error no, 0 success, != 0 fail
*/
int tcprecvfile(int sock, const char *filename, const int64_t file_bytes, \
		const int fsync_after_written_bytes, const int timeout, \
		int64_t *true_file_bytes);


#define tcprecvinfinitefile(sock, filename, fsync_after_written_bytes, \
			timeout, file_bytes) \
	tcprecvfile(sock, filename, INFINITE_FILE_SIZE, \
		fsync_after_written_bytes, timeout, file_bytes)


/** receive data to a file
 *  parameters:
 *          sock: the socket
 *          filename: the file to write
 *          file_bytes: file size (bytes)
 *          fsync_after_written_bytes: call fsync every x bytes
 *          hash_codes: return hash code of file content
 *          timeout: read/recv timeout
 *  return: error no, 0 success, != 0 fail
*/
int tcprecvfile_ex(int sock, const char *filename, const int64_t file_bytes, \
		const int fsync_after_written_bytes, \
		unsigned int *hash_codes, const int timeout);

/** receive specified data and discard
 *  parameters:
 *          sock: the socket
 *          bytes: data bytes to discard
 *          timeout: read timeout
 *          total_recv_bytes: store the total recv bytes
 *  return: error no, 0 success, != 0 fail
*/
int tcpdiscard(int sock, const int bytes, const int timeout, \
		int64_t *total_recv_bytes);

/** get local host ip addresses
 *  parameters:
 *          ip_addrs: store the ip addresses
 *          max_count: max ip address (max ip_addrs elements)
 *          count: store the ip address count
 *  return: error no, 0 success, != 0 fail
*/
int getlocaladdrs(char ip_addrs[][IP_ADDRESS_SIZE], \
	const int max_count, int *count);

/** get local host ip addresses by if alias prefix
 *  parameters:
 *          if_alias_prefixes: if alias prefixes, such as eth, bond etc.
 *          prefix_count: if alias prefix count
 *          ip_addrs: store the ip addresses
 *          max_count: max ip address (max ip_addrs elements)
 *          count: store the ip address count
 *  return: error no, 0 success, != 0 fail
*/
int gethostaddrs(char **if_alias_prefixes, const int prefix_count, \
	char ip_addrs[][IP_ADDRESS_SIZE], const int max_count, int *count);

/** get local if configs
 *  parameters:
 *          if_configs: store the if configs
 *          max_count: max ifconfig elements
 *          count: store the ifconfig count
 *  return: error no, 0 success, != 0 fail
*/
int getifconfigs(FastIFConfig *if_configs, const int max_count, int *count);

/** set socket address by ip and port
 *  parameters:
 *          ip: the ip address
 *          port: the port
 *          convert: the convert struct for IPv4 and IPv6 compatibility
 *  return: error no, 0 success, != 0 fail
*/
int setsockaddrbyip(const char *ip, const short port, sockaddr_convert_t *convert);

static inline bool is_ipv6_addr(const char *ip)
{
    return (*ip == ':' || strchr(ip, ':') != NULL); //ipv6
}

void tcp_set_try_again_when_interrupt(const bool value);

static inline void tcp_dont_try_again_when_interrupt()
{
    tcp_set_try_again_when_interrupt(false);
}

#ifdef __cplusplus
}
#endif

#endif

