#ifndef _SYN_ATTACK_H_
#define _SYN_ATTACK_H_

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>


// packet size
#define P_SIZE (sizeof(struct ip) + sizeof(struct tcphdr))

#define WIN_SIZE 65535



struct tcp_checksum_hdr
{
      struct in_addr ip_src, ip_dst;
      u_char zero;
      u_char ip_p;
      u_short tcp_len; 
      struct tcphdr tcp_hdr;
};

int syn_attack_sock(const char *, const char *, u_int16_t);

static u_int16_t tcp_checksum(struct ip *, struct tcphdr *);

static struct ip* ipv4_hdr_create(const char *, const char *, int);

static struct tcphdr* tcp_hdr_create(const u_int16_t, struct ip *);

static u_int32_t generate_random_seq();

static u_int16_t generate_random_port();

#endif // !_SYN_ATTACK_H_
