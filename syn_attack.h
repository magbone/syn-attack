#ifndef SYN_ATTACK_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>

// source port
#define SRC_PORT 30902

// packet size
#define P_SIZE 512




int syn_attack_sock(const char *, const char *, u_int16_t);

static u_int16_t packet_checksum(u_int16_t *, size_t);

static struct ip* ipv4_header_create(const char *, const char *, int);

static struct tcphdr* tcphdr_create(const u_int16_t);

#endif // !SYN_ATTACK_H
