#include "mainwindow.h"
#include <QApplication>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

void callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    unsigned short ether_type;

    printf("Source_Mac : %02x.%02x.%02x.%02x.%02x.%02x          ",packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
    printf("Destination_Mac : %02x.%02x.%02x.%02x.%02x.%02x     ",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    unsigned short eth_type = ntohs(*((unsigned short *)&(packet[12])));
    if (eth_type == 0x800){printf("Type : IPv4\n");}
    else if (eth_type == 0x0806){printf("Type : ARP\n");}
    else if (eth_type == 0x8035){printf("Type : RARP\n");}
    else if (eth_type == 0x8100){printf("Type : VLAN\n");}
    else if (eth_type == 0x8847){printf("Type : MPLS\n");}
    else if (eth_type == 0x8864){printf("Type : PPPOE\n");}

    printf("Source_IP  : %03d.%03d.%03d.%03d            ",packet[26],packet[27],packet[28],packet[29]);
    printf("Destination_IP  : %03d.%03d.%03d.%03d       ",packet[30],packet[31],packet[32],packet[33]);

    unsigned short IP_type = (*((unsigned short *)&(packet[23])))&0xFF;

    if (IP_type == 1){printf("Protocol : ICMP\n");}
    else if (IP_type == 2){printf("Protocol : IGMP\n");}
    else if (IP_type == 6){printf("Protocol : TCP\n");}
    else if (IP_type == 17){printf("Protocol : UDP\n");}
    else if (IP_type == 80){printf("Protocol : ISP-IP\n");}
    else if (IP_type == 88){printf("Protocol : EIGRP\n");}
    else {printf("Exception_Protocol!!\n");}

    unsigned short s_port = ntohs(*((unsigned short *)&(packet[34])));
    unsigned short d_port = ntohs(*((unsigned short *)&(packet[36])));

    printf("s_port : %05d                          ",s_port);
    printf("d_port : %05d\n",d_port);
    printf("\n");
}


int main(int argc, char **argv)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;


    //device select
    printf("%X\n",errbuf+2);
    dev=pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    printf("device : %s\n", dev);

    //device packet capture descriptor
    descr = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (descr == NULL)
        {
            printf("pcap_open_live(): %s\n", errbuf);
            exit(1);
        }

        //packet capture
        packet = pcap_next(descr, &hdr);
        if (packet == NULL)
        {
            printf("Fail_Capture_Packet!\n");
            exit(1);
        }

        pcap_loop(descr, -1, callback, NULL);

    return 0;
}





