#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include"libnet.h"

void Parse_Ethernet(const u_char * pakcet);
void Parse_IPv4(const u_char * pakcet);
void Parse_TCP(const u_char * pakcet);


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true)    {
        struct pcap_pkthdr* header;
        const u_char* packet;


        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        Parse_Ethernet(packet);
    }

    pcap_close(pcap);
}

void Parse_Ethernet(const u_char * pakcet)
{
    printf( "    \n================================\n");
    printf( " Start Parsing Packet\n\n");

    struct libnet_ethernet_hdr * parse = (struct libnet_ethernet_hdr*)(pakcet);

    uint16_t ether_type;

    ether_type = ntohs(parse -> ether_type );

    printf( " MAC dst : %02X:%02X:%02X:%02X:%02X:%02X\n\n",
    parse->ether_dhost[0],parse->ether_dhost[1],parse->ether_dhost[2],parse->ether_dhost[3],parse->ether_dhost[4],parse->ether_dhost[5]);

    printf( " MAC src : %02X:%02X:%02X:%02X:%02X:%02X\n\n",
    parse->ether_shost[0],parse->ether_shost[1],parse->ether_shost[2],parse->ether_shost[3],parse->ether_shost[4],parse->ether_shost[5]);


    if( ether_type == 0x0800){ //EtherType: IPv4 0x0800
        printf( " ================================\n ");
        printf( "IPv4 packet Detected\n");
        Parse_IPv4( pakcet + sizeof(struct libnet_ethernet_hdr) );
    }

    else{
        printf( " ================================\n ");
        printf( " ELSE...\n");
    }


    printf( " \n\n End Parsing Packet\n");
    printf( " ================================\n\n ");

}


void Parse_IPv4(const u_char * pakcet){
    struct libnet_ipv4_hdr * parse = (struct libnet_ipv4_hdr*)(pakcet);

    uint32_t src_IP = parse->ip_src.s_addr;
    uint32_t dst_IP = parse->ip_dst.s_addr;

    uint8_t temp[4];
    temp[3] = ( src_IP >> 24 ) & 0xFF;  //8*3
    temp[2] = ( src_IP >> 16 ) & 0xFF;  //8*2
    temp[1] = ( src_IP >> 8 ) & 0xFF;   //8*1
    temp[0] = src_IP & 0xFF;
    printf(" src IP : ");
    for(int i = 0; i < 4; i++){
        printf(" %d", temp[i]);
        if( i != 3)
            printf(".");
    }
    printf("\n");

    temp[3] = ( dst_IP >> 24 ) & 0xFF;
    temp[2] = ( dst_IP >> 16 ) & 0xFF;
    temp[1] = ( dst_IP >> 8 ) & 0xFF;
    temp[0] = dst_IP & 0xFF;
    printf(" dst IP : ");
    for(int i = 0; i < 4; i++){
        printf(" %d", temp[i]);
        if( i != 3)
            printf(".");
    }
    printf("\n");

    if ( parse->ip_p == 0x06 ){ //TCP Protocol 0x06
        printf("\n TCP detected\n");
        Parse_TCP(pakcet + sizeof(struct libnet_ipv4_hdr));
    }

}


void Parse_TCP(const u_char * pakcet){
    struct libnet_tcp_hdr * parse = (struct libnet_tcp_hdr*)(pakcet);

    uint16_t src_port = parse->th_sport;
    uint16_t dst_port = parse->th_dport;

    printf(" src port : %d\n", src_port);
    printf(" dst port : %d\n", dst_port);

    unsigned char * data = (unsigned char *)(parse + sizeof(struct libnet_tcp_hdr));
    typedef  unsigned char* uchar;
    uchar p_data = data;

    for(int i = 0; i < 8; i++){
        if (p_data == NULL)
            break;
        printf(" %02X ", p_data[i]);
    }
}
