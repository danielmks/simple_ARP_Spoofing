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
