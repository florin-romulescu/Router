#include "lib.h"
#include "protocols.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


int interfaces[ROUTER_NUM_INTERFACES];

int get_sock(const char *if_name)
{
	int res;
	int s = socket(AF_PACKET, SOCK_RAW, 768);
	DIE(s == -1, "socket");

	struct ifreq intf;
	strcpy(intf.ifr_name, if_name);
	res = ioctl(s, SIOCGIFINDEX, &intf);
	DIE(res, "ioctl SIOCGIFINDEX");

	struct sockaddr_ll addr;
	memset(&addr, 0x00, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = intf.ifr_ifindex;

	res = bind(s, (struct sockaddr *)&addr , sizeof(addr));
	DIE(res == -1, "bind");
	return s;
}

int send_to_link(int intidx, char *frame_data, size_t len)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the 
	 * interface, eg 1500 bytes 
	 */
	int ret;
	ret = write(interfaces[intidx], frame_data, len);
	DIE(ret == -1, "write");
	return ret;
}

ssize_t receive_from_link(int intidx, char *frame_data)
{
	ssize_t ret;
	ret = read(interfaces[intidx], frame_data, MAX_PACKET_LEN);
	return ret;
}

int socket_receive_message(int sockfd, char *frame_data, size_t *len)
{
	/*
	 * Note that "buffer" should be at least the MTU size of the
	 * interface, eg 1500 bytes
	 * */
	int ret = read(sockfd, frame_data, MAX_PACKET_LEN);
	DIE(ret < 0, "read");
	*len = ret;
	return 0;
}

int recv_from_any_link(char *frame_data, size_t *length) {
	int res;
	fd_set set;

	FD_ZERO(&set);
	while (1) {
		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			FD_SET(interfaces[i], &set);
		}

		res = select(interfaces[ROUTER_NUM_INTERFACES - 1] + 1, &set, NULL, NULL, NULL);
		DIE(res == -1, "select");

		for (int i = 0; i < ROUTER_NUM_INTERFACES; i++) {
			if (FD_ISSET(interfaces[i], &set)) {
				ssize_t ret = receive_from_link(i, frame_data);
				DIE(ret < 0, "receive_from_link");
				*length = ret;
				return i;
			}
		}
	}

	return -1;
}

char *get_interface_ip(int interface)
{
	struct ifreq ifr;
	int ret;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ret = ioctl(interfaces[interface], SIOCGIFADDR, &ifr);
	DIE(ret == -1, "ioctl SIOCGIFADDR");
	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

void get_interface_mac(int interface, uint8_t *mac)
{
	struct ifreq ifr;
	int ret;
	if (interface == 0)
		sprintf(ifr.ifr_name, "rr-0-1");
	else {
		sprintf(ifr.ifr_name, "r-%u", interface - 1);
	}
	ret = ioctl(interfaces[interface], SIOCGIFHWADDR, &ifr);
	DIE(ret == -1, "ioctl SIOCGIFHWADDR");
	memcpy(mac, ifr.ifr_addr.sa_data, 6);
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;

	return -1;
}

int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;

	return (a << 4) | b;
}

int hwaddr_aton(const char *txt, uint8_t *addr)
{
	int i;
	for (i = 0; i < 6; i++) {
		int a, b;
		a = hex2num(*txt++);
		if (a < 0)
			return -1;
		b = hex2num(*txt++);
		if (b < 0)
			return -1;
		*addr++ = (a << 4) | b;
		if (i < 5 && *txt++ != ':')
			return -1;
	}
	return 0;
}

void init(int argc, char *argv[])
{
	for (int i = 0; i < argc; ++i) {
		printf("Setting up interface: %s\n", argv[i]);
		interfaces[i] = get_sock(argv[i]);
	}
}


uint16_t checksum(uint16_t *data, size_t len)
{
	unsigned long checksum = 0;
	uint16_t extra_byte;
	while (len > 1) {
		checksum += ntohs(*data++);
		len -= 2;
	}
	if (len) {
		*(uint8_t *)&extra_byte = *(uint8_t *)data;
		checksum += extra_byte;
	}

	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >>16);
	return (uint16_t)(~checksum);
}

int read_rtable(const char *path, struct route_table_entry *rtable)
{
	FILE *fp = fopen(path, "r");
	int j = 0, i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strtok(line, " .");
		i = 0;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *)&rtable[j].prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&rtable[j].next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&rtable[j].mask)  + i % 4) = atoi(p);

			if (i == 12)
				rtable[j].interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}
		j++;
	}
	return j;
}

int parse_arp_table(char *path, struct arp_entry *arp_table)
{
	FILE *f;
	fprintf(stderr, "Parsing ARP table\n");
	f = fopen(path, "r");
	DIE(f == NULL, "Failed to open %s", path);
	char line[100];
	int i = 0;
	for(i = 0; fgets(line, sizeof(line), f); i++) {
		char ip_str[50], mac_str[50];
		sscanf(line, "%s %s", ip_str, mac_str);
		fprintf(stderr, "IP: %s MAC: %s\n", ip_str, mac_str);
		arp_table[i].ip = inet_addr(ip_str);
		int rc = hwaddr_aton(mac_str, arp_table[i].mac);
		DIE(rc < 0, "invalid MAC");
	}
	fclose(f);
	fprintf(stderr, "Done parsing ARP table.\n");
	return i;
}

/*
	This function will create an ethernet frame with the given
	destination MAC address, source MAC address and ether_type.
*/
struct ether_header create_eth_header(uint8_t *dest_mac,
									  uint8_t *src_mac,
									  uint16_t ether_type) {
	struct ether_header eth_hdr;
	memcpy(eth_hdr.ether_dhost, dest_mac, 6);
	memcpy(eth_hdr.ether_shost, src_mac, 6);
	eth_hdr.ether_type = htons(ether_type);
	return eth_hdr;
}

/*
	This function will create an ARP header with the given
	sender MAC address, sender IP address, target MAC address
	and target IP address.
*/
struct arp_header create_arp_header(uint8_t *sender_mac,
									uint32_t sender_ip,
									uint8_t *target_mac,
									uint32_t target_ip,
									uint16_t op) {
	struct arp_header arp_hdr;
	arp_hdr.htype = htons(1);
	arp_hdr.ptype = htons(0x800);
	arp_hdr.hlen = 6;
	arp_hdr.plen = 4;
	arp_hdr.op = htons(op);
	memcpy(arp_hdr.sha, sender_mac, 6);
	arp_hdr.spa = sender_ip;
	memcpy(arp_hdr.tha, target_mac, 6);
	arp_hdr.tpa = target_ip;
	return arp_hdr;
}

struct arp_entry* get_arp_entry(struct arp_entry* table,
									  unsigned int table_length,
									  uint32_t addr) {
	for (int i = 0; i < table_length; ++i) {
		if (ntohl(table[i].ip) == ntohl(addr)) {
			return &table[i];
		}
	}
	return NULL;
}

/*
    Send an ARP request to the given IP address and interface.
    The function should return 0 on success and -1 on failure.
*/
int send_arp_request(int interface, uint32_t ip) {
	uint8_t* sender_mac = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, sender_mac);
	
    // Create the ethernet header
	struct ether_header eth_hdr = create_eth_header(
		(uint8_t *)"\xff\xff\xff\xff\xff\xff", // Broadcast MAC
		sender_mac, // Source MAC
		(0x0806) // ARP
	);

	// Create the ARP header
	struct arp_header arp_hdr = create_arp_header(
		sender_mac, // Sender MAC
		inet_addr(get_interface_ip(interface)), // Sender IP
		(uint8_t *)"\x00\x00\x00\x00\x00\x00", // Target MAC
		ip, // Target IP
		(1) // ARP request
	);

	// Create the buffer
	void *buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	memcpy(buf, &eth_hdr, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	// Send the packet
	int ret = send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
	if (ret < 0) {
		return -1; // Error when sending
	}

	return 0;
}

/*
	Send a broadcast ARP request to an interface.
*/
int send_broadcast_arp_request(int interface) {
	uint8_t* sender_mac = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, sender_mac);

	// Create the ethernet header
	struct ether_header eth_hdr = create_eth_header(
		(uint8_t *)"\xff\xff\xff\xff\xff\xff", // Broadcast MAC
		sender_mac, // Source MAC
		(0x0806) // ARP
	);

	// Create the ARP header
	struct arp_header arp_hdr = create_arp_header(
		sender_mac, // Sender MAC
		inet_addr(get_interface_ip(interface)), // Sender IP
		(uint8_t *)"\x00\x00\x00\x00\x00\x00", // Target MAC
		0, // Target IP
		(1) // ARP request
	);

	// Create the buffer
	void *buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	memcpy(buf, &eth_hdr, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	// Send the packet
	int ret = send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
	if (ret < 0) {
		return -1; // Error when sending
	}

	return 0;
}

/*
	Send an ARP reply to the given IP address and interface.
	The function should return 0 on success and -1 on failure.
*/
int send_arp_reply(int interface, uint32_t ip, uint8_t *destination_mac) {
	uint8_t* sender_mac = malloc(6 * sizeof(uint8_t));
	get_interface_mac(interface, sender_mac);

	// Create the ethernet header
	struct ether_header eth_hdr = create_eth_header(
		destination_mac,
		sender_mac, // Source MAC
		(0x0806) // ARP
	);

	// Create the ARP header
	struct arp_header arp_hdr = create_arp_header(
		sender_mac, // Sender MAC
		inet_addr(get_interface_ip(interface)), // Sender IP
		destination_mac, // Target MAC
		ip, // Target IP
		(2) // ARP reply
	);

	// Create the buffer
	void *buf = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	memcpy(buf, &eth_hdr, sizeof(struct ether_header));
	memcpy(buf + sizeof(struct ether_header), &arp_hdr, sizeof(struct arp_header));

	// Send the packet
	int ret = send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
	if (ret < 0) {
		return -1; // Error when sending
	}

	return 0;
}

/*
	Create an arp entry in the arp table.
*/
void add_arp_entry(struct arp_entry *table, unsigned int *table_length,
				   uint32_t ip, uint8_t *mac) {
	for (int i = 0; i < *table_length; ++i) {
		if (ntohl(table[i].ip) == ntohl(ip)) {
			memcpy(table[i].mac, mac, 6);
			return;
		}
	}
	table[*table_length].ip = ip;
	memcpy(table[*table_length].mac, mac, 6);
	*table_length += 1;
	// write_arp_table(ARPTABLE, table, table_length + 1);
}

/*
	Create icmp header.
*/
struct icmphdr create_icmp_header(uint16_t type, uint16_t code, uint16_t checksum, uint16_t id, uint16_t seq) {
	struct icmphdr icmp_hdr;
	icmp_hdr.type = type;
	icmp_hdr.code = code;
	icmp_hdr.checksum = checksum;
	icmp_hdr.un.echo.id = id;
	icmp_hdr.un.echo.sequence = seq;
	return icmp_hdr;
}

int send_icmp_err_message(int interface,
						 void* buf, size_t len,
						 uint16_t type, uint16_t code) {
	// Create the icmp header
	struct icmphdr icmp_hdr = create_icmp_header(
		type,
		code,
		0,
		0,
		0
	);
	icmp_hdr.checksum = checksum((uint16_t*)&icmp_hdr, sizeof(struct icmphdr));
	// Get the ip header
	struct iphdr* ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));

	// Create the buffer
	void *new_buf = malloc(64 + sizeof(struct iphdr) + sizeof(struct icmphdr));
	memcpy(new_buf, buf, 64);
	memcpy(new_buf + 64, ip_hdr, sizeof(struct iphdr));
	memcpy(new_buf + 64 + sizeof(ip_hdr), &icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, new_buf, 64 + sizeof(struct iphdr) + sizeof(struct icmphdr));

	return 0;
}

/*
	Send ICMP message to the given IP address and interface.
*/
int send_icmp_message(int interface,
					  void *buf, size_t len,
					  uint16_t type, uint16_t code) {
	struct ether_header* given_eth_hdr = (struct ether_header*)buf;
	struct iphdr* given_ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));
	struct icmphdr* given_icmp_hdr = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Create the ethernet header
	struct ether_header eth_hdr = create_eth_header(
		given_eth_hdr->ether_shost, // Destination MAC
		given_eth_hdr->ether_dhost, // Source MAC
		(0x0800) // Ethernet type
	);
	// Create the IP header
	struct iphdr ip_hdr;
	ip_hdr.version = (4);
	ip_hdr.ihl = sizeof(struct iphdr) / 4;
	ip_hdr.tos = (0);
	ip_hdr.tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr.id = (0);
	ip_hdr.frag_off = 0; 
	ip_hdr.ttl = (64);
	ip_hdr.protocol = (1);
	ip_hdr.check = 0;
	ip_hdr.saddr = given_ip_hdr->daddr;
	ip_hdr.daddr = given_ip_hdr->saddr;
	ip_hdr.check = checksum((uint16_t*)&ip_hdr, sizeof(struct iphdr));

	// Create the ICMP header
	struct icmphdr icmp_hdr = create_icmp_header(
		(type), // Type
		(code), // Code
		0, // Checksum
		given_icmp_hdr->un.echo.id, // ID
		given_icmp_hdr->un.echo.sequence // Sequence
	);

	icmp_hdr.checksum = ntohs(checksum((uint16_t*)&icmp_hdr, sizeof(struct icmphdr)));
	void* new_buf = malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	memcpy(new_buf, &eth_hdr, sizeof(struct ether_header));
	memcpy(new_buf + sizeof(struct ether_header), &ip_hdr, sizeof(struct iphdr));
	memcpy(new_buf + sizeof(struct ether_header) + sizeof(struct iphdr), &icmp_hdr, sizeof(struct icmphdr));

	// Send the packet
	send_to_link(interface, new_buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
	return 0;
}