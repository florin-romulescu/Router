#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

struct packet_data {
	void *buf;
	unsigned int len;
	struct route_table_entry *entry;
};

uint16_t calculate_checksum(unsigned short *ptr, unsigned int len) {
	register long sum = 0;
	uint16_t checksum;

    while( len > 1 )  {
        /* This is the inner loop */
        sum += * (unsigned short *) ptr++;
        len -= 2;
    }

    /*  Add left-over byte, if any */
    if ( len > 0 )
        sum += * (unsigned char *) ptr;

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    checksum = ~sum;
	return checksum;
}

int cmp_route_table_entry(const void* a, const void* b) {
    const struct route_table_entry* entry_a = (const struct route_table_entry*) a;
    const struct route_table_entry* entry_b = (const struct route_table_entry*) b;

    // Compare the prefix and mask first
    if (entry_a->prefix > entry_b->prefix) {
        return -1;
    } else if (entry_a->prefix < entry_b->prefix) {
        return 1;
    } else if (entry_a->mask > entry_b->mask) {
        return -1;
    } else if (entry_a->mask < entry_b->mask) {
        return 1;
    }

    // If prefix and mask are the same, compare the next hop
    if (entry_a->next_hop > entry_b->next_hop) {
        return -1;
    } else if (entry_a->next_hop < entry_b->next_hop) {
        return 1;
    }

    // If all fields are the same, return 0 (entries are equal)
    return 0;
}

struct route_table_entry* get_table_entry(struct route_table_entry* table,
					unsigned int table_length,
					uint32_t daddr) {
	qsort((void *)table, table_length, sizeof(struct route_table_entry), cmp_route_table_entry); 
	for (int i = 0; i < table_length; ++i) {
		if (table[i].prefix == (daddr & table[i].mask)) {
			return &table[i];
		}
	}
	return NULL;
}

int is_mac_broadcast(uint8_t *mac) {
	for (int i = 0; i < 6; ++i) {
		if (mac[i] != 0x00) {
			return 0;
		}
	}
	return 1;
}

int is_macs_equal(uint8_t *mac1, uint8_t *mac2) {
	for (int i = 0; i < 6; ++i) {
		if (mac1[i] != mac2[i]) {
			return 0;
		}
	}
	return 1;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	printf("===Router INIT===\n");
	init(argc - 2, argv + 2);

	struct arp_entry *arp = malloc(sizeof(struct arp_entry) * 100);
	unsigned int arp_length = 0;
	queue q = queue_create();
	queue copy = queue_create();
	printf("%s\n", get_interface_ip(1));


	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		printf("PACKET Received\n");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (ntohs(eth_hdr->ether_type) == ARP_TYPE) { // We received an ARP packet
			printf("ARP packet\n");
			struct arp_header *arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));
			uint8_t *sha = malloc(sizeof(uint8_t) * 6);
			get_interface_mac(interface, sha);
			if (ntohs(arp_hdr->op) == ARP_REQUEST) {
				if (is_mac_broadcast(arp_hdr->tha) || is_macs_equal(arp_hdr->tha, sha)) {
					send_arp_reply(interface, arp_hdr->spa, arp_hdr->sha);
					add_arp_entry(arp, &arp_length, arp_hdr->spa, arp_hdr->sha);
				}
			} else if (ntohs(arp_hdr->op) == ARP_REPLY) {
				if (is_macs_equal(arp_hdr->tha, sha) || is_mac_broadcast(arp_hdr->tha)) {
					add_arp_entry(arp, &arp_length, arp_hdr->spa, arp_hdr->sha);
					if (!queue_empty(q)) {
						struct packet_data* p = queue_deq(q);
						struct arp_entry* arp_entry = get_arp_entry(arp, arp_length, p->entry->next_hop);
						if (arp_entry != NULL) {
							struct ether_header *eth_hdr = (struct ether_header *) p->buf;
							struct iphdr *ip_hdr = (struct iphdr *) (p->buf + sizeof(struct ether_header));
							ip_hdr->check = ntohs(checksum((uint16_t* )ip_hdr, sizeof(struct iphdr)));
							uint8_t mac[6];
							get_interface_mac(p->entry->interface, mac);
							memcpy(eth_hdr->ether_shost, mac, 6);
							memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
							send_to_link(p->entry->interface, p->buf, p->len);
						} else {
							queue_enq(copy, p);
							while (!queue_empty(q)) {
								queue_enq(copy, queue_deq(q));
							}
							while (!queue_empty(copy)) {
								queue_enq(q, queue_deq(copy));
							}
						}
					}
				}
			}
		} else { // We received an IP packet
			printf("IP packet\n");
			// Verify the integrity of the packet
			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
			uint16_t old_checksum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t new_checksum = checksum((uint16_t* )ip_hdr, sizeof(struct iphdr));

			if (old_checksum != new_checksum) {
				fprintf(stderr, "Packet corrupted! Sending ICMP message...\n");
				// send_icmp_err_message(interface, buf, len, 3, 0);
				continue;
			}

			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface))) { // We received a packet for this router
				struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				if (icmp_hdr->type == 8) { // We received an ICMP echo request
					send_icmp_message(interface, buf, len, 0, 0); // Send an ICMP echo reply
				}
				continue;
			}

			// Updating TTL
			if (ip_hdr->ttl - 1 < 1) {
				fprintf(stderr, "TTL reached zero. Sending ICMP message...\n");
				send_icmp_message(interface, buf, len, 11, 0);
				continue;
			}
			ip_hdr->ttl -= 1;
			
			// Searching for an entry in the routing table
			struct route_table_entry* table = malloc(sizeof(struct route_table_entry) * 80000);
			int rlength = read_rtable(argv[1], table);

			struct route_table_entry *entry = get_table_entry(table, rlength, ip_hdr->daddr);
			if (entry == NULL) {
				fprintf(stderr, "No entry found! Dropping...\n");
				send_icmp_err_message(interface, buf, len, 3, 0);
				continue;
			}

			struct arp_entry *arp_entry = get_arp_entry(arp, arp_length, entry->next_hop);
			// If the arp entry is not found, send an arp request and enqueue the packet
			if (arp_entry == NULL) {
				fprintf(stderr, "No arp entry found! Sending arp request...\n");
				for (int inter = 0; inter < ROUTER_NUM_INTERFACES; ++inter)
					if (inter != interface) // Don't send the arp request on the interface from which we received the packet
						send_arp_request(inter, entry->next_hop);
				struct packet_data *data = malloc(sizeof(struct packet_data));
				data->entry = malloc(sizeof(struct route_table_entry));
				data->buf = malloc(len);
				data->len = len;
				memcpy(data->entry, entry, sizeof(struct route_table_entry));
				memcpy(data->buf, buf, len);
				queue_enq(q, data);
				continue;
			}
			if (!queue_empty(q)) {
				struct packet_data *data = malloc(sizeof(struct packet_data));
				data->entry = malloc(sizeof(struct route_table_entry));
				data->buf = malloc(len);
				data->len = len;
				memcpy(data->entry, entry, sizeof(struct route_table_entry));
				memcpy(data->buf, buf, len);
				queue_enq(q, data);
				continue;
			}

			ip_hdr->check = ntohs(checksum((uint16_t*) ip_hdr, sizeof(struct iphdr)));
			
			interface = entry->interface;
			uint8_t int_mac[6];
			get_interface_mac(interface, int_mac);

			memcpy(eth_hdr->ether_shost, int_mac, 6*sizeof(uint8_t));
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6*sizeof(uint8_t));
			
			send_to_link(interface, buf, len);
		}
	}
}
