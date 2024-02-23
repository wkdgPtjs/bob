#include <iostream>
#include <pcap.h>
#include <map>
#include <string>
#include <sstream>
#include <iomanip>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct EndpointStats {
    unsigned int packets_sent = 0;
    unsigned int packets_received = 0;
    unsigned int bytes_sent = 0;
    unsigned int bytes_received = 0;
};

struct ConversationStats {
    std::string src_ip;
    std::string dst_ip;
    std::string protocol;
    uint16_t src_port;
    uint16_t dst_port;
};

std::map<std::string, EndpointStats> ipStatsMap;
std::map<std::string, EndpointStats> macStatsMap;
std::map<std::string, ConversationStats> conversationStatsMap;

std::string macToString(const u_char* addr) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        oss << std::setw(2) << static_cast<int>(addr[i]);
        if (i != 5) oss << ":";
    }
    return oss.str();
}

void packetHandler(const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ether_header *ethHeader = reinterpret_cast<const struct ether_header*>(packet);
    const struct ip *ipHeader = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
    std::string srcIP = inet_ntoa(ipHeader->ip_src);
    std::string dstIP = inet_ntoa(ipHeader->ip_dst);

    std::string srcMAC = macToString(ethHeader->ether_shost);
    std::string dstMAC = macToString(ethHeader->ether_dhost);

    macStatsMap[srcMAC].packets_sent++;
    macStatsMap[dstMAC].packets_received++;
    macStatsMap[srcMAC].bytes_sent += header->len;
    macStatsMap[dstMAC].bytes_received += header->len;

    ipStatsMap[srcIP].packets_sent++;
    ipStatsMap[dstIP].packets_received++;
    ipStatsMap[srcIP].bytes_sent += header->len;
    ipStatsMap[dstIP].bytes_received += header->len;

    std::string protocol;
    uint16_t srcPort = 0, dstPort = 0;
    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcpHeader = reinterpret_cast<const struct tcphdr*>(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        srcPort = ntohs(tcpHeader->th_sport);
        dstPort = ntohs(tcpHeader->th_dport);
        protocol = "TCP";
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr *udpHeader = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        srcPort = ntohs(udpHeader->uh_sport);
        dstPort = ntohs(udpHeader->uh_dport);
        protocol = "UDP";
    } else {
        protocol = "Unknown";
    }

    std::string conversationKey = srcIP + "-" + std::to_string(srcPort) + "-" + dstIP + "-" + std::to_string(dstPort) + "-" + protocol;
    conversationStatsMap[conversationKey].src_ip = srcIP;
    conversationStatsMap[conversationKey].dst_ip = dstIP;
    conversationStatsMap[conversationKey].protocol = protocol;
    conversationStatsMap[conversationKey].src_port = srcPort;
    conversationStatsMap[conversationKey].dst_port = dstPort;
}

void printStats() {
    std::cout << "[Ethernet]\n";
    for (const auto &entry : macStatsMap) {
        std::cout << "MAC Address: " << entry.first << "\n";
    }

    std::cout << "\n[IPv4]\n";
    for (const auto &entry : ipStatsMap) {
        std::cout << "IP Address : " << entry.first
                  << " , 송신 패킷 개수 : " << entry.second.packets_sent
                  << " , 수신 패킷 개수 : " << entry.second.packets_received
                  << " , 송신 패킷 바이트 : " << entry.second.bytes_sent
                  << " , 수신 패킷 바이트 : " << entry.second.bytes_received << std::endl;
    }

		std::cout << "\n[Conversation]\n";
		for (const auto &entry : conversationStatsMap) {
		    std::cout << "Source IP: " << entry.second.src_ip << "(" << entry.second.src_port << ")"
		              << " - Destination IP: " << entry.second.dst_ip << "(" << entry.second.dst_port << ")"
		              << " , Protocol: " << entry.second.protocol << std::endl;
	}
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap file>" << std::endl;
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << "Could not open file " << argv[1] << ": " << errbuf << std::endl;
        return -2;
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header))) {
        packetHandler(&header, packet);
    }

    printStats();

    pcap_close(handle);
    
    return 0;
}
