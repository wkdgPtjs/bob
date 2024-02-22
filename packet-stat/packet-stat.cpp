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
    unsigned int packets = 0;
    unsigned int bytes = 0;
};

// 새로운 구조체 ConversationStats 추가
struct ConversationStats {
    EndpointStats src;
    EndpointStats dst;
};

std::map<std::string, EndpointStats> macStatsMap; // MAC 주소별 통계
std::map<std::string, ConversationStats> conversationStatsMap; // 대화(Conversation)별 통계

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
    std::string srcMAC = macToString(ethHeader->ether_shost);
    std::string dstMAC = macToString(ethHeader->ether_dhost);

    // MAC 주소별 통계 업데이트
    macStatsMap[srcMAC].packets++;
    macStatsMap[srcMAC].bytes += header->len;
    macStatsMap[dstMAC].packets++;
    macStatsMap[dstMAC].bytes += header->len;

    // IP 헤더 및 프로토콜 확인
    const struct ip *ipHeader = reinterpret_cast<const struct ip*>(packet + sizeof(struct ether_header));
    u_int8_t protocol = ipHeader->ip_p;

    // Conversation 식별자 생성 (srcIP:srcPort-dstIP:dstPort)
    std::ostringstream conversationKeyStream;
    if (protocol == IPPROTO_TCP) {
        const struct tcphdr *tcpHeader = reinterpret_cast<const struct tcphdr*>(packet + sizeof(struct ether_header) + sizeof(struct ip));
        conversationKeyStream << inet_ntoa(ipHeader->ip_src) << ":" << ntohs(tcpHeader->th_sport) << "-"
                              << inet_ntoa(ipHeader->ip_dst) << ":" << ntohs(tcpHeader->th_dport);
    } else if (protocol == IPPROTO_UDP) {
        const struct udphdr *udpHeader = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ether_header) + sizeof(struct ip));
        conversationKeyStream << inet_ntoa(ipHeader->ip_src) << ":" << ntohs(udpHeader->uh_sport) << "-"
                              << inet_ntoa(ipHeader->ip_dst) << ":" << ntohs(udpHeader->uh_dport);
    }

    std::string conversationKey = conversationKeyStream.str();

    // Conversation별 통계 업데이트
    conversationStatsMap[conversationKey].src.packets++;
    conversationStatsMap[conversationKey].src.bytes += header->len;
    conversationStatsMap[conversationKey].dst.packets++;
    conversationStatsMap[conversationKey].dst.bytes += header->len;
}

void printStats() {
    std::cout << "MAC Statistics:\n";
    for (const auto &entry : macStatsMap) {
        std::cout << "MAC Address: " << entry.first
                  << ", Packets: " << entry.second.packets
                  << ", Bytes: " << entry.second.bytes << std::endl;
    }

    std::cout << "\nConversation Statistics:\n";
    for (const auto &entry : conversationStatsMap) {
        std::cout << "Conversation: " << entry.first
                  << ", Src Packets: " << entry.second.src.packets
                  << ", Src Bytes: " << entry.second.src.bytes
                  << ", Dst Packets: " << entry.second.dst.packets
                  << ", Dst Bytes: " << entry.second.dst.bytes << std::endl;
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

