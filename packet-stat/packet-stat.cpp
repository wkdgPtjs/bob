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

struct IPStats {
    unsigned int sendPackets = 0;
    unsigned int receivePackets = 0;
    unsigned int sendBytes = 0;
    unsigned int receiveBytes = 0;
};

std::map<std::string, IPStats> ipStatsMap;

// MAC 주소를 문자열로 변환
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
    const struct ip *ipHeader = (const struct ip *)(packet + sizeof(struct ether_header));
    std::string srcIP = inet_ntoa(ipHeader->ip_src);
    std::string dstIP = inet_ntoa(ipHeader->ip_dst);
    unsigned int bytes = header->len;

    ipStatsMap[srcIP].sendPackets++;
    ipStatsMap[srcIP].sendBytes += bytes;

    ipStatsMap[dstIP].receivePackets++;
    ipStatsMap[dstIP].receiveBytes += bytes;
}

void printStats() {
    std::cout << "IPv4 Statistics:\n";
    for (const auto &entry : ipStatsMap) {
        std::cout << "IP Address: " << entry.first
                  << ", Send Packets: " << entry.second.sendPackets
                  << ", Receive Packets: " << entry.second.receivePackets
                  << ", Send Bytes: " << entry.second.sendBytes
                  << ", Receive Bytes: " << entry.second.receiveBytes << std::endl;
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

