// Made by Matej Kulisek
#include <iostream>
#include <pcap.h>
#include <ctime>
#include <cstring>
#include <netinet/if_ether.h>  // Ethernet hlavička (L2)
#include <netinet/ip.h>        // IP hlavička (L3)
#include <netinet/tcp.h>       // TCP hlavička (L4)
#include <netinet/udp.h>       // UDP hlavička (L4)
#include <arpa/inet.h>         // inet_ntoa — převod IP na string
#include <map>
#include <string>
#include <csignal>

// Globální statistiky
std::map<std::string, int> protocolCount;
std::map<std::string, int> ipCount;
int totalPackets = 0;
int totalBytes = 0;
pcap_t *globalHandle = nullptr;

// Forward declarations
const char* getServiceName(int port);

void signalHandler(int signum) {
    std::cout << "\n\n========== STATISTIKY ==========" << std::endl;
    std::cout << "Celkem paketu: " << totalPackets << std::endl;
    std::cout << "Celkem dat:    " << totalBytes << " bajtu ("
              << totalBytes / 1024 << " KB)" << std::endl;

    std::cout << "\n--- Protokoly ---" << std::endl;
    for (const auto &pair : protocolCount) {
        std::cout << "  " << pair.first << ": " << pair.second
                  << " paketu" << std::endl;
    }

    std::cout << "\n--- Top IP adresy ---" << std::endl;
    for (const auto &pair : ipCount) {
        if (pair.second > 5) {
            std::cout << "  " << pair.first << ": " << pair.second
                      << " paketu" << std::endl;
        }
    }
    std::cout << "=================================" << std::endl;

    if (globalHandle) pcap_close(globalHandle);
    exit(0);
}

// Forward declaration
void packetHandler(u_char *userData,
                   const struct pcap_pkthdr *header,
                   const u_char *packet);

// Callback funkce — volá se pro KAŽDÝ zachycený paket
void packetHandler(u_char *userData,
                   const struct pcap_pkthdr *header,
                   const u_char *packet) {
    static int count = 0;
    count++;

    // Timestamp
    char timeStr[64];
    time_t rawTime = header->ts.tv_sec;
    struct tm *timeInfo = localtime(&rawTime);
    strftime(timeStr, sizeof(timeStr), "%H:%M:%S", timeInfo);

    // === VRSTVA 2: Ethernet ===
    const struct ether_header *ethHeader;
    ethHeader = (struct ether_header *)packet;

    // Zkontroluj, jestli je to IP paket (0x0800)
    if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP) {
        return;
    }

    // === VRSTVA 3: IP ===
    const struct ip *ipHeader;
    ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

    // Zdrojová a cílová IP adresa
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    strcpy(srcIP, inet_ntoa(ipHeader->ip_src));
    strcpy(dstIP, inet_ntoa(ipHeader->ip_dst));

    // === VRSTVA 4: Protokol ===
    const char *protocol;
    int srcPort = 0, dstPort = 0;

    switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            protocol = "TCP";
            const struct tcphdr *tcpHeader;
            tcpHeader = (struct tcphdr *)(packet
                + sizeof(struct ether_header)
                + (ipHeader->ip_hl * 4));
            srcPort = ntohs(tcpHeader->th_sport);
            dstPort = ntohs(tcpHeader->th_dport);
            break;
        }
        case IPPROTO_UDP: {
            protocol = "UDP";
            const struct udphdr *udpHeader;
            udpHeader = (struct udphdr *)(packet
                + sizeof(struct ether_header)
                + (ipHeader->ip_hl * 4));
            srcPort = ntohs(udpHeader->uh_sport);
            dstPort = ntohs(udpHeader->uh_dport);
            break;
        }
        case IPPROTO_ICMP:
            protocol = "ICMP";
            break;
        default:
            protocol = "OTHER";
            break;
    }

    // Statistiky
    totalPackets++;
    totalBytes += header->len;
    protocolCount[protocol]++;
    ipCount[srcIP]++;
    ipCount[dstIP]++;

    // Výpis s názvem služby
    std::cout << "[" << timeStr << "] "
              << "#" << count << " | "
              << protocol;

    const char *service = getServiceName(dstPort);
    if (!service) service = getServiceName(srcPort);
    if (service) std::cout << " (" << service << ")";

    std::cout << " | "
              << srcIP << ":" << srcPort
              << " -> "
              << dstIP << ":" << dstPort
              << " | " << header->len << "B"
              << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live("en0", 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Nelze otevrit rozhrani: " << errbuf << std::endl;
        return 1;
    }

    globalHandle = handle;
    signal(SIGINT, signalHandler);

    std::cout << "Zachytavam pakety na en0... (Ctrl+C pro statistiky)" << std::endl;
    std::cout << "============================================================" << std::endl;

    pcap_loop(handle, 0, packetHandler, nullptr);
    pcap_close(handle);
    return 0;
}

const char* getServiceName(int port) {
    switch (port) {
        case 80:    return "HTTP";
        case 443:   return "HTTPS";
        case 53:    return "DNS";
        case 22:    return "SSH";
        case 21:    return "FTP";
        case 25:    return "SMTP";
        case 110:   return "POP3";
        case 143:   return "IMAP";
        case 3389:  return "RDP";
        case 67:    case 68:  return "DHCP";
        case 123:   return "NTP";
        case 51820: return "WireGuard";
        default:    return nullptr;
    }
}
