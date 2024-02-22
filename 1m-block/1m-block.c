#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAX_BLOCKED_DOMAINS 1000000

char *blocked_domains[MAX_BLOCKED_DOMAINS];
size_t num_blocked_domains = 0;

u_int32_t print_pkt(struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    return id;
}

// cb 함수 내부의 코드 수정
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
            struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

    unsigned char *payload;
    int payload_len = nfq_get_payload(nfa, &payload);
    struct iphdr *ip_header = (struct iphdr *)payload;
    
    if (ip_header->protocol == 6) { // TCP
        struct tcphdr *tcp_header = (struct tcphdr *)(payload + (ip_header->ihl << 2));
        char *http_payload = (char *)(payload + (ip_header->ihl << 2) + (tcp_header->doff << 2));

        char *host_start = strstr(http_payload, "Host: ");
        if (host_start != NULL) {
            host_start += 6; // Move past "Host: "
            char *host_end = strchr(host_start, '\r'); // Assuming HTTP request ends with '\r'
            if (host_end != NULL) {
                *host_end = '\0'; // Null-terminate the host value
                
                // Check if the extracted host is in the blocked_domains list
                for (size_t i = 0; i < num_blocked_domains; i++) {
                    if (strcmp(host_start, blocked_domains[i]) == 0) {
                        printf("Blocking packet from domain: %s\n", blocked_domains[i]);
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    }
                }
            }
        }
    }
    
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <site list file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        fprintf(stderr, "Error opening file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    while (fgets(line, sizeof(line), file) && num_blocked_domains < MAX_BLOCKED_DOMAINS) {
        char *domain = strchr(line, ',');
        if (domain != NULL) {
            domain++; // Move past the comma
            domain[strcspn(domain, "\r\n")] = '\0'; // Remove newline characters
            
            blocked_domains[num_blocked_domains] = strdup(domain);
            num_blocked_domains++;
        }
    }

    fclose(file);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);
    
    printf("closing library handle\n");
    nfq_close(h);

    // Free memory for blocked domains
    for (size_t i = 0; i < num_blocked_domains; i++) {
        free(blocked_domains[i]);
    }

    exit(0);
}
