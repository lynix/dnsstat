/* Copyright 2017, 2019, 2021 Alexander Koch <mail@alexanderkoch.net>
 *
 * This file is part of 'dnsstat'. 'dnsstat' is distributed under the terms of
 * the MIT License, see file LICENSE.
 */

#include <arpa/inet.h>
#include <float.h>
#include <math.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ETH_TYPE_OFFS       12
#define IP4_TYPE_OFFS       23
#define IP6_TYPE_OFFS       20
#define IP_TYPE_UDP         0x11
#define IP4_UDP_PORT_OFFS_SRC   34
#define IP6_UDP_PORT_OFFS_SRC   54
#define IP4_UDP_PORT_OFFS_DST   36
#define IP6_UDP_PORT_OFFS_DST   56
#define IP4_UDP_PAYLOAD_OFFS    42
#define IP6_UDP_PAYLOAD_OFFS    62
#define DNS_QUERY_TYPE_OFFS 44
#define DNS_NAME_OFFS       12
#define PORT_DNS            53
#define DNS_MAX_LEN         512

#define DNS_FLAGS_QR(x) ((ntohs(x) & 0x8000) >> 7)

typedef enum {
    QUERY_A    = 0x0001,
    QUERY_PTR  = 0x000c,
    QUERY_TXT  = 0x0010,
    QUERY_AAAA = 0x001c,
    QUERY_SRV  = 0x0021
} query_type_t;

struct qlist {
    uint16_t        id;
    struct timeval  time;
    query_type_t    type;
    char            *name;
    double          delay_ms;
    struct qlist    *prev;
};
typedef struct qlist qlist_t;

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed)) dns_header_t;

static const uint8_t ETH_TYPE_IPV4[] = { 0x08, 0x00 };
static const uint8_t ETH_TYPE_IPV6[] = { 0x86, 0xdd };

qlist_t *list = NULL;
uint64_t num_queries = 0;
uint64_t num_replies = 0;
double min = DBL_MAX;
double max = -1;

void err_exit(const char *format, ...)
{
    fprintf(stderr, "Error: ");

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    fflush(stderr);
    va_end(args);

    exit(EXIT_FAILURE);
}

static inline qlist_t *find_query(uint16_t id)
{
    for (qlist_t *p = list; p != NULL; p = p->prev)
        if (p->id == id && p->delay_ms == -1)
            return p;

    return NULL;
}

void dns_decode_name_type(qlist_t *entry, const unsigned char *src)
{
    char *name = malloc(DNS_MAX_LEN);
    if (name == NULL)
        err_exit("out of memory allocating name buffer");

    const unsigned char *p = src;
    char *pname = name;
    while (*p != '\0') {
        int len = *p;
        memcpy(pname, p+1, len);
        pname[len] = '.';
        pname += len + 1;
        p += len + 1;
    }
    *(pname-1) = '\0';
    entry->name = name;

    entry->type = ntohs(*(uint16_t *)(p + 1));
}

static inline const char *dns_qtypestr(query_type_t type)
{
    if (type == QUERY_A)
        return "A";
    if (type == QUERY_AAAA)
        return "AAAA";
    if (type == QUERY_PTR)
        return "PTR";
    if (type == QUERY_SRV)
        return "SRV";
    if (type == QUERY_TXT)
        return "TXT";

    return "???";
}

void pkg_handler(u_char *unused, const struct pcap_pkthdr *pkg_hdr,
                 const u_char *pkg_data)
{
    uint8_t ip_type_offs = IP4_TYPE_OFFS;
    uint8_t udp_port_offs_src = IP4_UDP_PORT_OFFS_SRC;
    uint8_t udp_port_offs_dst = IP4_UDP_PORT_OFFS_DST;
    uint8_t udp_payload_offs = IP4_UDP_PAYLOAD_OFFS;
    if (memcmp(pkg_data + ETH_TYPE_OFFS, ETH_TYPE_IPV6, sizeof(ETH_TYPE_IPV6)) == 0) {
       ip_type_offs = IP6_TYPE_OFFS;
       udp_port_offs_src = IP6_UDP_PORT_OFFS_SRC;
       udp_port_offs_dst = IP6_UDP_PORT_OFFS_DST;
       udp_payload_offs = IP6_UDP_PAYLOAD_OFFS;
    } else if (memcmp(pkg_data + ETH_TYPE_OFFS, ETH_TYPE_IPV4, sizeof(ETH_TYPE_IPV4)) != 0) {
        // SKIP non-IPv6 non-IPv4 packets
        return;
    }

    // skip non-UDP packets
    if (pkg_data[ip_type_offs] != IP_TYPE_UDP)
        return;

    // skip non-DNS packets
    if (ntohs(*(uint16_t *)(pkg_data + udp_port_offs_src)) != PORT_DNS)
        if (ntohs(*(uint16_t *)(pkg_data + udp_port_offs_dst)) != PORT_DNS)
            return;

    // skip truncated packets
    if (pkg_hdr->caplen <= udp_payload_offs + DNS_NAME_OFFS) {
        fprintf(stderr, "warning: skipping truncated package (%u captured, "\
                "%u on wire)\n", pkg_hdr->caplen, pkg_hdr->len);
        return;
    }

    dns_header_t *header = (dns_header_t *)(pkg_data + udp_payload_offs);

    // skip multi-query messages
    if  (DNS_FLAGS_QR(header->flags) == 0 && ntohs(header->qdcount) != 1) {
        fprintf(stderr, "warning: skipping unsupported multi-query\n");
        return;
    }

    if (DNS_FLAGS_QR(header->flags) == 0) {

        // DNS query: add to list

        qlist_t *entry = malloc(sizeof(qlist_t));
        if (entry == NULL)
            err_exit("out of memory allocating qlist_t");

        entry->time.tv_sec  = pkg_hdr->ts.tv_sec;
        entry->time.tv_usec = pkg_hdr->ts.tv_usec;
        entry->id           = ntohs(header->id);
        entry->delay_ms     = -1;
        entry->prev         = list;
        dns_decode_name_type(entry, pkg_data + udp_payload_offs + DNS_NAME_OFFS);

        list = entry;
        num_queries++;

    } else {

        // DNS response: find query, update delay and statistics

        qlist_t *p = find_query(ntohs(header->id));
        if (p == NULL) {
            fprintf(stderr, "warning: reply for unknown query (id 0x%04x)\n",
                    ntohs(header->id));
            return;
        }

        double ms_diff = (double)(pkg_hdr->ts.tv_sec - p->time.tv_sec) * 1000.0;
        ms_diff += (double)(pkg_hdr->ts.tv_usec - p->time.tv_usec) / 1000.0;
        p->delay_ms = ms_diff;

        if (ms_diff < min)
            min = ms_diff;
        if (ms_diff > max)
            max = ms_diff;

        num_replies++;
    }
}

static inline void print_help()
{
    puts("Usage: dnsstat [-v] FILE\n");
    puts("Arguments:");
    puts("  FILE  PCAP file to analyze");
    puts("  -v    Dump list of queries captured");
    puts("");
    printf("dnsstat version %s, built %s %s.\n", GIT_VERSION, __DATE__,
           __TIME__);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        err_exit("missing argument(s) (try '-h' for help).");

    if (strcmp(argv[1], "-h") == 0) {
        print_help();
        return EXIT_SUCCESS;
    }

    // open pcap file, process contents
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[argc-1], error_buffer);
    if (handle == NULL)
        err_exit("failed to open '%s': %s", argv[1], error_buffer);
    pcap_loop(handle, 0, pkg_handler, NULL);
    pcap_close(handle);

    if ((num_queries | num_replies) == 0) {
        puts("No DNS packets found in capture.");
        return EXIT_SUCCESS;
    }

    // calculate loss
    uint64_t num_lost = num_queries - num_replies;
    double perc_lost = (double)num_lost / (double)num_queries * 100.0;

    // calculate average delay
    double avg = 0;
    for (qlist_t *p = list; p != NULL; p = p->prev)
        if (p->delay_ms >= 0)
            avg += p->delay_ms;
    avg /= (double)num_replies;

    // calculate delay standard deviation
    double dev = 0;
    for (qlist_t *p = list; p != NULL; p = p->prev)
        if (p->delay_ms >= 0)
            dev += (p->delay_ms - avg) * (p->delay_ms - avg);
    dev /= (double)num_replies - 1.0;
    dev = sqrt(dev);

    // print statistics
    puts("Queries");
    printf("    sent:      %8lu\n", num_queries);
    printf("    answered:  %8lu\n", num_replies);
    printf("    lost:      %8lu (%.2f%%)\n", num_lost, perc_lost);
    puts("Delay");
    printf("    min:       %8.2f ms\n", min);
    printf("    avg:       %8.2f ms\n", avg);
    printf("    max:       %8.2f ms\n", max);
    printf("    stdev:     %8.2f ms\n", dev);

    // dump query list if requested
    if (strcmp(argv[1], "-v") == 0) {
        puts("");
        for (qlist_t *p = list; p != NULL; p = p->prev) {
            printf("%04x", p->id);
            if (p->delay_ms > 0)
                printf("  %7.2fms", p->delay_ms);
            else
                printf("        -  ");
            printf("  %4s  %s\n", dns_qtypestr(p->type), p->name);
        }
    }

    // clean-up
    for (qlist_t *p = list; p != NULL; ) {
        qlist_t *prev = p->prev;
        free(p->name);
        free(p);
        p = prev;
    }

    return EXIT_SUCCESS;
}
