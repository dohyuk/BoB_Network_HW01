
#include "pcap.h"

#include <stdio.h>
#include <winsock2.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )

#define FILTER_RULE "host 165.246.12.215 and port 7778"

struct ether_addr
{
	unsigned char ether_addr_octet[6];
};

struct ether_header
{
	struct  ether_addr ether_dhost;
	struct  ether_addr ether_shost;
	unsigned short ether_type;
};

struct ip_header
{
	unsigned char ip_header_len : 4;
	struct in_addr ip_srcaddr;
	struct in_addr ip_destaddr;
};

struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned char data_offset : 4;
};

void print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
int print_tcp_header(const unsigned char *data);

int main() 
{
	pcap_if_t *alldevs = NULL;
	pcap_if_t *d;

	char errbuf[PCAP_ERRBUF_SIZE];

	int offset = 0;
	int i;
	int inum = 1;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		printf("dev find failed\n");
		return -1;
	}

	//failure
	if (alldevs == NULL) 
	{
		printf("no devs found\n");
		return -1;
	}

	// device information
	for (d = alldevs, i = 0; d != NULL; d = d->next)
	{
		printf("%d-th dev: %s ", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	for (d = alldevs, i = 0; i<inum - 1; d = d->next, i++);

															
	pcap_t  *fp;
	struct pcap_pkthdr *header;
	const unsigned char *pkt_data;
	int res;

	if ((fp = pcap_open_live(d->name, 65536, 1, 20, errbuf)) == NULL) 
	{
		printf("pcap open failed\n");
		return -1;
	}


	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) 
	{
		if (res == 0)
			continue;

		print_ether_header(pkt_data);   // ethernet 출력 
		pkt_data = pkt_data + 14;       // pkt_data의 14번지까지 ethernet

		offset = print_ip_header(pkt_data);     // ip 출력
		pkt_data = pkt_data + offset;           // ip_header의 길이만큼 offset

		offset = print_tcp_header(pkt_data);    // tcp 출력
		pkt_data = pkt_data + offset;           //print_tcp_header *4 위치로 offset
		break;
	}

	return 0;

}

void print_ether_header(const unsigned char *data)
{
	struct  ether_header *eh;               // 이더넷 헤더 구조체
	unsigned short ether_type;
	eh = (struct ether_header *)data;       // 받아온 로우 데이터를 이더넷 헤더구조체 형태로 사용
	ether_type = ntohs(eh->ether_type);       // 숫자는 네트워크 바이트 순서에서 호스트 바이트 순서로 바꿔야함

	if (ether_type != 0x0800)
	{
		printf("ether type wrong\n");
		return;
	}
	// 이더넷 헤더 출력
	printf("\n============ETHERNET HEADER==========\n");
	printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
		eh->ether_dhost.ether_addr_octet[0],
		eh->ether_dhost.ether_addr_octet[1],
		eh->ether_dhost.ether_addr_octet[2],
		eh->ether_dhost.ether_addr_octet[3],
		eh->ether_dhost.ether_addr_octet[4],
		eh->ether_dhost.ether_addr_octet[5]);
	printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
		eh->ether_shost.ether_addr_octet[0],
		eh->ether_shost.ether_addr_octet[1],
		eh->ether_shost.ether_addr_octet[2],
		eh->ether_shost.ether_addr_octet[3],
		eh->ether_shost.ether_addr_octet[4],
		eh->ether_shost.ether_addr_octet[5]);
}

int print_ip_header(const unsigned char *data)
{
	struct  ip_header *ih;
	ih = (struct ip_header *)data;  // 마찬가지로 ip_header의 구조체 형태로 변환

	printf("\n============IP HEADER============\n");
	printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr));
	printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr));

	// return to ip header size
	return ih->ip_header_len * 4;
}

int print_tcp_header(const unsigned char *data)
{
	struct  tcp_header *th;
	th = (struct tcp_header *)data;

	printf("\n============TCP HEADER============\n");
	printf("Src Port Num : %d\n", ntohs(th->source_port));
	printf("Dest Port Num : %d\n", ntohs(th->dest_port));

	// return to tcp header size
	return th->data_offset * 4;
}






