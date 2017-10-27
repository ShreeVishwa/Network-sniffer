#include <time.h>
#include <math.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
#define ETHERTYPE_ARP 0x0806

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

struct sniff_arp {
	// struct	arphdr ea_hdr;
	u_char	arp_sha[6];	/* sender hardware address */
	u_char	arp_spa[4];	/* sender protocol address */
	u_char	arp_tha[6];	/* target hardware address */
	u_char	arp_tpa[4];
	u_char hlen;        /* Hardware Address Length */ 
    u_char plen;
};

struct arphdr {
	uint16_t ar_hrd;	
	uint16_t ar_pro;	
	uint8_t ar_hln;	
	uint8_t ar_pln;	
	uint16_t ar_op;
};

struct sniff_icmp
{
  u_int8_t type;		/* message type */
  u_int8_t code;		/* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t	id;
      u_int16_t	sequence;
    } echo;			/* echo datagram */
    u_int32_t	gateway;	/* gateway address */
    struct
    {
      u_int16_t	__unused;
      u_int16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

// #define	arp_hrd	ea_hdr.ar_hrd
// #define	arp_hln	ea_hdr.ar_hln

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_app_banner(void);

void
print_app_usage(void);

void
print_tcp(const u_char *packet,const struct sniff_ip *ip,int size_ip,u_char *args,const struct sniff_ethernet *ethernet, int size, const struct pcap_pkthdr *header);

void
print_udp(const u_char *packet,const struct sniff_ip *ip,int size_ip,u_char *args,const struct sniff_ethernet *ethernet, int size, const struct pcap_pkthdr *header);

void
print_icmp(const u_char *packet,const struct sniff_ip *ip,int size_ip,u_char *args,const struct sniff_ethernet *ethernet, int size, const struct pcap_pkthdr *header);

void
print_arp(const u_char *packet,u_char *args,const struct sniff_ethernet *ethernet,int size, const struct pcap_pkthdr *header);

const u_char*
substr(const u_char* payload, int size_payload, u_char* args);


void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

const u_char*
substr(const u_char* payload, int size_payload, u_char* args){
	int len = 0;
	while(len < size_payload){
		const char* text = payload;
		char* pat = args;
		while(*pat && *payload==*pat){
			pat++;
			payload++;
		}
		if(!*pat) return text;
		payload = text+1;
		len++;
	}
	return NULL;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	int size_ip;
	
	
	

	int size = header->len;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

	size_ip = IP_HL(ip)*4;

	if(ntohs(ethernet->ether_type) == ETHERTYPE_ARP){

		print_arp(packet,args,ethernet,size,header);

	}

	else{
	
		switch(ip->ip_p) {
			case IPPROTO_TCP:
				print_tcp(packet,ip,size_ip,args,ethernet,size,header);
				break;
			case IPPROTO_UDP:
				print_udp(packet,ip,size_ip,args,ethernet,size,header);
				return;
			case IPPROTO_ICMP:
				print_icmp(packet,ip,size_ip,args,ethernet,size,header);
				return;
			case IPPROTO_IP:
				printf("Unknown Packet\n");
				return;
			default:
				printf("Unknown Packet\n");
				return;
		}

	}

return;
}

void
print_arp(const u_char *packet,u_char *args,const struct sniff_ethernet *ethernet,int size, const struct pcap_pkthdr *header){

	const char *payload;
    int size_payload;
    char buffer[26];
	struct tm* time;
	const struct sniff_arp *arp;

	arp = (struct sniff_arp *) (packet + SIZE_ETHERNET);

	if(args!=NULL){
		if(substr(payload,size_payload,args) != NULL){

			printf("Ethernet type : %#x\n",ntohs(ethernet->ether_type));
			// printf("Hello : %x\n",ntohs(ethernet->ether_type));
			printf("Length of the packet %d\n",size);
			time = localtime(&header->ts.tv_sec);
			strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
			printf("%s.%06d ",buffer,((int)(header->ts.tv_usec)));
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
			printf("type %#x ",ntohs(ethernet->ether_type));
			printf("len %d\n",size);
			printf("ARP\n");
			
			payload = (u_char *)(packet + SIZE_ETHERNET + sizeof arp);
			// printf("%d\n",ntohs(arp->hlen));
			size_payload = size - (SIZE_ETHERNET);
			// printf("%d\n",ntohs(arp->hlen + arp->plen));
			print_payload(payload, size_payload);

		}
	}

	else{

		printf("Ethernet type : %#x\n",ntohs(ethernet->ether_type));
		// printf("Hello : %x\n",ntohs(ethernet->ether_type));
		printf("Length of the packet %d\n",size);
		time = localtime(&header->ts.tv_sec);
		strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
		printf("%s.%06d ",buffer,((int)(header->ts.tv_usec)));
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
		printf("type %#x ",ntohs(ethernet->ether_type));
		printf("len %d\n",size);
		printf("ARP\n");
		
		payload = (u_char *)(packet + SIZE_ETHERNET + sizeof arp);
		// printf("%d\n",ntohs(arp->hlen));
		size_payload = size - (SIZE_ETHERNET);
		// printf("%d\n",ntohs(arp->hlen + arp->plen));
		print_payload(payload, size_payload);

	}
	
	
	

}

void
print_tcp(const u_char *packet,const struct sniff_ip *ip,int size_ip,u_char *args,const struct sniff_ethernet *ethernet, int size, const struct pcap_pkthdr *header){

	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	int size_tcp;
    int size_payload;
    char buffer[26];
	struct tm* time;
	struct timeval tv;
	time_t nowtime;

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if(args != NULL){
		if(substr(payload,size_payload,args) != NULL){

			
			// printf("Hello : %x\n",ntohs(ethernet->ether_type));
			time = localtime(&header->ts.tv_sec);
			strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
			printf("%s.%06d ",buffer,((int)(header->ts.tv_usec)));
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
			printf("type %#x ",ntohs(ethernet->ether_type));
			printf("len %d\n",size);
			if (size_tcp < 20) {
				printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			printf("%s:", inet_ntoa(ip->ip_src));
			printf("%d -> ", ntohs(tcp->th_sport));
			printf("%s:", inet_ntoa(ip->ip_dst));
			printf("%d ", ntohs(tcp->th_dport));
			printf("TCP\n");
			
			if (size_payload > 0) {
				print_payload(payload, size_payload);
			}
		}
	}

	else{
		
		time = localtime(&header->ts.tv_sec);
		strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
		printf("%s.%06d ",buffer,((int)(header->ts.tv_usec)));
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
		printf("type %#x ",ntohs(ethernet->ether_type));
		printf("len %d\n",size);
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}

		printf("%s:", inet_ntoa(ip->ip_src));
		printf("%d -> ", ntohs(tcp->th_sport));
		printf("%s:", inet_ntoa(ip->ip_dst));
		printf("%d ", ntohs(tcp->th_dport));
		printf("TCP\n");
		
		if (size_payload > 0) {
			print_payload(payload, size_payload);
		}
	}
    
    
	
	
	/* define/compute tcp payload (segment) offset */
	
	
	
	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	
}

void
print_udp(const u_char *packet,const struct sniff_ip *ip,int size_ip,u_char *args,const struct sniff_ethernet *ethernet, int size, const struct pcap_pkthdr *header){

    const struct sniff_udp *udp;            /* The TCP header */
    const char *payload;
    int size_udp;
	int size_payload;
    char buffer[26];
    struct tm* time;

	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof udp);
	size_payload = ntohs(ip->ip_len) - (size_ip + sizeof udp);

	if(args != NULL){
		if(substr(payload,size_payload,args) != NULL){
			
			
			// printf("Hello : %x\n",ntohs(ethernet->ether_type));
			
			time = localtime(&header->ts.tv_sec);
			strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
			printf("%s.%06d ",buffer,((int)(header->ts.tv_usec)));
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
			printf("type %#x ",ntohs(ethernet->ether_type));
			printf("len %d\n",size);

			printf("%s:", inet_ntoa(ip->ip_src));
			printf("%d -> ", ntohs(udp->uh_sport));
			printf("%s:", inet_ntoa(ip->ip_dst));
			printf("%d ", ntohs(udp->uh_dport));
			printf("UDP\n");
			
			if (size_payload > 0) {
				print_payload(payload, size_payload);
			}
		}
	}

	else{
		
		time = localtime(&header->ts.tv_sec);
		strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
		printf("%s.%06d ",buffer,((int)(header->ts.tv_usec)));
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
		printf("type %#x ",ntohs(ethernet->ether_type));
		printf("len %d\n",size);

		printf("%s:", inet_ntoa(ip->ip_src));
		printf("%d -> ", ntohs(udp->uh_sport));
		printf("%s:", inet_ntoa(ip->ip_dst));
		printf("%d ", ntohs(udp->uh_dport));
		printf("UDP\n");
		
		if (size_payload > 0) {
			print_payload(payload, size_payload);
		}

	}
    
    

}

void
print_icmp(const u_char *packet,const struct sniff_ip *ip,int size_ip,u_char *args,const struct sniff_ethernet *ethernet, int size, const struct pcap_pkthdr *header){

	const struct sniff_icmp *icmp;            /* The TCP header */
    const char *payload;
    int size_icmp;
	int size_payload;
	char buffer[26];
    struct tm* time;

	icmp = (struct sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);

	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + sizeof icmp);
	size_payload = size - (size_ip + SIZE_ETHERNET);
	
	if(args != NULL){
		if(substr(payload,size_payload,args) != NULL){

			// printf("Hello : %x\n",ntohs(ethernet->ether_type));
			
			time = localtime(&header->ts.tv_sec);
			strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
			printf("%s.%06d\n",buffer,((int)(header->ts.tv_usec)));
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
			printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
			printf("type %#x ",ntohs(ethernet->ether_type));
			printf("len %d\n",size);

			printf("%s -> ", inet_ntoa(ip->ip_src));
			printf("%s ", inet_ntoa(ip->ip_dst));
			printf("ICMP\n");
			
			if (size_payload > 0) {
				print_payload(payload, size_payload);
			}
		}
	}

	else{
		
		time = localtime(&header->ts.tv_sec);
		strftime(buffer,26,"%Y-%m-%d %H:%M:%S", time);
		printf("%s.%06d ",buffer,((int)(header->ts.tv_usec)));
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> ", ethernet->ether_shost[0] , ethernet->ether_shost[1] , ethernet->ether_shost[2] , ethernet->ether_shost[3] , ethernet->ether_shost[4] , ethernet->ether_shost[5]);
		printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X ", ethernet->ether_dhost[0] , ethernet->ether_dhost[1] , ethernet->ether_dhost[2] , ethernet->ether_dhost[3] , ethernet->ether_dhost[4] , ethernet->ether_dhost[5]);
		printf("type %#x ",ntohs(ethernet->ether_type));
		printf("len %d\n",size);

		printf("%s -> ", inet_ntoa(ip->ip_src));
		printf("%s ", inet_ntoa(ip->ip_dst));
		printf("ICMP\n");
		
		if (size_payload > 0) {
			print_payload(payload, size_payload);
		}

	}
}

int main(int argc, char **argv)
{
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char* filter_exp;		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10;
	char *dev = NULL;
	char *dev1 = NULL;
	char *file = NULL;
	char *str = NULL;
	int c;
	int i = 0;			

	while ((c = getopt (argc, argv, "i:r:s:")) != -1)
    {
        switch (c)
        {
		case 'i':
			dev1 = optarg;
            break;
		case 'r':
			file = optarg;
            break;
        case 's':
			str = optarg;
            break;
        }
	}

	if(dev1 != NULL && file != NULL){
		printf("Please enter either i flag or r flag them but not both\n");
		exit(EXIT_FAILURE);
	}
	
	if(file == NULL){
		if(dev1 == NULL){
			dev = pcap_lookupdev(errbuf);
			if (dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n",
					errbuf);
				exit(EXIT_FAILURE);
			}
		}
		else{
			dev = dev1;
		}
	
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
				dev, errbuf);
			net = 0;
			mask = 0;
		}
	
	
		handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
		}
	
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}
	
		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}

		if(argv[optind] != NULL){
			if (pcap_compile(handle, &fp, argv[optind], 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
		}
	
		else{
			if (pcap_compile(handle, &fp, NULL, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
		}
	
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}

	else{
		handle = pcap_open_offline(argv[2], errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open file: %s\n", errbuf);
			return 1;
		}

		if(argv[optind] != NULL){
			if (pcap_compile(handle, &fp, argv[optind], 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
		}
	
		else{
			if (pcap_compile(handle, &fp, NULL, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
				exit(EXIT_FAILURE);
			}
		}
	
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}

	if(str == NULL){
		pcap_loop(handle, 0, got_packet, NULL);
	}
	else{
		pcap_loop(handle, 0, got_packet, str);
	}

	
	
		/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);
	
	printf("\nCapture complete.\n");
	

return 0;
}
