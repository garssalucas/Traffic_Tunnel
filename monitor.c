#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <time.h>

#define BUFFER_SIZE 2048

// Função para obter data e hora atual
void get_datetime(char *buffer, int len)
{
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	strftime(buffer, len, "%Y-%m-%d %H:%M:%S", t);
}

int main()
{
	int fd;							   // Socket RAW
	struct ifreq ifr;				   // Interface
	struct sockaddr_ll sa;			   // Endereço da interface
	unsigned char buffer[BUFFER_SIZE]; // Buffer para armazenar pacotes

	// Contadores
	unsigned long int total = 0;
	unsigned long int cont_ipv4 = 0;
	unsigned long int cont_tcp = 0;
	unsigned long int cont_udp = 0;
	unsigned long int cont_icmp = 0;
	unsigned long int cont_outros = 0;

	unsigned char mac_dst[6], mac_src[6];
	unsigned short  int ethertype;				 

	// Abre CSVs
	FILE *log_camada2 = fopen("camada2.csv", "a");
	FILE *log_camada3 = fopen("camada3.csv", "a");
	FILE *log_camada4 = fopen("camada4.csv", "a");

	if (!log_camada2 || !log_camada3 || !log_camada4)
	{
		perror("Erro ao abrir arquivos CSV");
		exit(1);
	}

	// Cabeçalhos dos CSVs
	fprintf(log_camada2, "DataHora ; MAC_Origem ; MAC_Destino ; EtherType ; Tamanho\n");
	fprintf(log_camada3, "DataHora ; Protocolo ; IP_Origem ; IP_Destino ; Protocolo_Camada4 ; Tamanho\n");
	fprintf(log_camada4, "DataHora ; Protocolo ; IP_Origem ; Porta_Origem ; IP_Destino ; Porta_Destino ; Tamanho\n");

	fflush(log_camada2);
	fflush(log_camada3);
	fflush(log_camada4);

	// Cria socket RAW
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
	{
		perror("Erro ao criar socket RAW");
		exit(1);
	}

	// Configura interface tun0
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("Erro ao obter índice da interface");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_protocol = htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
		perror("Erro ao fazer bind");
		exit(1);
	}

	printf("Monitorando tráfego na interface tun0...\n");

	while (1)
	{
		ssize_t bytes_recebidos = recvfrom(fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
		if (bytes_recebidos < 0)
		{
			perror("Erro ao capturar pacote");
			close(fd);
			exit(1);
		}

		// Data e hora
		char datahora[64];
		get_datetime(datahora, sizeof(datahora));

		// Copia o conteudo do cabecalho Ethernet 
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(ethertype));
		ethertype = ntohs(ethertype);

		// Camada 2
		fprintf(log_camada2, "%s ; %02x:%02x:%02x:%02x:%02x:%02x ; %02x:%02x:%02x:%02x:%02x:%02x ; 0x%04x ; %ld\n",
				datahora,
				mac_src[0], mac_src[1], mac_src[2],
				mac_src[3], mac_src[4], mac_src[5],
				mac_dst[0], mac_dst[1], mac_dst[2],
				mac_dst[3], mac_dst[4], mac_dst[5],
				ethertype,
				bytes_recebidos);
		fflush(log_camada2);

		total++;

		// Interpreta como IP diretamente (pois tun0 começa no cabeçalho IP)
		struct iphdr *ip = (struct iphdr *)(buffer);

		char ip_src[INET_ADDRSTRLEN];
		char ip_dst[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &(ip->saddr), ip_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip->daddr), ip_dst, INET_ADDRSTRLEN);

		char protocolo_camada4[10] = "-";

		switch (ip->protocol)
		{
		case 1:
			cont_icmp++;
			strcpy(protocolo_camada4, "ICMP");
			break;
		case 6:
			cont_tcp++;
			strcpy(protocolo_camada4, "TCP");
			break;
		case 17:
			cont_udp++;
			strcpy(protocolo_camada4, "UDP");
			break;
		default:
			cont_outros++;
			strcpy(protocolo_camada4, "OUTRO");
			break;
		}

		cont_ipv4++; // Todo pacote capturado na tun0 é IPv4

		// Camada 3 - log CSV
		fprintf(log_camada3, "%s ; IPv4 ; %s ; %s ; %s ; %ld\n",
				datahora, ip_src, ip_dst, protocolo_camada4, bytes_recebidos);
		fflush(log_camada3);

		// Camada 4 - se for TCP ou UDP
		if (ip->protocol == 6)
		{ // TCP
			struct tcphdr *tcp = (struct tcphdr *)(buffer + ip->ihl * 4);
			fprintf(log_camada4, "%s ; TCP ; %s ; %u ; %s ; %u ; %ld\n",
					datahora,
					ip_src, ntohs(tcp->source),
					ip_dst, ntohs(tcp->dest),
					bytes_recebidos);
			fflush(log_camada4);
		}
		else if (ip->protocol == 17)
		{ // UDP
			struct udphdr *udp = (struct udphdr *)(buffer + ip->ihl * 4);
			fprintf(log_camada4, "%s ; UDP ; %s ; %u ; %s ; %u ; %ld\n",
					datahora,
					ip_src, ntohs(udp->source),
					ip_dst, ntohs(udp->dest),
					bytes_recebidos);
			fflush(log_camada4);
		}

		// Interface modo texto com contadores
		printf("\rTotal:%lu | IPv4:%lu | TCP:%lu | UDP:%lu | ICMP:%lu | Outros:%lu",
			   total, cont_ipv4, cont_tcp, cont_udp, cont_icmp, cont_outros);
		fflush(stdout);
	}

	close(fd);
	fclose(log_camada2);
	fclose(log_camada3);
	fclose(log_camada4);
	return 0;
}