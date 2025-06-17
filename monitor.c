#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <time.h>

#define BUFFER_SIZE 2048

void get_datetime(char *buffer, int len) {
	time_t now = time(NULL);
	struct tm *t = localtime(&now);
	strftime(buffer, len, "%Y-%m-%d %H:%M:%S", t);
}

int main() {
	int fd;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	unsigned char buffer[BUFFER_SIZE];
	unsigned long int contador = 0;

	unsigned char mac_dst[6], mac_src[6];
	unsigned short ethertype;
	//unsigned char *data;

	// Abre CSV da camada 2
	FILE *log_camada2 = fopen("camada2.csv", "a");
	if (!log_camada2) {
		perror("Erro ao abrir camada2.csv");
		exit(1);
	}

	// Cabeçalho do CSV
	fprintf(log_camada2, "DataHora,MAC_Origem,MAC_Destino,EtherType,Tamanho\n");
	fflush(log_camada2);

	// Cria socket RAW
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("Erro ao criar socket RAW");
		exit(1);
	}

	// Associa à interface tun0
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("Erro ao obter índice da interface");
		exit(1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_protocol = htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("Erro ao fazer bind");
		exit(1);
	}

	printf("Monitorando tráfego na interface tun0 (Camada 2)...\n");

	while (1) {
		ssize_t bytes_recebidos = recvfrom(fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
		if (bytes_recebidos < 0) {
			perror("Erro ao capturar pacote");
			close(fd);
			exit(1);
		}

		// Interpreta cabeçalho Ethernet
		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer + sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype, buffer + sizeof(mac_dst) + sizeof(mac_src), sizeof(ethertype));
		ethertype = ntohs(ethertype);
		//data = (buffer + sizeof(mac_dst) + sizeof(mac_src) + sizeof(ethertype));

		// Data e hora
		char datahora[64];
		get_datetime(datahora, sizeof(datahora));

		// Salva no CSV
		fprintf(log_camada2, "%s,%02x:%02x:%02x:%02x:%02x:%02x,%02x:%02x:%02x:%02x:%02x:%02x,0x%04x,%ld\n",
				datahora,
				mac_src[0], mac_src[1], mac_src[2],
				mac_src[3], mac_src[4], mac_src[5],
				mac_dst[0], mac_dst[1], mac_dst[2],
				mac_dst[3], mac_dst[4], mac_dst[5],
				ethertype,
				bytes_recebidos);
		fflush(log_camada2);

		contador++;
		printf("\rQuadros capturados: %lu", contador);
        fflush(stdout);
	}

	close(fd);
	fclose(log_camada2);
	return 0;
}