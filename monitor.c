#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define BUFFER_SIZE 65536

int main() {
    int raw_socket;
    struct ifreq ifr;
    char buffer[BUFFER_SIZE];

    // Cria o raw socket
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("Erro ao criar socket");
        exit(1);
    }

    // Associa o socket à interface tun0
    strcpy(ifr.ifr_name, "tun0");
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0) {
        perror("Erro ao obter índice da interface");
        exit(1);
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(raw_socket, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Erro ao fazer bind no socket");
        exit(1);
    }

    printf("Monitor de tráfego iniciado na interface tun0...\n");

    // Loop para capturar pacotes
    while (1) {
        ssize_t num_bytes = recvfrom(raw_socket, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (num_bytes < 0) {
            perror("Erro ao receber pacote");
            exit(1);
        }

        printf("Pacote capturado: %ld bytes\n", num_bytes);
    }

    close(raw_socket);
    return 0;
}