#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

#define PACKET_SIZE 64

// 체크섬 계산
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    for (; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int main() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr); // 대상 IP

    // 패킷 준비
    char packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));
    struct icmphdr *icmp = (struct icmphdr *)packet;

    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;
    icmp->checksum = checksum(icmp, sizeof(packet));

    // 전송
    ssize_t sent = sendto(sock, packet, sizeof(packet), 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        return 1;
    }

    printf("ICMP Echo Request sent to 8.8.8.8\n");

    // 수신 대기
    char recv_buf[1024];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);

    ssize_t received = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                                (struct sockaddr *)&recv_addr, &addr_len);
    if (received < 0) {
        perror("recvfrom");
    } else {
        struct iphdr *ip = (struct iphdr *)recv_buf;
        //recv_buf의 시작 주소에 IP 헤더 길이만큼 더하면, 바로 뒤에 오는 ICMP 헤더의 시작 위치가 됩니다.
        struct icmphdr *icmp_resp = (struct icmphdr *)(recv_buf + (ip->ihl << 2));

        if (icmp_resp->type == ICMP_ECHOREPLY)
            printf("ICMP Echo Reply received from %s\n", inet_ntoa(recv_addr.sin_addr));
        else
            printf("Received ICMP type: %d\n", icmp_resp->type);
    }

    close(sock);
    return 0;
}
