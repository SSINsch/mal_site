#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF  0xFFFF
#define MAX_LEN 100

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

int main(int argc, char **argv){
	HANDLE handle;          // WinDivert handle
	WINDIVERT_ADDRESS addr; // Packet address
	char packet[MAXBUF];    // Packet buffer
	UINT packetLen;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_TCPHDR tcp_header;
	char* data, *host, *hostend;
	char target[MAX_LEN] = {0, }, temp[MAX_LEN] = { 0, };
	int flag = 0;

	int i = 0;
	FILE *fpread, *fpwrite;
	
	handle = WinDivertOpen("(tcp.DstPort == 80 or tcp.SrcPort == 80)", 0, 0, 0);   // Open some filter
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	// Main capture-modify-inject loop:
	while (TRUE) {
		flag = 0;
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packetLen)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		// if http, find the URL
		ip_header = (PWINDIVERT_IPHDR)packet;
		tcp_header = (PWINDIVERT_TCPHDR)((char*)ip_header + (ip_header->HdrLength) * 4);
		data = (char*)((char*)tcp_header + (tcp_header->HdrLength) * 4);
		host = strstr(data, "Host: ");
		if (host != NULL) {
			host = host + strlen("Host: ");
			hostend = strstr(host, "\r\n");
			strncpy(target, host, MAX_LEN - 1);
			target[strlen(host) - strlen(hostend)] = '\0';
			fpread = fopen("site.txt", "r");
			fpwrite = fopen("log.txt", "a+");

			// is the site user entered malicioud site?
			while ( !feof(fpread) ) {
				fscanf(fpread, "%s\n", temp);
				if (strncmp(target, temp, strlen(target)) == 0) {
					fprintf(fpwrite, "*** MALICIOUS SITE ENTERED ***\n");
					fprintf(fpwrite, "SITE_URL: %s\n\n", temp);
					flag = 1;
					break;
				}
			}

			fclose(fpwrite);
			fclose(fpread);
		}
		if (flag == 0) {
			if (!WinDivertSend(handle, packet, packetLen, &addr, NULL)) {
				fprintf(stderr, "warning: failed to send packet\n");
				continue;
			}
		}
	}
	WinDivertClose(handle);
}
