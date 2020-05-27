// link with Ws2_32.lib
#pragma comment(lib,"Ws2_32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>   // Needed for _wtoi



USHORT checksum(USHORT *buffer, int size)
{
	unsigned long cksum = 0;
	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size) {
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}
/*****************************************************************/
typedef struct ip_hdr
{
	unsigned char    ip_verlen;
	unsigned char    ip_tos;
	unsigned short   ip_total_len;
	unsigned short   ip_id;
	unsigned short   ip_offset;
	unsigned char    ip_ttl;
	unsigned char    ip_protocol;
	unsigned short   ip_checksum;
	//unsigned int     sourceIP;
	//unsigned int     destIP;
	struct   in_addr ip_src, ip_dst;
}IP_HDR;

typedef struct udp_hdr
{
	unsigned short   source_port;
	unsigned short   dest_port;
	unsigned short   udp_len;
	unsigned short   udp_sum;
}UDP_HDR;

/*****************************************************************/

int sendLog(char *ip_dst, char *ip_src, int udp_port, char *event)
//int main()
{
	struct sockaddr_in remote;
	IP_HDR                 ipHdr;
	UDP_HDR                udpHdr;
	unsigned short     iTotalSize;
	char *ptr;
	char buf[4096];

	//char *event = "<194>May 26 17:17:50 : %ASA-4-106023: Deny tcp src SIEM_VLAN55:192.168.55.1/61872 dst outside:173.194.73.102/443 by access-group \"SIEM_(VLAN55)_access_in\" [0x0, 0x0]";
	//char *event = "May 27 13:17:50 : %ASA-4-106023: Deny tcp src SIEM_VLAN55:192.168.55.1/61872 dst outside:173.194.73.102/443 by access-group \"SIEM_(VLAN55)_access_in\" [0x0, 0x0]";
	//char *ip_dst = "127.0.0.1";
	//char *ip_src = "192.168.66.7";
	//int udp_port = 514;

	char *data = (char *) calloc(strlen(event), sizeof(char) + 1);
	strcpy(data, event);
	int res;

	WSADATA wsaData;
	//res = WSAStartup(0x0202, &wsaData);
	res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(res)
	{
		res = WSAGetLastError();
		printf("%d\n", res);
		return 1;
	}
	else
	{
		printf("%s\n", "WSAStartup - OK");
		SOCKET sckt;
		sckt = WSASocket(AF_INET, SOCK_RAW, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
		//sckt = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		if (sckt == INVALID_SOCKET) 
		{
			res = WSAGetLastError();
			printf("%d\n", res);
			return 1;
		}
		else
		{
			printf("%s\n", "Raw scoket is created");
			
			BOOL opt = TRUE;
			//res = setsockopt(sckt, IPPROTO_IP, IP_HDRINCL, (char*)&opt, sizeof(opt));
			res = setsockopt(sckt, IPPROTO_IP, IP_HDRINCL, (char*)&opt, sizeof(opt));
			if (res == SOCKET_ERROR)
			{
				res = WSAGetLastError();
				printf("%d\n", res);
				return 1;
			}
			else
			{
				printf("%s\n", "setsockopt - OK");
				
				ZeroMemory(&ipHdr, sizeof(IP_HDR));
				ipHdr.ip_verlen = 0x40 + (sizeof(IP_HDR) / sizeof(ULONG));
				ipHdr.ip_tos = 0;
				ipHdr.ip_total_len = htons(sizeof(IP_HDR) + sizeof(UDP_HDR) + strlen(data));
				ipHdr.ip_id = 0;
				ipHdr.ip_offset = 0;
				ipHdr.ip_ttl = 65;
				ipHdr.ip_protocol = IPPROTO_UDP;
				ipHdr.ip_checksum = 0;
				ipHdr.ip_src.s_addr = inet_addr(ip_src);
				ipHdr.ip_dst.s_addr = inet_addr(ip_dst);
				//ipHdr.ip_checksum = checksum((USHORT *)&ipHdr, sizeof(IP_HDR));

				ZeroMemory(&udpHdr, sizeof(UDP_HDR));
				udpHdr.source_port = htons(udp_port);
				udpHdr.dest_port = htons(udp_port);
				udpHdr.udp_len = htons(sizeof(UDP_HDR) + strlen(data));
				udpHdr.udp_sum = 0;

				ptr = buf;
				memcpy(buf, &ipHdr, sizeof(IP_HDR));
				ptr += sizeof(IP_HDR);
				memcpy(ptr, &udpHdr, sizeof(UDP_HDR));
				ptr += sizeof(UDP_HDR);
				memcpy(ptr, data, strlen(data));
				iTotalSize = ptr - buf + strlen(data) + 10;



				remote.sin_family = AF_INET;
				remote.sin_port = htons(udp_port);
				remote.sin_addr.s_addr = inet_addr(ip_dst);
				res = NULL;
				res = sendto(sckt, buf, iTotalSize, 0, (SOCKADDR *)&remote, sizeof(remote));
				free(data);
				if (res == SOCKET_ERROR) 
				{ 
					res = WSAGetLastError();
					printf("%d\n", res);
					return 1;
				}
				else { printf("%s %d\n", "sendto - OK, Bytes: ", res); }
			}
			res = closesocket(sckt);
			if (res == SOCKET_ERROR) 
			{ 
				res = WSAGetLastError();
				printf("%d\n", res);
				return 1;
			}
			else { printf("%s\n", "closesocket - OK"); }
		}
		res = WSACleanup();
		if (res) 
		{ 
			res = WSAGetLastError();
			printf("%d\n", res);
			return 1;
		}
		else { printf("%s\n", "WSACleanup - OK"); }
	}
	return 0;
}

int sendLog(char *ip_dst, char *ip_src, char *event) 
{
	if (sendLog(ip_dst, ip_src, 514, event)) {return 1;}
	else { return 0; }
}

int main(int argc, char *argv[])
{
	char *src = "192.168.55.71";
	char *dst = "127.0.0.1";
	int port = 514;
	char *msg = "May 27 14:17:50 : %ASA-4-106023: Deny tcp src SIEM_VLAN55:192.168.55.1/61872 dst outside:173.194.73.102/443 by access-group \"SIEM_(VLAN55)_access_in\" [0x0, 0x0]";

	sendLog(dst, src, port, msg);
	//sendLog(dst, src, msg);
	return 0;
}
