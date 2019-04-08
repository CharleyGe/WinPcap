#include "pcap.h"
#include <WinSock2.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib,"ws2_32")

#include <WS2tcpip.h>

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

void main(int argc, char **argv)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;

	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct timeval st_ts;
	u_int netmask;
	struct bpf_program fcode;

	/* Check the validity of the command line */
	//if (argc != 2)
	//{
	//	usage();
	//	return;
	//}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description avaliable)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the output adapter */
	if ((fp = pcap_open(d->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open adapter %s.\n", errbuf);
		return;
	}

	/* Don't care about netmask, it won't be used for this filter */
	netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(fp, &fcode, "tcp", 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		return;
	}

	//set the filter
	if (pcap_setfilter(fp, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_close(fp);
		/* Free the device list */
		return;
	}

	/* Put the interface in statistics mode */
	if (pcap_setmode(fp, MODE_STAT) < 0)
	{
		fprintf(stderr, "\nError setting the mode.\n");
		pcap_close(fp);
		/* Free the device list */
		return;
	}

	printf("TCP traffic summary:\n");
	/* Start the main loop */
	pcap_loop(fp, 0, dispatcher_handler, (PUCHAR)&st_ts);

	pcap_close(fp);
	return;
}

void dispatcher_handler(u_char *state, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct timeval *old_ts = (struct timeval *)state;
	u_int delay;
	LARGE_INTEGER Bps, Pps;
	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;

	/* Calculate the delay in microseconds from the last sample. */
	/* This value is obtained from the timestamp that the associated with the sample. */
	delay = (header->ts.tv_sec - old_ts->tv_sec) * 1000000 - old_ts->tv_usec + header->ts.tv_usec;
	/* Get the number of the Bits per second */
	Bps.QuadPart = (((*(LONGLONG*)(pkt_data + 8)) * 8 * 1000000) / (delay));
	/* Get the number of the Packets per second */
	Pps.QuadPart = (((*(LONGLONG*)(pkt_data)) * 1000000) / (delay));

	/* Convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

	/* Print timestamp */
	printf("%s ", timestr);

	/* Print the samples */
	printf("BPS=%I64u ", Bps.QuadPart);
	printf("PPS=%I64u\n", Pps.QuadPart);

	//store current timestamp
	old_ts->tv_sec = header->ts.tv_sec;
	old_ts->tv_usec = header->ts.tv_usec;
}