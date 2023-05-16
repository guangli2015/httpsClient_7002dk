/*
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <stdio.h>
#include <zephyr/drivers/uart.h>
#include <string.h>
#include <zephyr/random/rand32.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/wifi.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/shell/shell.h>
#include <modem/lte_lc.h>
#include <zephyr/logging/log.h>
#include <dk_buttons_and_leds.h>

#include "certificates.h"

LOG_MODULE_REGISTER(mqtt_simple, CONFIG_MQTT_SIMPLE_LOG_LEVEL);

extern struct k_sem wifi_ready;


#define HTTPS_PORT 443

//#define HTTPS_HOSTNAME "api.nrfcloud.com"
#define HTTPS_HOSTNAME "example.com"
/*#define HTTP_HEAD                                                              \
	"POST /v1/devices/50503041-3633-4085-8043-2a20675f50f8/messages HTTP/1.1\r\n"                                                  \
	"Host: " HTTPS_HOSTNAME "\r\n"                                     \
	"Authorization: Bearer 01cfa5299f66da3096a984a9688e2e73badb9617\r\n"   \
	"Content-Type: application/json\r\n"                                       \
	"Content-Length: 111\r\n"                                                  \
	"{\"topic\": \"d/50503041-3633-4085-8043-2a20675f50f8/d2c\",\"message\": {\"sample_message\":\"helloNordic56\"}}\r\n\r\n"


#define HTTP_HEAD                                                              \
	"HEAD / HTTP/1.1\r\n"                                                  \
	"Host: " HTTPS_HOSTNAME ":443\r\n"                                     \
	"Connection: close\r\n\r\n"


#define HTTP_HEAD                                                              \
	"GET /v1/devices HTTP/1.1\r\n"                                                  \
	"Host: " HTTPS_HOSTNAME ":443\r\n"                                     \
	"Authorization: Bearer 01cfa5299f66da3096a984a9688e2e73badb9617\r\n"   \
	"Connection: close\r\n\r\n"
*/

#define HTTP_HEAD                                                              \
	"HEAD / HTTP/1.1\r\n"                                                  \
	"Host: " HTTPS_HOSTNAME ":443\r\n"                                     \
	"Connection: close\r\n\r\n"

#define HTTP_HEAD_LEN (sizeof(HTTP_HEAD) - 1)

#define HTTP_HDR_END "\r\n\r\n"

#define RECV_BUF_SIZE 2048
//#define TLS_SEC_TAG 16842753
#define TLS_SEC_TAG 42

static const char send_buf[] = HTTP_HEAD;
static char recv_buf[RECV_BUF_SIZE];

/* Certificate for `example.com` */
static const char cert[] = {
	#include "../cert/DigiCertGlobalRootCA.pem"
	//#include "../cert/mosquitto.org.crt"
	//#include "../cert/AmazonRootCA1_mqtt.pem"
};

BUILD_ASSERT(sizeof(cert) < KB(4), "Certificate too large");

/* Setup TLS options on a given socket */
int tls_setup(int fd)
{
	int err;
	int verify;

	/* Security tag that we have provisioned the certificate with */
	const sec_tag_t tls_sec_tag[] = {
		TLS_SEC_TAG,
	};


	err = tls_credential_add(tls_sec_tag[0], TLS_CREDENTIAL_CA_CERTIFICATE, cert, sizeof(cert));
	if (err) {
		return err;
	}


	/* Set up TLS peer verification */
	enum {
		NONE = 0,
		OPTIONAL = 1,
		REQUIRED = 2,
	};

	verify = REQUIRED;

	err = setsockopt(fd, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));
	if (err) {
		printk("Failed to setup peer verification, err %d\n", errno);
		return err;
	}

	/* Associate the socket with the security tag
	 * we have provisioned the certificate with.
	 */
	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, tls_sec_tag,
			 sizeof(tls_sec_tag));
	if (err) {
		printk("Failed to setup TLS sec tag, err %d\n", errno);
		return err;
	}

	err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME, HTTPS_HOSTNAME, sizeof(HTTPS_HOSTNAME) - 1);
	if (err) {
		printk("Failed to setup TLS hostname, err %d\n", errno);
		return err;
	}
	return 0;
}

void main(void)
{
	int err;
	int fd;
	char *p;
	int bytes;
	int rev_siz;
	size_t off;
	struct addrinfo *res;
	struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
	};
k_sem_take(&wifi_ready, K_FOREVER);
	printk("HTTPS client sample started\n\r");


	err = getaddrinfo(HTTPS_HOSTNAME, NULL, &hints, &res);
	if (err) {
		printk("getaddrinfo() failed, err %d\n", errno);
		return;
	}

	((struct sockaddr_in *)res->ai_addr)->sin_port = htons(HTTPS_PORT);


	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	//fd = socket(AF_INET, SOCK_STREAM | SOCK_NATIVE_TLS, IPPROTO_TLS_1_2);
	
	if (fd == -1) {
		printk("Failed to open socket!\n");
		goto clean_up;
	}

	/* Setup TLS socket options */
	err = tls_setup(fd);
	if (err) {
		goto clean_up;
	}

	printk("Connecting to %s\n", HTTPS_HOSTNAME);
	err = connect(fd, res->ai_addr, sizeof(struct sockaddr_in));
	if (err) {
		printk("connect() failed, err: %d\n", errno);
		goto clean_up;
	}

	off = 0;
	do {
		bytes = send(fd, &send_buf[off], HTTP_HEAD_LEN - off, 0);
		if (bytes < 0) {
			printk("send() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (off < HTTP_HEAD_LEN);

	printk("Sent %d bytes\n", off);

	off = 0;
	do {
		printk("*", off);
		bytes = recv(fd, &recv_buf[off], RECV_BUF_SIZE - off, 0);
		if (bytes < 0) {
			printk("recv() failed, err %d\n", errno);
			goto clean_up;
		}
		off += bytes;
	} while (bytes != 0 /* peer closed connection */);

	printk("Received %d bytes\n", off);

	rev_siz=off;

	/* Print HTTP response
    for(int i=0; i<rev_siz;i++)
	{
		printk("%c", recv_buf[i]);
	}*/
	printk("\nFinished, closing socket.\n");

clean_up:
	freeaddrinfo(res);
	(void)close(fd);

}
