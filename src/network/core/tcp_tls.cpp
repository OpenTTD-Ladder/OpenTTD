/* $Id$ */

/*
 * This file is part of OpenTTD.
 * OpenTTD is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
 * OpenTTD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with OpenTTD. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file tcp_tls.cpp Basic functions to do TLS over TCP.
 */

#ifdef ENABLE_NETWORK

#include "../../stdafx.h"
#include "../../debug.h"
#include "../../rev.h"
#include "../network_func.h"

extern "C"
{
#include "polarssl/ssl.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
}

#include "tcp_tls.h"

/* static */ void *NetworkTLSSocketHandler::entropy = NULL;
/* static */ void *NetworkTLSSocketHandler::ctr_drbg = NULL;


int tls_recv(void *socket, unsigned char *buffer, size_t len)
{
	SOCKET sock = *(SOCKET *)socket;
	ssize_t res = ::recv(sock, (char *)buffer, len, 0);

	if (res == -1) {
		int err = GET_LAST_ERROR();
		if (err != EWOULDBLOCK) {
			return POLARSSL_ERR_NET_RECV_FAILED;
		}
		return POLARSSL_ERR_NET_WANT_READ;
	}

	return res;
}

int tls_send(void *socket, const unsigned char *buffer, size_t len)
{
	SOCKET sock = *(SOCKET *)socket;
	ssize_t res = ::send(sock, (const char *)buffer, len, 0);

	if (res == -1) {
		int err = GET_LAST_ERROR();
		if (err != EWOULDBLOCK) {
			return POLARSSL_ERR_NET_SEND_FAILED;
		}
		return POLARSSL_ERR_NET_WANT_WRITE;
	}

	return res;
}

/* static */ void NetworkTLSSocketHandler::Initialize()
{
	const char *pers = "OpenTTD Client";

	NetworkTLSSocketHandler::entropy = MallocT<entropy_context>(1);
	NetworkTLSSocketHandler::ctr_drbg = MallocT<ctr_drbg_context>(1);

	entropy_init((entropy_context *)NetworkTLSSocketHandler::entropy);
	if (ctr_drbg_init((ctr_drbg_context *)NetworkTLSSocketHandler::ctr_drbg, entropy_func, NetworkTLSSocketHandler::entropy, (const unsigned char *)pers, strlen(pers)) != 0) {
		DEBUG(net, 0, "[core] failed to initialize TLS");
		return;
	}
}

NetworkTLSSocketHandler::NetworkTLSSocketHandler(SOCKET s) :
	NetworkSocketHandler(),
	sock(s),
	tls_connected(false)
{
	/* TODO -- Check settings if TLS is enabled */
	this->tls = true;
}

bool NetworkTLSSocketHandler::TLSHandshake(const char *host)
{
	if (!this->tls) {
		return this->OnConnected();
	}

	this->ssl = MallocT<ssl_context>(1);

	ssl_init(this->ssl);
	ssl_set_endpoint(this->ssl, SSL_IS_CLIENT);
	ssl_set_authmode(this->ssl, SSL_VERIFY_NONE);

	ssl_set_rng(this->ssl, ctr_drbg_random, NetworkTLSSocketHandler::ctr_drbg);
	ssl_set_bio(this->ssl, tls_recv, &this->sock, tls_send, &this->sock);

	/* Set hostname for SNI */
	ssl_set_hostname(this->ssl, host);
	/* Depend on PolarSSL to give us a good ciphersuite */
	ssl_set_ciphersuites(this->ssl, ssl_default_ciphersuites);
	/* At the very least TLS1.0 */
	ssl_set_min_version(this->ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_0);

	/* Initial call to get things going */
	return this->Receive() >= 0;
}

NetworkTLSSocketHandler::~NetworkTLSSocketHandler()
{
	this->CloseConnection();

	if (this->sock != INVALID_SOCKET) closesocket(this->sock);
	this->sock = INVALID_SOCKET;

	if (this->tls) {
		ssl_free(this->ssl);
		free(this->ssl);
	}
}

ssize_t NetworkTLSSocketHandler::recv(char *buffer, int len)
{
	if (!this->tls) {
		return ::recv(this->sock, buffer, len, 0);
	}
	if (!this->tls_connected) {
		DEBUG(net, 0, "[TLS] recv() called before handshake completed");
		return -1;
	}

	int res = ssl_read(this->ssl, (unsigned char *)buffer, len);
	if (res < 0) return -1;
	return res;
}

ssize_t NetworkTLSSocketHandler::send(const char *buffer, int len)
{
	if (!this->tls) {
		return ::send(this->sock, buffer, len, 0);
	}
	if (!this->tls_connected) {
		DEBUG(net, 0, "[TLS] send() called before handshake completed");
		return -1;
	}

	int res = ssl_write(this->ssl, (unsigned char *)buffer, len);
	if (res < 0) return -1;
	return res;
}

NetworkRecvStatus NetworkTLSSocketHandler::CloseConnection(bool error)
{
	NetworkSocketHandler::CloseConnection(error);
	return NETWORK_RECV_STATUS_OKAY;
}

int NetworkTLSSocketHandler::Receive()
{
	if (this->tls_connected) return 0;

	int res = ssl_handshake(this->ssl);
	if (res < 0) {
		if (res != POLARSSL_ERR_NET_WANT_READ && res != POLARSSL_ERR_NET_WANT_WRITE) {
			DEBUG(net, 0, "handshake failed with error %d", res);
			return -1;
		}
		/* Connection would block, so stop for now */
		return 1;
	}

	this->tls_connected = true;
	return this->OnConnected() ? 0 : -1;
}

#endif /* ENABLE_NETWORK */
