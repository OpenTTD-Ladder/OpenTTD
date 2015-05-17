/* $Id$ */

/*
 * This file is part of OpenTTD.
 * OpenTTD is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
 * OpenTTD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with OpenTTD. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file tcp_tls.h Basic functions to do TLS over TCP.
 */

#ifndef NETWORK_CORE_TCP_TLS_H
#define NETWORK_CORE_TCP_TLS_H

#include "core.h"

#ifdef ENABLE_NETWORK

typedef struct _ssl_context ssl_context;

/** Base socket handler for HTTP traffic. */
class NetworkTLSSocketHandler : public NetworkSocketHandler {
private:
	bool tls;                          ///< Whether the socket uses TLS.
	bool tls_connected;                ///< Whether the socket is done with the handshake and is ready for communication.
	ssl_context *ssl;                  ///< The SSL context of the socket.

	static void *entropy;   ///< Entropy of the TLS.
	static void *ctr_drbg; ///< Random number generator of the TLS.

public:
	SOCKET sock;        ///< The socket currently connected to.

	virtual NetworkRecvStatus CloseConnection(bool error = true);

	/**
	 * Whether this socket is currently bound to a socket.
	 * @return true when the socket is bound, false otherwise
	 */
	bool IsConnected() const
	{
		return this->sock != INVALID_SOCKET;
	}

	NetworkTLSSocketHandler(SOCKET sock);

	~NetworkTLSSocketHandler();

	/**
	 * Initialize TLS capabilities
	 */
	static void Initialize();

	/**
	 * Wrapper around recv() to use TLS if enabled.
	 */
	ssize_t recv(char *buffer, int len);
	/**
	 * Wrapper around send() to use TLS if enabled.
	 */
	ssize_t send(const char *buffer, int len);

	/**
	 * Start the TLS handshake. Required before any data can be send.
	 */
	bool TLSHandshake(const char *host);

	/**
	 * Called when we're done with the handshake and data can now be exchanged.
	 * @return False if a connection problem happened.
	 */
	virtual bool OnConnected() = 0;

	/**
	 * Function to be called till it returns 0, (or < 0 in case of an error),
	 *  indicating the socket is setup for TLS usage.
	 */
	int Receive();
};

#endif /* ENABLE_NETWORK */

#endif /* NETWORK_CORE_TCP_TLS_H */
