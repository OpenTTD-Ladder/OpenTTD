/* $Id$ */

#ifndef NETWORK_CORE_H
#define NETWORK_CORE_H

#ifdef ENABLE_NETWORK

#include "os_abstraction.h"

bool NetworkCoreInitialize(void);
void NetworkCoreShutdown(void);

typedef enum {
	NETWORK_RECV_STATUS_OKAY,             ///< Everything is okay
	NETWORK_RECV_STATUS_DESYNC,           ///< A desync did occur
	NETWORK_RECV_STATUS_SAVEGAME,         ///< Something went wrong (down)loading the savegame
	NETWORK_RECV_STATUS_CONN_LOST,        ///< The conection is 'just' lost
	NETWORK_RECV_STATUS_MALFORMED_PACKET, ///< We apparently send a malformed packet
	NETWORK_RECV_STATUS_SERVER_ERROR,     ///< The server told us we made an error
	NETWORK_RECV_STATUS_SERVER_FULL,      ///< The server is full
	NETWORK_RECV_STATUS_SERVER_BANNED,    ///< The server has banned us
	NETWORK_RECV_STATUS_CLOSE_QUERY,      ///< Done quering the server
} NetworkRecvStatus;

/**
 * SocketHandler for all network sockets in OpenTTD.
 */
class NetworkSocketHandler {
public:
	/* TODO: make socket & has_quit protected once the TCP stuff
	 *is in a real class too */
	bool has_quit; ///< Whether the current client has quit/send a bad packet
	SOCKET sock;   ///< The socket currently connected to
public:
	NetworkSocketHandler() { this->sock = INVALID_SOCKET; this->has_quit = false; }
	virtual ~NetworkSocketHandler() { this->Close(); }

	/** Really close the socket */
	virtual void Close() {}

	/**
	 * Close the current connection; for TCP this will be mostly equivalent
	 * to Close(), but for UDP it just means the packet has to be dropped.
	 * @return new status of the connection.
	 */
	virtual NetworkRecvStatus CloseConnection() { this->has_quit = true; return NETWORK_RECV_STATUS_OKAY; }

	/**
	 * Whether this socket is currently bound to a socket.
	 * @return true when the socket is bound, false otherwise
	 */
	bool IsConnected() { return this->sock != INVALID_SOCKET; }

	/**
	 * Whether the current client connected to the socket has quit.
	 * In the case of UDP, for example, once a client quits (send bad
	 * data), the socket in not closed; only the packet is dropped.
	 * @return true when the current client has quit, false otherwise
	 */
	bool HasClientQuit() { return this->has_quit; }
};

#endif /* ENABLE_NETWORK */

#endif /* NETWORK_CORE_H */
