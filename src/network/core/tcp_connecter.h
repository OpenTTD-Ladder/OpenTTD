/* $Id$ */

/*
 * This file is part of OpenTTD.
 * OpenTTD is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, version 2.
 * OpenTTD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details. You should have received a copy of the GNU General Public License along with OpenTTD. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file tcp_connecter.h Basic functions to connect to a TCP server.
 */

#ifndef NETWORK_CORE_TCP_CONNECTER_H
#define NETWORK_CORE_TCP_CONNECTER_H

#include "address.h"

#ifdef ENABLE_NETWORK

/**
 * "Helper" class for creating TCP connections in a non-blocking manner
 */
class TCPConnecter {
private:
	class ThreadObject *thread; ///< Thread used to create the TCP connection
	bool connected;             ///< Whether we succeeded in making the connection
	bool aborted;               ///< Whether we bailed out (i.e. connection making failed)
	bool killed;                ///< Whether we got killed
	SOCKET sock;                ///< The socket we're connecting with

	void Connect();

	static void ThreadEntry(void *param);

protected:
	/** Address we're connecting to */
	NetworkAddress address;

public:
	TCPConnecter(const NetworkAddress &address);
	/** Silence the warnings */
	virtual ~TCPConnecter() {}

	/**
	 * Callback when the connection succeeded.
	 * @param s the socket that we opened
	 */
	virtual void OnConnect(SOCKET s) {}

	/**
	 * Callback for when the connection attempt failed.
	 */
	virtual void OnFailure() {}

	static void CheckCallbacks();
	static void KillAll();
};

#endif /* ENABLE_NETWORK */

#endif /* NETWORK_CORE_TCP_CONNECTER_H */
