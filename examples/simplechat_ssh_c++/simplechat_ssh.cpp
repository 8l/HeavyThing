/*
	; ------------------------------------------------------------------------
	; HeavyThing x86_64 assembly language library and showcase programs
	; Copyright © 2015 2 Ton Digital 
	; Homepage: https://2ton.com.au/
	; Author: Jeff Marrison <jeff@2ton.com.au>
	;       
	; This file is part of the HeavyThing library.
	;       
	; HeavyThing is free software: you can redistribute it and/or modify
	; it under the terms of the GNU General Public License, or
	; (at your option) any later version.
	;       
	; HeavyThing is distributed in the hope that it will be useful, 
	; but WITHOUT ANY WARRANTY; without even the implied warranty of
	; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the 
	; GNU General Public License for more details.
	;       
	; You should have received a copy of the GNU General Public License along
	; with the HeavyThing library. If not, see <http://www.gnu.org/licenses/>.
	; ------------------------------------------------------------------------
	;       

        see https://2ton.com.au/rants_and_musings/gcc_integration.html for
        information and commentary re: how/why/what/where/when

*/
#include <cstdio>
#include <string>
#include <iostream>
#include <unordered_map>


/*
	This example is the same as our previous C++ simplechat,
	only we do it all via SSH2. There are some pretty hefty
	differences between line-based telnet-friendly plain and
	the foundation for a proper SSH terminal session, mainly
	that instead of getting line-at-a-time, we get character
	at a time, and we have to echo each character back to the
	user.

	And this example makes use of the HeavyThing IO layering
	which is required for SSH/TLS/etc.
*/



/* 
	All our HeavyThing functions need C declarations (otherwise,
	name mangling and all sorts of fun happens).
*/
typedef void (*vmethod_t)(void);

extern "C" {

void ht$init_args(int, char **);
void **io$new();
void *ssh$new_server(void *);
void *epoll$new(vmethod_t, int);
void io$destroy(void *);
void *io$clone(void *);
void io$send(void *, const void *, int);
void simplechat_error(void *);
bool io$timeout(void *);
void inaddr_any(void *, int);
bool epoll$inbound(void *, int, void *);
void epoll$run();
void *inet_ntoa(unsigned);
void *string$from_unsigned(unsigned, int);
int string$to_utf8(void *, void *);
void io$link(void *, void *);
void epoll$default_vtable();

};

/*
	Our default vtable for the epoll layer is a public symbol from
	the HeavyThing library:
*/


/*
	Forward declarations for our custom simplechat functions so that
	they can be included in our HeavyThing virtual method table:
*/
void simplechat_connected(void *epoll_object, void *raddr, int raddr_len);
bool simplechat_received(void *epoll_object, void *buffer, int len);
void simplechat_error(void *epoll_object);


/*
	The HeavyThing epoll layer works with what basically amounts to a
	virtual method table, but they are explicitly defined. Rather than
	wrap the HeavyThing functionality into a corresponding C++ layer,
	this example explicitly defines them the same as we'd do in our
	native assembly language environment.
	Note re: typecasting these, since all our HeavyThing functions
	require varying arguments, we have to forcibly typecast them to
	get them into a sensible array necessary for the virtual method
	table functionality that HeavyThing requires:
*/

static vmethod_t epoll_methods[7] = {
	(vmethod_t)io$destroy,
	(vmethod_t)io$clone,
	(vmethod_t)simplechat_connected,
	(vmethod_t)io$send,
	(vmethod_t)simplechat_received,
	(vmethod_t)simplechat_error,
	(vmethod_t)io$timeout
};

/*
	Here we define our pathetically simple class to hold our state
	information.
	Note re: std::string use here: We are intentionally not using
	HeavyThing's string implementation despite it being UTF capable
	mainly to show that language mixing is trivial.
*/
class ChatClient {
public:
	ChatClient(void *epoll, void *raddr, int raddrlen) : epoll(epoll) {
		/*
			Construct a std::string representation of our
			remote address. The actual 32 bit address in a
			sockaddr_in structure is located at +4, and the
			big endian port number is at +2. Since we don't
			want our compiler complaining about pointer math
			we case it to an unsigned char *
		*/
		unsigned char *r = (unsigned char *)raddr;
		void *ht_addrstr = inet_ntoa(*(unsigned *)(r+4));
		/*
			Next up, we need the port number, but since it is
			in big endian order, we can extract the bytes directly.
		*/
		int port = (r[2] << 8) + r[3];
		/*
			Convert that to a string with the HeavyThing string
			library... of course we could use snprintf, etc
			but we are mixing it up on purpose here.
		*/
		void *ht_portstr = string$from_unsigned(port, 10);
		/*
			Now we can construct our char * of the above
		*/
		char scratch[32];
		int i = string$to_utf8(ht_addrstr, scratch);
		scratch[i] = ':';
		int j = string$to_utf8(ht_portstr, &scratch[i+1]);
		scratch[i+j+1] = 0;
		remote_address = std::string(scratch, i+j+1);
	}
	~ChatClient() {
	}

	void *epoll;
	std::string remote_address;
	std::string handle;
	std::string accum;
};

/*
	Our typedefs and global static client map:
*/
typedef std::pair<void *, ChatClient *> clients_r;
typedef std::unordered_map<void *, ChatClient *> clients_t;

static clients_t clients;

/*
	This function is called by the HeavyThing's epoll layer when a new
	connection arrives. We are passed an epoll object (specific to the
	connection itself), and its remote address details. Our only mission
	here is to send a greeting to the client and add it to our clients
	map.
*/

void simplechat_connected(void *epoll_object, void *raddr, int raddr_len) {
	/*
		Send our greeting first.
	*/
	static const std::string greeting("Greetings! Your desired handle? ");
	io$send(epoll_object, greeting.c_str(), greeting.length());
	/*
		Add the client to our map.
	*/
	clients.insert(clients_r(epoll_object, new ChatClient(epoll_object, raddr, raddr_len)));
}

/*
	When data arrives from a connection, this function is called. If we
	return true from here, the connection will be closed, false and it
	stays open.
*/
bool simplechat_line(void *epoll_object, ChatClient *client);
bool simplechat_received(void *epoll_object, void *buffer, int len) {
	/*
		Unlike our telnet-friendly previous version, we get
		SSH2 input character-by-character, so we accumulate
		them until we get a linefeed.

		First up, find our client in our map:
	*/
	clients_t::const_iterator x = clients.find(epoll_object);
	/*
		Sanity only: freak out if we failed.
	*/
	if (x == clients.end())
		return true;
	ChatClient *client = (*x).second;
	/*
		Since SSH disables echo, echo for the typist
	*/
	io$send(epoll_object, buffer, len);
	/*
		Loop through however many characters we got.
	*/
	const char *b = (const char *)buffer;
	for (int i = 0; i < len; i++) {
		const char c = b[i];
		if (c == 13) {
			if (simplechat_line(epoll_object, client))
				return true;
			// send an LF for them
			io$send(epoll_object, "\n", 1);
			client->accum.clear();
		}
		else if (c == 127) {
			if (!client->accum.empty())
				client->accum = client->accum.substr(0, client->accum.length()-1);
			io$send(epoll_object, "\b \b", 3);
		}
		else if (c != 10) {
			client->accum += c;
		}
	}
	return false;
}

/*
	Line-based input version from above:
*/
bool simplechat_line(void *epoll_object, ChatClient *client) {
	/*
		Ignore empty lines.
	*/
	if (client->accum.empty())
		return false;
	std::string input = client->accum;
	/*
		Our only two states are:
		1) very first message, call that their handle.
		2) anything else, normal message.
	*/
	clients_t::const_iterator x;
	if (client->handle.empty()) {
		/*
			Set our client handle
		*/
		client->handle = input;
		/*
			Send back a greeting specific to our client.
		*/
		static const std::string hello_part1("\nWelcome, ");
		static const std::string hello_part2("\r\nEverything to you type will be "
			"broadcast to other connected clients,\r\nand will not be echoed "
			"back to you.\r\n\r\nCommands we understand are: /who and /exit\r");
		std::string greeting = hello_part1 + input + hello_part2;
		io$send(epoll_object, greeting.c_str(), greeting.length());
		/*
			Let everyone else know our client has arrived, but only those
			who have already provided a handle.
		*/
		static const std::string arrival = " has joined the circus.\r\n";
		std::string notice = input + arrival;
		x = clients.begin();
		while (x != clients.end()) {
			if ((*x).first != epoll_object && !(*x).second->handle.empty())
				io$send((*x).first, notice.c_str(), notice.length());
			x++;
		}
		/*
			Done, return false to keep the connection open.
		*/
		return false;
	}
	/*
		Otherwise, normal message. Check for our two known commands, else
		broadcast.
	*/
	if (input == "/who") {
		/*
			Construct a std::string of everyone here, including the asker.
		*/
		std::string response = "\nSmoke on the water: ";
		std::string present;
		clients_t::const_iterator x = clients.begin();
		while (x != clients.end()) {
			if (!present.empty())
				present += ", ";
			present += (*x).second->handle;
			present += " (";
			present += (*x).second->remote_address;
			present += ")";
			x++;
		}
		response += present;
		response += "\r";
		io$send(epoll_object, response.c_str(), response.length());
		/*
			Return false to keep the connection open.
		*/
		return false;
	}
	if (input == "/exit") {
		static const std::string bye = "\nBye.\r\n";
		io$send(epoll_object, bye.c_str(), bye.length());
		/*
			Let everyone else know, noting here that since this also occurs
			from an epoll error event, we separated it out into its own
			function (will clean itself up too).
		*/
		simplechat_error(epoll_object);
		/*
			return true from here to kill the current connection.
		*/
		return true;
	}
	/*
		Normal broadcast message, send to everyone except the sender.
	*/
	std::string message = client->handle;
	message += ": ";
	message += input;
	message += "\r\n";
	x = clients.begin();
	while (x != clients.end()) {
		if ((*x).first != epoll_object)
			io$send((*x).first, message.c_str(), message.length());
		x++;
	}
	/*
		Return false to keep the connection open.
	*/
	return false;
}

/*
	This function is called either by an /exit command from a client,
	or on epoll error when they disconnected. Notify everyone else
	that this client has left, but only if they already provided a
	handle.
*/
void simplechat_error(void *epoll_object) {
	clients_t::const_iterator x = clients.find(epoll_object);
	/*
		Sanity only, bailout if we didn't find it
	*/
	if (x == clients.end())
		return;
	std::string handle = (*x).second->handle;
	/*
		Remove them from our map.
	*/
	delete (*x).second;
	clients.erase(x);
	/*
		Let everyone remaining who has a handle know they left.
	*/
	handle += " has departed.\r\n";
	x = clients.begin();
	while (x != clients.end()) {
		if (!(*x).second->handle.empty())
			io$send((*x).first, handle.c_str(), handle.length());
		x++;
	}
}

int main(int argc, char *argv[]) {
	/* 
		First up: initialize HeavyThing, and like our previous
		examples, we are not interested in argc/argv from inside
		our assembler environment:

		An interesting sidenote here: because HeavyThing has normal
		function definitions for memcpy, memcmp, etc, those get
		preferentially linked instead of the libc versions, and so
		during our C++ initialization, those HeavyThing functions
		were already called. Fortunately for us in this case, those
		functions do not require any HeavyThing global state.
	*/
	ht$init_args(0, 0);
	/*
		We need a default/generic io layer for our top level
	*/
	void **iolayer = io$new();
	/*
		Set its virtual method table to our own:
	*/
	iolayer[0] = epoll_methods;
	/*
		Next in the layers is our ssh server layer, and its argument
		as 0 specifies to use /etc/ssh host keys
	*/
	void *sshserver = ssh$new_server(0);
	if (!sshserver) {
		std::cerr << "SSH host key error" << std::endl;
		exit(1);
	}
	/*
		We have to link the iolayer with the ssh layer:
	*/
	io$link((void *)iolayer, sshserver);
	/*
		And our lowest layer is a real epoll object with defaults
	*/
	void *listener = epoll$new((vmethod_t)epoll$default_vtable, 0);
	/*
		Link that to our sshserver
	*/
	io$link(sshserver, listener);
	/*
		Setup an IPv4 socket address for our listener, noting that
		sockaddr_in_size from epoll.inc is 16 bytes. Listener port
		== 8001:
	*/
	unsigned char addrbuf[16];
	inaddr_any(addrbuf, 8001);
	/*
		Now we can pass that off to our epoll layer. The HeavyThing's
		epoll$inbound will return false if bind failure:
	*/
	if (!epoll$inbound(addrbuf, sizeof(addrbuf), (void *)iolayer)) {
		std::cerr << "INADDR_ANY:8001 bind failure." << std::endl;
		exit(1);
	}
	/*
		Dump a banner to stdout so that we know all is well
	*/
	std::cout << "Simple SSH chat server listening on port 8001." << std::endl;
	/*
		Pass control (indefinitely) to HeavyThing's epoll layer.
	*/
	epoll$run();
	/*
		Not reached.
	*/
}
