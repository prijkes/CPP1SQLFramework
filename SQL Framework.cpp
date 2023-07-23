// SQL Framework.cpp : Defines the entry point for the console application.
//
#define _CRT_SECURE_NO_WARNINGS		// Disable warnings about insecure function usage
#pragma warning(disable:4996)						// warning C4996: '_swprintf': swprintf has been changed to conform with the ISO C standard, adding an extra character count parameter.

#ifndef _UNICODE		// Enable unicode
#define _UNICODE		// http://msdn.microsoft.com/en-us/library/dybsewaf.aspx
#endif
#ifdef _MBCS			// Don't use 'Multi-Byte Character Set'
#undef _MBCS			// http://msdn.microsoft.com/en-us/library/5z097dxa(VS.71).aspx
#endif

#include <stdio.h>
#include <tchar.h>
//#define USE_PCRE_REGEXP		// Uncomment this if you want to use PCRE regex strings for parsing <not recommend if you don't know regex>
#include "CFramework.h"

struct COMMANDS
{
	TCHAR* cmd;
	TCHAR* parameters;
	TCHAR* description;
} commands[] = {
	{_T(""),				_T(""),								_T("\t\t* --------- Target --------- *")},
	{_T("host"),		_T("<host> (port)"),			_T("set the hostname and port to attack")},
	{_T("path"),		_T("<path> (rest)"),			_T("set the path to the script with rest behind it")},
	{_T(""),				_T(""),								_T("\t\t* --------- Attack --------- *")},
	{_T("method"),	_T("<id>"),							_T("\tmethod to use")},
	{_T("space"),		_T("<string>"),					_T("\tuse <string> as space in query")},
	{_T("end"),			_T("<string>"),					_T("\tuse <string> as end string in query")},
	{_T("length"),		_T("<length>"),					_T("\tuse max <length> characters in charset")},
	{_T("dynamic"), _T("<start> <end>"),			_T("remove dynamic data between <start> and <end>")},
	{_T(""),				_T(""),								_T("\t\t* --------- Query --------- *")},
	{_T("interval"),	_T("<interval>"),					_T("wait <interval> milliseconds before next try")},
	{_T("attack"),		_T("<type> <params>"),		_T("execute query <type> on target")},
	{_T(""),				_T(""),								_T("\t\t* --------- Results --------- *")},
	{_T("show"),		_T(""),								_T("\t\tshow gathered info")},
	{_T("cache"),		_T(""),								_T("\t\tshow all cached entries")},
	{_T(""),				_T(""),								_T("\t\t* ------------------------------------------ *")},
	{_T("debug"),		_T("<level>"),					_T("\tset debug to <level>")},
	{_T("help"),		_T(""),								_T("\t\tshow usage")},
	{_T("cls"),			_T(""),								_T("\t\tclear screen")},
	{_T("quit"),			_T(""),								_T("\t\tquit this shell")}
};

struct info
{
	TCHAR id;
	TCHAR* description;
	TCHAR* parameters;
} atypes[] = {
	{1, _T("Count databases"),					_T("\t\t\t\t")},
	{2, _T("Get database name"),				_T("(index)\t\t\t")},
	{3, _T("Count tables in database"),		_T("dbname\t\t\t")},
	{4, _T("Get table name"),					_T("dbname (index)\t\t")},
	{5, _T("Count columns in table"),			_T("dbname tablename\t\t")},
	{6, _T("Get column name"),					_T("dbname tablename (index)\t")},
	{7, _T("Count rows in table"),				_T("dbname tablename\t\t")},
	{8, _T("Get row data from column"),		_T("dbname tablename columnname (index)")},
	{9, _T("Do everything"),						_T("\t\t\t\t")},
	{10, _T("Get MySQL version"),			_T("\t\t\t\t")},
	{11, _T("Retrieves columname for target with criteria"), _T("dbname tablename columnname <target> <criteria>")}
}, methods[] = {
#ifdef USE_PCRE_REGEX
	{1, _T("Use normal bruteforce method"),		_T("<regexp string>\t")},
	{2, _T("Use smart bruteforce queries"),		_T("<regexp string>\t")},
#else
	{1, _T("Use normal bruteforce method"),		_T("<search string> !case sensitive!")},
	{2, _T("Use smart bruteforce queries"),		_T("<search string> !case sensitive!")},
#endif
	{3, _T("Use caching method, if supported"),	_T("<start page> (end page)\t")}
};

CFramework* framework = new CFramework();
void usage()
{
	framework->log(0, _T("\r\n"));
	framework->log(0, _T("\tBlind SQL Injection Framework %s"), BSIFW_VERSION);
	framework->log(0, _T("\tBy %s <%s>"), BSIFW_AUTHOR, BSIFW_AUTHOR_EMAIL);
	framework->log(0, _T("\r\n"));
	for (int i=0; i<sizeof(commands)/sizeof(COMMANDS); i++)
	{
		framework->log(0, _T("\t%s %s\t%s"), commands[i].cmd, commands[i].parameters, commands[i].description);
	}
}

int _tmain(int m_argc, TCHAR* m_argv[])
{
	if (!framework->initialize())
	{
		framework->log(0, _T("[-] Error: %s (code: %d)"), framework->getError(), WSAGetLastError());
		return GetLastError();
	}
	usage();
	TCHAR* command = 0;
	TCHAR* argv[20] = {0};
	unsigned long argc = 0;
	TCHAR buffer[1024] = {0};
	TCHAR* tokpos = 0;
	unsigned long tmp = 0;

	while (true)
	{
		printf("\r\nshell>");
		WriteFile(framework->getFileHandle(), _T("\r\nshell>"), _tcslen(_T("\r\nshell>"))*sizeof(TCHAR), &tmp, 0);
		_fgetts(buffer, sizeof(buffer), stdin);
		WriteFile(framework->getFileHandle(), buffer, _tcslen(buffer)*sizeof(TCHAR), &tmp, 0);
		WriteFile(framework->getFileHandle(), _T("\r\n"), _tcslen(_T("\r\n"))*sizeof(TCHAR), &tmp, 0);

		argc = 0;
		memset(&argv, 0, 20*sizeof(TCHAR));
		command = _tcstok_s(buffer, _T(" \r\n"), &tokpos);
		if (!command) continue;
		do
		{
			argv[argc++] = command;
			command = _tcstok_s(0, _T(" \r\n"), &tokpos);
		} while (command && argc<sizeof(argv));

		command = argv[0];
		if (!_tcscmp(_T("host"), command))
		{
			TCHAR* host = framework->getHost();
			unsigned short port = framework->getPort();
			port = (port ? port : 80);
			if (argc < 2)
			{
				framework->log(0, _T("host <host> (port)"));
				if (host) framework->log(0, _T("Current host: %s:%d (IP: %s)"), host, port, framework->getIP());
				continue;
			}
			host = argv[1];
			port = (argc > 2 ? (unsigned short)_wtoi(argv[2]) : 80);
			if (!framework->setHost(host, port))
				framework->log(0, _T("[-] Error (%d): %s"), GetLastError(), framework->getError());
			else
				framework->log(0, _T("[*] Changed host to %s:%d"), host, port);
		}
		else if (!_tcscmp(_T("path"), command))
		{
			TCHAR* path = framework->getPath();
			TCHAR* rest = framework->getRest();
			rest = (rest ? rest : _T(""));
			if (argc < 2)
			{
				framework->log(0, _T("path <path> (rest)"));
				if (path) framework->log(0, _T("Current path: %s%s"), path, (rest ? rest : _T("")));
				continue;
			}
			path = argv[1];
			rest = (argc >= 3 ? argv[2] : _T(""));
			if (!framework->setPath(path, rest))
				framework->log(0, _T("[-] Error (%d): %s"), GetLastError(), framework->getError());
			else
				framework->log(0, _T("[*] Changed path to %s%s"), path, rest);
		}
		else if (!_tcscmp(_T("method"), command))
		{
			TCHAR _old = framework->getMethod();
			if (argc < 3)
			{
				framework->log(0, _T("method <id> <params>"));
				for (int i=0; i<sizeof(methods)/sizeof(info); i++)
						framework->log(0, _T("\t%d %s\t%s"), methods[i].id, methods[i].parameters, methods[i].description);
				framework->log(0, _T("Current method: %d"), _old);
				continue;
			}
			TCHAR _new = (TCHAR)_wtoi(argv[1]);
			TCHAR** ptr = argv+2;
			if (!framework->setMethod(_new, ptr, argc-2))
				framework->log(0, _T("[-] Error (%d): %s"), GetLastError(), framework->getError());
			else
				framework->log(0, _T("[*] Changed method id from %d to %d"), _old, _new);
		}
		else if (!_tcscmp(_T("space"), command))
		{
			TCHAR* space = (argc >= 2 ? argv[1] : _T(""));
			framework->log(0, _T("[*] Changed space to %s"), space);
			framework->setSpace(space);
		}
		else if (!_tcscmp(_T("end"), command))
		{
			TCHAR* end = (argc >= 2 ? argv[1] : _T(""));
			framework->log(0, _T("[*] Changed end to %s"), end);
			framework->setEnd(end);
		}
		else if (!_tcscmp(_T("length"), command))
		{
			unsigned short old = framework->getLength();
			if (argc < 2)
			{
				framework->log(0, _T("length <length>"));
				framework->log(0, _T("Current length: %d"), old);
				continue;
			}
			unsigned short length = _ttoi(argv[1]);
			if (!framework->setLength(length))
				framework->log(0, _T("[*] Error: %s"), framework->getError());
			else
				framework->log(0, _T("[*] Changed length from %d to %d"), old, length);
		}
		else if (!_tcscmp(_T("dynamic"), command))
		{
			TCHAR* start = framework->getDynamicStart();
			TCHAR* end = framework->getDynamicEnd();
			if (argc < 3)
			{
				framework->log(0, _T("dynamic <start> <end>"));
				if (start && end) framework->log(0, _T("Current tags: %s %s"), start, end);
				continue;
			}
			framework->setDynamicTags(argv[1], argv[2]);
			framework->log(0, _T("[*] Changed dynamic tags to %s %s"), argv[1], argv[2]);
		}
		else if (!_tcscmp(_T("interval"), command))
		{
			unsigned long old = framework->getInterval();
			if (argc < 2)
			{
				framework->log(0, _T("interval <milliseconds>"));
				framework->log(0, _T("Current inverval: %d milliseconds"), old);
				continue;
			}
			unsigned long interval = _wtol(argv[1]);
			framework->setInterval(interval);
			framework->log(0, _T("[*] Changed interval from %d to %d milliseconds"), old, interval);
		}
		else if (!_tcscmp(_T("attack"), command))
		{
			TCHAR attack = framework->getAttack();
			if (argc < 2)
			{
				framework->log(0, _T("attack <type> (params)"));
				for (int i=0; i<sizeof(atypes)/sizeof(info); i++)
					framework->log(0, _T("\t%d %s\t%s"), atypes[i].id, atypes[i].parameters, atypes[i].description);
				framework->log(0, _T("Current attack: %d"), attack);
				continue;
			}
			bool found = false;
			TCHAR _a = (TCHAR)_wtoi(argv[1]);
			for (int i=0;;i++)
			{
				if (_a == atypes[i].id)
				{
					found = true;
					break;
				}
			}
			if (!found)
			{
				framework->log(0, _T("[-] Error: invalid attack type."));
				continue;
			}
			framework->setAttack(_a);
			framework->log(0, _T("[*] Changed attack from %d to %d"), attack, _a);
			TCHAR** ptr = argv+2;
			unsigned long start = GetTickCount();
			if (!framework->start(ptr, argc-2))
			{
				framework->log(0, _T("[-] Error (%d): %s"), GetLastError(), framework->getError());
				continue;
			}
			framework->log(0, _T("[*] Done, attack took %d second(s)"), (GetTickCount()-start)/1000);
		}
		else if (!_tcscmp(_T("show"), command))
		{
			framework->show_history_list();
		}
		else if (!_tcscmp(_T("cache"), command))
		{
			framework->show_cache_list();
		}
		else if (!_tcscmp(_T("debug"), command))
		{
			TCHAR debug = framework->getDebug();
			if (argc < 2)
			{
				framework->log(0, _T("debug <level>"));
				framework->log(0, _T("Current debug level: %d"), debug);
				continue;
			}
			TCHAR _d = (TCHAR)_wtoi(argv[1]);
			framework->setDebug(_d);
			framework->log(0, _T("[*] Changed debug from %d to %d"), debug, _d);
		}
		else if (!_tcscmp(_T("help"), command))
		{
			usage();
		}
		else if (!_tcscmp(_T("cls"), command))
		{
			system("cls");
			//for (int i=0; i<300; i++) _tprintf(_T("\r\n"));
		}
		else if (!_tcscmp(_T("quit"), command))
		{
			framework->log(0, _T("[*] Exiting..."));
			break;
		}
		else
		{
			framework->log(0, _T("'%s' is not reconized as a valid command."), command);
		}
	}
	return 0;
}
