#ifndef _CFramework_H_
#define _CFramework_H_

#define BSIFW_AUTHOR _T("Paul")
#define BSIFW_AUTHOR_EMAIL _T("")
#define BSIFW_VERSION _T("2.0")

//
#include <winsock2.h>
#pragma comment(lib, "ws2_32")
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp")

//
#include "CHistory.h"

// PCRE
#ifdef USE_PCRE_REGEX
#include <pcre.h>
#pragma comment(lib, "pcre")
#endif

#include <stdio.h>
#include <tchar.h>
#include <wchar.h>

#define RESULT_NOT_FOUND (TCHAR)-1

// http://msdn.microsoft.com/en-us/library/dd317756(VS.85).aspx
struct CODEPAGES
{
	unsigned int identifier;
	TCHAR* netname;
	TCHAR* info;
} static const codepages[] = {
	{037, _T("IBM037"), _T("IBM EBCDIC US-Canada")},
	{437, _T("IBM437"), _T("OEM United States")},
	{500, _T("IBM500"), _T("IBM EBCDIC International")},
	{708, _T("ASMO-708"), _T("Arabic (ASMO 708)")},
//	{709, _T(""), _T("Arabic (ASMO-449+, BCON V4)")},
//	{710, _T(""), _T("Arabic - Transparent Arabic")},
	{720, _T("DOS-720"), _T("Arabic (Transparent ASMO); Arabic (DOS)")},
	{737, _T("ibm737"), _T("OEM Greek (formerly 437G); Greek (DOS)")},
	{775, _T("ibm775"), _T("OEM Baltic; Baltic (DOS)")},
	{850, _T("ibm850"), _T("OEM Multilingual Latin 1; Western European (DOS)")},
	{852, _T("ibm852"), _T("OEM Latin 2; Central European (DOS)")},
	{855, _T("IBM855"), _T("OEM Cyrillic (primarily Russian)")},
	{857, _T("ibm857"), _T("OEM Turkish; Turkish (DOS)")},
	{858, _T("IBM00858"), _T("OEM Multilingual Latin 1 + Euro symbol")},
	{860, _T("IBM860"), _T("OEM Portuguese; Portuguese (DOS)")},
	{861, _T("ibm861"), _T("OEM Icelandic; Icelandic (DOS)")},
	{862, _T("DOS-862"), _T("OEM Hebrew; Hebrew (DOS)")},
	{863, _T("IBM863"), _T("OEM French Canadian; French Canadian (DOS)")},
	{864, _T("IBM864"), _T("OEM Arabic; Arabic (864)")},
	{865, _T("IBM865"), _T("OEM Nordic; Nordic (DOS)")},
	{866, _T("cp866"), _T("OEM Russian; Cyrillic (DOS)")},
	{869, _T("ibm869"), _T("OEM Modern Greek; Greek, Modern (DOS)")},
	{870, _T("IBM870"), _T("IBM EBCDIC Multilingual/ROECE (Latin 2); IBM EBCDIC Multilingual Latin 2")},
	{874, _T("windows-874"), _T("ANSI/OEM Thai (same as 28605, ISO 8859-15); Thai (Windows)")},
	{875, _T("cp875"), _T("IBM EBCDIC Greek Modern")},
	{932, _T("shift_jis"), _T("ANSI/OEM Japanese; Japanese (Shift-JIS)")},
	{936, _T("gb2312"), _T("ANSI/OEM Simplified Chinese (PRC, Singapore); Chinese Simplified (GB2312)")},
	{949, _T("ks_c_5601-1987"), _T("ANSI/OEM Korean (Unified Hangul Code)")},
	{950, _T("big5"), _T("ANSI/OEM Traditional Chinese (Taiwan; Hong Kong SAR, PRC); Chinese Traditional (Big5)")},
	{1026, _T("IBM1026"), _T("IBM EBCDIC Turkish (Latin 5)")},
	{1047, _T("IBM01047"), _T("IBM EBCDIC Latin 1/Open System")},
	{1140, _T("IBM01140"), _T("IBM EBCDIC US-Canada (037 + Euro symbol); IBM EBCDIC (US-Canada-Euro)")},
	{1141, _T("IBM01141"), _T("IBM EBCDIC Germany (20273 + Euro symbol); IBM EBCDIC (Germany-Euro)")},
	{1142, _T("IBM01142"), _T("IBM EBCDIC Denmark-Norway (20277 + Euro symbol); IBM EBCDIC (Denmark-Norway-Euro)")},
	{1143, _T("IBM01143"), _T("IBM EBCDIC Finland-Sweden (20278 + Euro symbol); IBM EBCDIC (Finland-Sweden-Euro)")},
	{1144, _T("IBM01144"), _T("IBM EBCDIC Italy (20280 + Euro symbol); IBM EBCDIC (Italy-Euro)")},
	{1145, _T("IBM01145"), _T("IBM EBCDIC Latin America-Spain (20284 + Euro symbol); IBM EBCDIC (Spain-Euro)")},
	{1146, _T("IBM01146"), _T("IBM EBCDIC United Kingdom (20285 + Euro symbol); IBM EBCDIC (UK-Euro)")},
	{1147, _T("IBM01147"), _T("IBM EBCDIC France (20297 + Euro symbol); IBM EBCDIC (France-Euro)")},
	{1148, _T("IBM01148"), _T("IBM EBCDIC International (500 + Euro symbol); IBM EBCDIC (International-Euro)")},
	{1149, _T("IBM01149"), _T("IBM EBCDIC Icelandic (20871 + Euro symbol); IBM EBCDIC (Icelandic-Euro)")},
	{1200, _T("utf-16"), _T("Unicode UTF-16, little endian byte order (BMP of ISO 10646); available only to managed applications")},
	{1201, _T("unicodeFFFE"), _T("Unicode UTF-16, big endian byte order; available only to managed applications")},
	{1250, _T("windows-1250"), _T("ANSI Central European; Central European (Windows)")},
	{1251, _T("windows-1251"), _T("ANSI Cyrillic; Cyrillic (Windows)")},
	{1252, _T("windows-1252"), _T("ANSI Latin 1; Western European (Windows)")},
	{1253, _T("windows-1253"), _T("ANSI Greek; Greek (Windows)")},
	{1254, _T("windows-1254"), _T("ANSI Turkish; Turkish (Windows)")},
	{1255, _T("windows-1255"), _T("ANSI Hebrew; Hebrew (Windows)")},
	{1256, _T("windows-1256"), _T("ANSI Arabic; Arabic (Windows)")},
	{1257, _T("windows-1257"), _T("ANSI Baltic; Baltic (Windows)")},
	{1258, _T("windows-1258"), _T("ANSI/OEM Vietnamese; Vietnamese (Windows)")},
	{1361, _T("Johab"), _T("Korean (Johab)")},
	{10000, _T("macintosh"), _T("MAC Roman; Western European (Mac)")},
	{10001, _T("x-mac-japanese"), _T("Japanese (Mac)")},
	{10002, _T("x-mac-chinesetrad"), _T("MAC Traditional Chinese (Big5); Chinese Traditional (Mac)")},
	{10003, _T("x-mac-korean"), _T("Korean (Mac)")},
	{10004, _T("x-mac-arabic"), _T("Arabic (Mac)")},
	{10005, _T("x-mac-hebrew"), _T("Hebrew (Mac)")},
	{10006, _T("x-mac-greek"), _T("Greek (Mac)")},
	{10007, _T("x-mac-cyrillic"), _T("Cyrillic (Mac)")},
	{10008, _T("x-mac-chinesesimp"), _T("MAC Simplified Chinese (GB 2312); Chinese Simplified (Mac)")},
	{10010, _T("x-mac-romanian"), _T("Romanian (Mac)")},
	{10017, _T("x-mac-ukrainian"), _T("Ukrainian (Mac)")},
	{10021, _T("x-mac-thai"), _T("Thai (Mac)")},
	{10029, _T("x-mac-ce"), _T("MAC Latin 2; Central European (Mac)")},
	{10079, _T("x-mac-icelandic"), _T("Icelandic (Mac)")},
	{10081, _T("x-mac-turkish"), _T("Turkish (Mac)")},
	{10082, _T("x-mac-croatian"), _T("Croatian (Mac)")},
	{12000, _T("utf-32"), _T("Unicode UTF-32, little endian byte order; available only to managed applications")},
	{12001, _T("utf-32BE"), _T("Unicode UTF-32, big endian byte order; available only to managed applications")},
	{20000, _T("x-Chinese_CNS"), _T("CNS Taiwan; Chinese Traditional (CNS)")},
	{20001, _T("x-cp20001"), _T("TCA Taiwan")},
	{20002, _T("x_Chinese-Eten"), _T("Eten Taiwan; Chinese Traditional (Eten)")},
	{20003, _T("x-cp20003 IBM5550"), _T("Taiwan")},
	{20004, _T("x-cp20004"), _T("TeleText Taiwan")},
	{20005, _T("x-cp20005"), _T("Wang Taiwan")},
	{20105, _T("x-IA5"), _T("IA5 (IRV International Alphabet No. 5, 7-bit); Western European (IA5)")},
	{20106, _T("x-IA5-German"), _T("IA5 German (7-bit)")},
	{20107, _T("x-IA5-Swedish"), _T("IA5 Swedish (7-bit)")},
	{20108, _T("x-IA5-Norwegian"), _T("IA5 Norwegian (7-bit)")},
	{20127, _T("us-ascii"), _T("US-ASCII (7-bit)")},
	{20261, _T("x-cp20261"), _T("T.61")},
	{20269, _T("x-cp20269"), _T("ISO 6937 Non-Spacing Accent")},
	{20273, _T("IBM273"), _T("IBM EBCDIC Germany")},
	{20277, _T("IBM277"), _T("IBM EBCDIC Denmark-Norway")},
	{20278, _T("IBM278"), _T("IBM EBCDIC Finland-Sweden")},
	{20280, _T("IBM280"), _T("IBM EBCDIC Italy")},
	{20284, _T("IBM284"), _T("IBM EBCDIC Latin America-Spain")},
	{20285, _T("IBM285"), _T("IBM EBCDIC United Kingdom")},
	{20290, _T("IBM290"), _T("IBM EBCDIC Japanese Katakana Extended")},
	{20297, _T("IBM297"), _T("IBM EBCDIC France")},
	{20420, _T("IBM420"), _T("IBM EBCDIC Arabic")},
	{20423, _T("IBM423"), _T("IBM EBCDIC Greek")},
	{20424, _T("IBM424"), _T("IBM EBCDIC Hebrew")},
	{20833, _T("x-EBCDIC-KoreanExtended"), _T("IBM EBCDIC Korean Extended")},
	{20838, _T("IBM-Thai"), _T("IBM EBCDIC Thai")},
	{20866, _T("koi8-r"), _T("Russian (KOI8-R); Cyrillic (KOI8-R)")},
	{20871, _T("IBM871"), _T("IBM EBCDIC Icelandic")},
	{20880, _T("IBM880"), _T("IBM EBCDIC Cyrillic Russian")},
	{20905, _T("IBM905"), _T("IBM EBCDIC Turkish")},
	{20924, _T("IBM00924"), _T("IBM EBCDIC Latin 1/Open System (1047 + Euro symbol)")},
	{20932, _T("EUC-JP"), _T("Japanese (JIS 0208-1990 and 0121-1990)")},
	{20936, _T("x-cp20936"), _T("Simplified Chinese (GB2312); Chinese Simplified (GB2312-80)")},
	{20949, _T("x-cp20949"), _T("Korean Wansung")},
	{21025, _T("cp1025"), _T("IBM EBCDIC Cyrillic Serbian-Bulgarian")},
//	{21027, _T(""), _T("(deprecated)")},
	{21866, _T("koi8-u"), _T("Ukrainian (KOI8-U); Cyrillic (KOI8-U)")},
	{28591, _T("iso-8859-1"), _T("ISO 8859-1 Latin 1; Western European (ISO)")},
	{28592, _T("iso-8859-2"), _T("ISO 8859-2 Central European; Central European (ISO)")},
	{28593, _T("iso-8859-3"), _T("ISO 8859-3 Latin 3")},
	{28594, _T("iso-8859-4"), _T("ISO 8859-4 Baltic")},
	{28595, _T("iso-8859-5"), _T("ISO 8859-5 Cyrillic")},
	{28596, _T("iso-8859-6"), _T("ISO 8859-6 Arabic")},
	{28597, _T("iso-8859-7"), _T("ISO 8859-7 Greek")},
	{28598, _T("iso-8859-8"), _T("ISO 8859-8 Hebrew; Hebrew (ISO-Visual)")},
	{28599, _T("iso-8859-9"), _T("ISO 8859-9 Turkish")},
	{28603, _T("iso-8859-13"), _T("ISO 8859-13 Estonian")},
	{28605, _T("iso-8859-15"), _T("ISO 8859-15 Latin 9")},
	{29001, _T("x-Europa"), _T("Europa 3")},
	{38598, _T("iso-8859-8-i"), _T("ISO 8859-8 Hebrew; Hebrew (ISO-Logical)")},
	{50220, _T("iso-2022-jp"), _T("ISO 2022 Japanese with no halfwidth Katakana; Japanese (JIS)")},
	{50221, _T("csISO2022JP"), _T("ISO 2022 Japanese with halfwidth Katakana; Japanese (JIS-Allow 1 byte Kana)")},
	{50222, _T("iso-2022-jp"), _T("ISO 2022 Japanese JIS X 0201-1989; Japanese (JIS-Allow 1 byte Kana - SO/SI)")},
	{50225, _T("iso-2022-kr"), _T("ISO 2022 Korean")},
	{50227, _T("x-cp50227"), _T("ISO 2022 Simplified Chinese; Chinese Simplified (ISO 2022)")},
//	{50229, _T(""), _T("ISO 2022 Traditional Chinese")},
	{57002, _T("x-iscii-de"), _T("ISCII Devanagari")},
	{57003, _T("x-iscii-be"), _T("ISCII Bengali")},
	{57004, _T("x-iscii-ta"), _T("ISCII Tamil")},
	{57005, _T("x-iscii-te"), _T("ISCII Telugu")},
	{57006, _T("x-iscii-as"), _T("ISCII Assamese")},
	{57007, _T("x-iscii-or"), _T("ISCII Oriya")},
	{57008, _T("x-iscii-ka"), _T("ISCII Kannada")},
	{57009, _T("x-iscii-ma"), _T("ISCII Malayalam")},
	{57010, _T("x-iscii-gu"), _T("ISCII Gujarati")},
	{57011, _T("x-iscii-pa"), _T("ISCII Punjabi")},
//	{50930, _T(""), _T("EBCDIC Japanese (Katakana) Extended")},
//	{50931, _T(""), _T("EBCDIC US-Canada and Japanese")},
//	{50933, _T(""), _T("EBCDIC Korean Extended and Korean")},
//	{50935, _T(""), _T("EBCDIC Simplified Chinese Extended and Simplified Chinese")},
//	{50936, _T(""), _T("EBCDIC Simplified Chinese")},
//	{50937, _T(""), _T("EBCDIC US-Canada and Traditional Chinese")},
//	{50939, _T(""), _T("EBCDIC Japanese (Latin) Extended and Japanese")},
	{51932, _T("euc-jp"), _T("EUC Japanese")},
	{51936, _T("EUC-CN"), _T("EUC Simplified Chinese; Chinese Simplified (EUC)")},
	{51949, _T("euc-kr"), _T("EUC Korean")},
//	{51950, _T(""), _T("EUC Traditional Chinese")},
	{52936, _T("hz-gb-2312"), _T("HZ-GB2312 Simplified Chinese; Chinese Simplified (HZ)")},
	{54936, _T("GB18030"), _T("Windows XP and later: GB18030 Simplified Chinese (4 byte); Chinese Simplified (GB18030)")},
	{65000, _T("utf-7"), _T("Unicode (UTF-7)")},
	{65001, _T("utf-8"), _T("Unicode (UTF-8)")}
};


class CFramework
{
	enum METHODS
	{
		METHOD_HISTORY,							// Not implemented
		METHOD_BRUTEFORCE,
		METHOD_BRUTEFORCE_SMART,
		METHOD_CACHING
	};

	enum ATTACKS
	{
		COUNT_DATABASES = 1,
		GET_DATABASE_NAME,
		COUNT_TABLES_IN_DATABASE,
		GET_TABLE_NAME_IN_DATABASE,
		COUNT_COLUMNS_IN_TABLE,
		GET_COLUMN_NAME_IN_TABLE,
		COUNT_ROWS_IN_TABLE,
		GET_ROW_DATA_IN_COLUMN,
		DATABASE_DO_ALL,
		GET_MYSQL_VERSION,
		RUN_CUSTOM_CRITERIA
	};

	typedef struct NEEDLES
	{
		NEEDLES()
		{
			this->length = 0;
			this->needle = 0;
		}
		unsigned int length;						// length of needle string
		TCHAR* needle;								// needle string
	} NEEDLES, *PNEEDLES;

	typedef struct CACHELIST
	{
		CACHELIST()
		{
			this->page = 0;
			this->data = 0;
			this->index = 0;
			this->data_needles = 0;
			this->data_needles_count = 0;
			this->real_needles = 0;
			this->real_needles_count = 0;
			this->chr = 0;
		}
		unsigned long page;							// real page number
		TCHAR* data;									// page data
		unsigned long index;							// index id in cache_list array
		PNEEDLES* data_needles;				// array of data split by '\r\n '
		unsigned long data_needles_count;		// array length
		PNEEDLES* real_needles;					// array of unique needles
		unsigned long real_needles_count;		// array length
		TCHAR chr;										// character the page represents in cache list
	} CACHELIST, *PCACHELIST;

	typedef struct CACHEHITS
	{
		CACHEHITS()
		{
			this->needlesfound = 0;
			this->pagechar = 0;
		}
		unsigned long needlesfound;
		TCHAR pagechar;
	} *PCACHEHITS;

private:
	//
	// Variables
	//
	// common
	TCHAR debug;				// Level of debug
	TCHAR* error;				// Error string
	CHistory history;			// History manager

	// host
	TCHAR* host;				// Host string
	TCHAR* ip;					// IP of host
	char* _ip;						// IP in MBCS aka. normal char[]
	unsigned short port;		// Port
	TCHAR* path;				// Path to vulnerable part
	TCHAR* rest;					// Part after vulnerable part

	// method
	TCHAR method;				// Method
	TCHAR** mparams;		// Parameters to method (if needed)
#ifdef USE_PCRE_REGEX
	pcre* re;						// Regular expression struct
	char* regexp;					// Regular expression holder
#else
	TCHAR* regexp;			// Search string holder
#endif

	// mysql injection data
	TCHAR* space;				// Space string
	TCHAR* end;					// End string
	unsigned long interval;	// Wait time between each query
	TCHAR* charset;			// Charset to use
	unsigned int charlen;		// Length of charset

	// attack info
	TCHAR atype;				// attack type
	TCHAR** aparams;		// parameters for atticking

	// internal info
	bool initialized;						// did we load WSAStartup() yet?
	unsigned long requests;			// amount of requests generated for attack
	TCHAR* common_tables;		// common_tables? // not implented yet
	TCHAR* ofile;						// output filename
	HANDLE hfile;						// handle to output filename
	WSAData wsa;						// WSAStartup() saver

	// caching method
	unsigned long cache_start;								// Start page
	unsigned long cache_max_pages;					// Max pages to cache
	PCACHELIST* cache_list;								// Final cache list
	unsigned long cache_pages_count;					// Amount of pages in cache
	unsigned long cache_needles_count;				// Amount of needles in cache

	// data parsing
	TCHAR* dynamic_start;			// Pointer to the dynamic start string
	TCHAR* dynamic_end;			// Pointer to the dynamic end string

	//
	// Functions
	//
	// Query functions
	TCHAR query_send(TCHAR* query);				// Send query to http_send
	TCHAR* http_send(TCHAR* packet);				// Send http_request
	bool getEncodingFromMetaData(char* page, unsigned long len, TCHAR* buffer, unsigned long buflen);
	TCHAR* convert_http_data(char* data, unsigned long len, TCHAR* encoding);		// Convert data from charset to UTF16 (wchar_t)
	void removeDynamicContent(TCHAR* page, unsigned long len);							// Remove dynamic content from page
	// Caching functions
	bool create_cache_list();									// Create cache list
	TCHAR search_cache_list(TCHAR* page);		// Search in cache list
	unsigned int fill_needle_list(TCHAR* data, unsigned int len, PNEEDLES* needles);

	void reset();													// Reset cache list

	TCHAR get_brute_result(TCHAR* sub_qry, bool use_charset, unsigned short start, unsigned short end);
	TCHAR get_smart_result(TCHAR* sub_qry, bool use_charset, unsigned short gap, unsigned short max);
	TCHAR get_cache_result(TCHAR* qry, bool use_charset);
	TCHAR get_result(TCHAR* qry, bool use_charset, unsigned short param1, unsigned short param2);

	unsigned long getDatabaseVersion();
	unsigned long getDatabaseCount();
	unsigned long getDatabaseNameLength(unsigned long id);
	TCHAR* getDatabaseName(unsigned long id, unsigned long length);
	unsigned long getTableCount(TCHAR* dbname);
	unsigned long getTableNameLength(TCHAR* dbname, unsigned long id);
	TCHAR* getTableName(TCHAR* dbname, unsigned long id, unsigned long length);
	unsigned long getColumnCount(TCHAR* dbname, TCHAR* tablename);
	unsigned long getColumnNameLength(TCHAR* dbname, TCHAR* tablename, unsigned long id);
	TCHAR* getColumnName(TCHAR* dbname, TCHAR* tablename, unsigned long id, unsigned long length);
	unsigned long getRowCount(TCHAR* dbname, TCHAR* tablename);
	unsigned long getRowDataLength(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long row);
	TCHAR* getRowData(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long row, unsigned long length);
	TCHAR* getCustomData(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, TCHAR* target, TCHAR* criteria);
	//unsigned long CFramework::getCustomQueryRowCount(TCHAR* query);
	bool checkExistence(TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long row, TCHAR* criteria);
	bool checkExistence(TCHAR* query);

public:
	CFramework::CFramework();
	CFramework::~CFramework();

	TCHAR* getError() {return this->error;}
	TCHAR* getHost() {return this->host;}
	TCHAR* getIP() {return this->ip;}
	unsigned short getPort() {return this->port;}
	TCHAR* getPath() {return this->path;}			// TODO: path is not in unicode - should be in hex %C41F for example - convert it back to unicode and return
	TCHAR* getRest() {return this->rest;}			// TODO: path is not in unicode - should be in hex %C41F for example - convert it back to unicode and return
	TCHAR getMethod() {return this->method;}
	TCHAR* getSpace() {return this->space;}
	TCHAR* getEnd() {return this->end;}
	unsigned short getLength() {return this->charlen;}
	unsigned long getInterval() {return this->interval;}
	TCHAR getAttack() {return this->atype;}
	TCHAR getDebug() {return this->debug;}
	TCHAR* getDynamicStart() {return this->dynamic_start;}
	TCHAR* getDynamicEnd() {return this->dynamic_end;}
	TCHAR* getCharset() {return this->charset;}
	HANDLE getFileHandle() {return this->hfile;}

	void log(wchar_t level, wchar_t* text, ...);
	void log(char level, char* text, ...);

	bool initialize();					// First thing needed to be called - starting WSA stuff
	bool setHost(TCHAR* host, unsigned short port=80);
	bool setPath(TCHAR* path, TCHAR* rest=0);
	void setInterval(unsigned long interval);
	bool setMethod(TCHAR method, TCHAR** argv, unsigned long argc);
	void setSpace(TCHAR* space);
	void setEnd(TCHAR* end);
	bool setLength(unsigned short length);
	void setAttack(TCHAR type);
	void setDebug(TCHAR debug) {this->debug = debug;}
	void setDynamicTags(TCHAR* start, TCHAR* end);
	bool validateConfig();			// Checks if needed variables are set

	bool start(TCHAR** params=0, unsigned long argc=0);

	bool getDatabaseInfo();
	void show_cache_list();		// Print out cache info
	void show_history_list();		// Print out history info			

protected:
};

#endif