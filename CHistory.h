#ifndef _HISTORY_H_
#define _HISTORY_H_
/*
	This file only contains the structs for the history variable.
	These structs keeps track of what has been found internally.
*/
#include <tchar.h>
#include <string.h>

struct ROW
{
	ROW()
	{
		this->length = 0;
		this->data = 0;
		this->index = 0;
	}
	unsigned long length;
	TCHAR* data;
	unsigned long index;
};

struct COLUMN
{
	COLUMN()
	{
		this->size = 0;
		this->name = 0;
		this->index = 0;
		memset(this->rows, 0, sizeof(rows));
	}
	unsigned long size;
	TCHAR* name;
	unsigned long index;
	ROW* rows[1024];
};

struct TABLE
{
	TABLE()
	{
		this->size = 0;
		this->name = 0;
		this->index = 0;
		this->columncount = 0;
		this->rowcount = 0;
		memset(this->columns, 0, sizeof(columns));
	}
	unsigned long size;
	TCHAR* name;
	unsigned long index;
	unsigned long columncount;
	long rowcount;
	COLUMN* columns[1024];
};

struct DATABASE
{
	DATABASE()
	{
		this->size = 0;
		this->name = 0;
		this->index = 0;
		this->tablecount = 0;
		memset(this->tables, 0, sizeof(tables));
	}
	unsigned long size;
	TCHAR* name;
	unsigned long index;
	unsigned long tablecount;
	TABLE* tables[1024];
};

struct HOST
{
	HOST()
	{
		this->size = 0;
		this->name = 0;
		this->index = 0;
		this->version = 0;
		this->databasecount = 0;
		memset(this->databases, 0, sizeof(databases));
	}
	unsigned long size;
	TCHAR* name;
	unsigned long index;
	unsigned long version;
	unsigned long databasecount;
	DATABASE* databases[1024];
};

class CHistory
{
private:
	unsigned long size;
	HOST* hosts[1024];

public:
	CHistory();
	~CHistory();

	HOST* addHost(TCHAR* hostname);
	DATABASE* addDatabase(TCHAR* hostname, TCHAR* dbname);
	TABLE* addTable(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename);
	COLUMN* addColumn(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname);
	ROW* addRow(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, TCHAR* rowdata);

	unsigned long getHostCount() {return this->size;}
	HOST* getHost(unsigned long index);
	HOST* getHost(TCHAR* hostname);
	DATABASE* getDatabase(TCHAR* hostname, TCHAR* dbname);
	DATABASE* getDatabase(TCHAR* hostname, unsigned long index);
	TABLE* getTable(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename);
	TABLE* getTable(TCHAR* hostname, TCHAR* dbname, unsigned long index);
	COLUMN* getColumn(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname);
	COLUMN* getColumn(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, unsigned long index);
	ROW* getRow(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, TCHAR* rowdata);
	ROW* getRow(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long index);
};

#endif
