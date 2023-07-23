#include "CHistory.h"

CHistory::CHistory()
{
	this->size = 0;
	memset(this->hosts, 0, sizeof(hosts));
}

CHistory::~CHistory()
{
	if (this->size)
	{
		for (unsigned int a=0; a<this->size; a++)
		{
			HOST* host = this->hosts[a];
			for (unsigned int b=0; b<host->size; b++)
			{
				DATABASE* db = host->databases[b];
				for (unsigned int c=0; c<db->size; c++)
				{
					TABLE* table = db->tables[c];
					for (unsigned int d=0; d<table->size; d++)
					{
						COLUMN* column = table->columns[d];
						for (unsigned int e=0; e<table->size; e++)
						{
							ROW* row = column->rows[e];
							delete[] row->data;
							delete row;
						}
						delete[] column->name;
						delete column;
					}
					delete[] table->name;
					delete table;
				}
				delete[] db->name;
				delete db;
			}
			delete[] host->name;
			delete host;
		}
	}
}

HOST* CHistory::getHost(TCHAR* hostname)
{
	if (!hostname) return 0;
	for (unsigned int a=0; a<this->size; a++)
	{
		HOST* host = this->hosts[a];
		if (!_tcsicmp(hostname, host->name))
			return host;
	}
	return 0;
}
HOST* CHistory::getHost(unsigned long index)
{
	if (index > this->size) 
		return 0;
	else
		return hosts[index];
}

DATABASE* CHistory::getDatabase(TCHAR* hostname, TCHAR* dbname)
{
	if (!dbname) return 0;
	HOST* host = this->getHost(hostname);
	if (host)
	{
		for (unsigned int b=0; b<host->size; b++)
		{
			DATABASE* db = host->databases[b];
			if (!_tcsicmp(dbname, db->name))
				return db;
		}
	}
	return 0;
}
DATABASE* CHistory::getDatabase(TCHAR* hostname, unsigned long id)
{
	if (!id) return 0;
	HOST* host = this->getHost(hostname);
	if (host)
	{
		for (unsigned long int a=0; a<host->size; a++)
			if (host->databases[a]->index == id) return host->databases[a];
	}
	return 0;
}

TABLE* CHistory::getTable(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename)
{
	if (!tablename) return 0;
	DATABASE* db = this->getDatabase(hostname, dbname);
	if (db)
	{
		for (unsigned int c=0; c<db->size; c++)
		{
			TABLE* table = db->tables[c];
			if (!_tcsicmp(tablename, table->name))
				return table;
		}
	}
	return 0;
}
TABLE* CHistory::getTable(TCHAR* hostname, TCHAR* dbname, unsigned long id)
{
	if (!id) return 0;
	DATABASE* db = this->getDatabase(hostname, dbname);
	if (db)
	{
		for (unsigned int a=0; a<db->size; a++)
			if (db->tables[a]->index == id) return db->tables[a];
	}
	return 0;
}

COLUMN* CHistory::getColumn(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname)
{
	if (!columnname) return 0;
	TABLE* table = this->getTable(hostname, dbname, tablename);
	if (table)
	{
		for (unsigned int d=0; d<table->size; d++)
		{
			COLUMN* column = table->columns[d];
			if (!_tcsicmp(columnname, column->name))
				return column;
		}
	}
	return 0;
}
COLUMN* CHistory::getColumn(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, unsigned long id)
{
	if (!id) return 0;
	TABLE* table = this->getTable(hostname, dbname, tablename);
	if (table)
	{
		for (unsigned int a=0; a<table->size; a++)
			if (table->columns[a]->index == id) return table->columns[a];
	}
	return 0;
}

ROW* CHistory::getRow(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, TCHAR* rowdata)
{
	if (!rowdata) return 0;
	COLUMN* column = this->getColumn(hostname, dbname, tablename, columnname);
	if (column)
	{
		for (unsigned int e=0; e<column->size; e++)
		{
			ROW* row = column->rows[e];
			if (!_tcsicmp(rowdata, row->data))
				return row;
		}
	}
	return 0;
}
ROW* CHistory::getRow(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, unsigned long id)
{
	if (!id) return 0;
	TABLE* table = this->getTable(hostname, dbname, tablename);
	if (table)
	{
		COLUMN* column = this->getColumn(hostname, dbname, tablename, columnname);
		if (column)
		{
			for (unsigned int a=0; a<column->size; a++)
				if (column->rows[a]->index == id) return column->rows[a];
		}
	}
	return 0;
}



HOST* CHistory::addHost(TCHAR* hostname)
{
	if (!hostname) return 0;
	HOST* host = 0;
	if (!(host = this->getHost(hostname)))
	{
		this->hosts[this->size] = new HOST;
		host = this->hosts[this->size];
		host->index = ++this->size;
		unsigned long len = _tcslen(hostname)+1;
		host->name = new TCHAR[len];
		memset(host->name, 0, len*sizeof(TCHAR));
		_tcscpy_s(host->name, len, hostname);
	}
	return host;
}

DATABASE* CHistory::addDatabase(TCHAR* hostname, TCHAR* dbname)
{
	if (!dbname) return 0;
	HOST* host = this->addHost(hostname);
	DATABASE* db = 0;
	if (!(db = this->getDatabase(hostname, dbname)))
	{
		host->databases[host->size] = new DATABASE;
		db = host->databases[host->size];
		db->index = ++host->size;
		unsigned long len = _tcslen(dbname)+1;
		db->name = new TCHAR[len];
		memset(db->name, 0, len*sizeof(TCHAR));
		_tcscpy_s(db->name, len, dbname);
	}
	return db;
}

TABLE* CHistory::addTable(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename)
{
	if (!tablename) return 0;
	DATABASE* db = this->addDatabase(hostname, dbname);
	TABLE* table = 0;
	if (!(table = this->getTable(hostname, dbname, tablename)))
	{
		db->tables[db->size] = new TABLE;
		table = db->tables[db->size];
		table->index = ++db->size;
		unsigned long len = _tcslen(tablename)+1;
		table->name = new TCHAR[len];
		memset(table->name, 0, len*sizeof(TCHAR));
		_tcscpy_s(table->name, len, tablename);
	}
	return table;
}

COLUMN* CHistory::addColumn(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname)
{
	if (!columnname) return 0;
	TABLE* table = this->addTable(hostname, dbname, tablename);
	COLUMN* column = 0;
	if (!(column = this->getColumn(hostname, dbname, tablename, columnname)))
	{
		table->columns[table->size] = new COLUMN;
		column = table->columns[table->size];
		column->index = ++table->size;
		unsigned len = _tcslen(columnname)+1;
		column->name = new TCHAR[len];
		memset(column->name, 0, len*sizeof(TCHAR));
		_tcscpy_s(column->name, len, columnname);
	}
	return column;
}

ROW* CHistory::addRow(TCHAR* hostname, TCHAR* dbname, TCHAR* tablename, TCHAR* columnname, TCHAR* rowdata)
{
	if (!rowdata) return 0;
	COLUMN* column = this->addColumn(hostname, dbname, tablename, columnname);
	TABLE* table = this->getTable(hostname, dbname, tablename);
	ROW* row = 0;
	if (!(row = this->getRow(hostname, dbname, tablename, columnname, rowdata)))
	{
		column->rows[column->size] = new ROW;
		row = column->rows[column->size];
		row->length = _tcslen(rowdata);
		row->index = ++column->size;
		unsigned long len = _tcslen(rowdata)+1;
		row->data = new TCHAR[len];
		memset(row->data, 0, len*sizeof(TCHAR));
		_tcscpy_s(row->data, len, rowdata);
	}
	return row;
}
