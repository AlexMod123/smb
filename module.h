#ifndef MODULE_H
#define MODULE_H

 #include <QtWinExtras>


#include <cstdio>    //для sprintf_s()

#include <cstring>
#include <map>

#include <QObject>
#include <QMap>
#include <QString>
#include <QBitmap>
#include <QApplication>

#include "tcp\IModuleTCPSess.h" 
#include "smb_handler.h"

class StreamModule:IModuleTCPSess
{
public:
	//реализация интерфейса модуля - эти методы ДОЛЖНЫ существовать 
	StreamModule();
	~StreamModule();

	virtual void __stdcall createModule();
	virtual void __stdcall showForm();

	virtual bool __stdcall initResources();
	virtual bool __stdcall freeResources();

	virtual bool __stdcall processData(unsigned char* d, unsigned int l);
	virtual bool __stdcall processTimeout();
	virtual bool __stdcall processNoData();

	virtual bool __stdcall setParameter(const char* _name, const char* _value, int _type);
	virtual void __stdcall tellParams();

protected:
	QPixmap       bitmap;
};

#endif // MODULE_H
