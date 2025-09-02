#ifndef MODULE_H
#define MODULE_H

#ifdef _WIN32
#include <QtWinExtras>
#endif

#include <cstdio>

#include <cstring>
#include <map>

#include <QObject>
#include <QMap>
#include <QString>
#include <QBitmap>
#include <QApplication>

#include "../../../include/tcp/imoduleTCPSess.h"
#include "../smb_handler.h"

class StreamModule : IModuleTCPSess
{
public:
	StreamModule();
	~StreamModule() override;

	virtual void createModule();
	virtual void showForm();

	virtual bool initResources();
	virtual bool freeResources();

	virtual bool processData(unsigned char* d, unsigned int l);
	virtual bool processTimeout();
	virtual bool processNoData();

	virtual bool setParameter(const char* _name, const char* _value, int _type);
	virtual void tellParams();

protected:
	QPixmap bitmap;
};

#endif // MODULE_H
