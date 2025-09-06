#ifndef MODULE_H
#define MODULE_H

#ifdef _WIN32
#include <QtWinExtras>
#else

#endif



#include <QObject>
#include "tcp/imoduleTCPSess.h"
#include "smb_handler.h"

class StreamModule final : IModuleTCPSess
{
public:
	StreamModule();
	~StreamModule() override;

	void createModule() override;
	void showForm() override;

	bool initResources() override;
	bool freeResources() override;

	bool processData(unsigned char* d, unsigned int l) override;
	bool processTimeout() override;
	bool processNoData() override;

	bool setParameter(const char* _name, const char* _value, int _type) override;
	void tellParams() override;

protected:
	QPixmap bitmap;
};

#endif // MODULE_H
