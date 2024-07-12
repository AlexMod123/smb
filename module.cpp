#include "module.h"

const char* mName        = "SMB";
const char* mDescription = "Processing of server message block protocol";
const char* mGroup       = "[OSI-7] Application Layer";
const char* mVersion     = "0.0.1";
const bool  mIsGenerator = false;
const bool  mIsTerminator = false;

void initTranslator()
{
	QObject::tr("SMB");
	QObject::tr("Processing of server message block protocol");
	QObject::tr("[OSI-7] Application Layer");
}

StreamModule::StreamModule() : IModuleTCPSess(mName, mDescription, mGroup, mVersion, mIsGenerator, mIsTerminator), bitmap(":/img/NG_Module_SMB.png")
{
	h_Bitmap = QtWin::toHBITMAP(bitmap, QtWin::HBitmapPremultipliedAlpha);
}

void __stdcall StreamModule::createModule()
{	
}

void __stdcall StreamModule::showForm()
{
}

StreamModule::~StreamModule()
{
}

bool __stdcall StreamModule::initResources()
{
	clear_sessions<SMB_Handler>();
	return true;
}

bool __stdcall StreamModule::freeResources()
{
	clear_sessions<SMB_Handler>();
	return true;
}

bool __stdcall StreamModule::processData(unsigned char* d, unsigned int l)
{
	//получаем IP адреса и порты
	StreamIdentify::idtypeIPv4 ipSrc;
	StreamIdentify::idtypeIPv4 ipDst;

	StreamIdentify::idtypeUInt16 portSrc;
	StreamIdentify::idtypeUInt16 portDst;
	StreamIdentify::idtypeTCPParams tcpParams;

	bool ret = false;

	ret = kernel->getIdentify(StreamIdentify::STR_IPV4_SRC, &ipSrc);if (!ret) return true;
	ret = kernel->getIdentify(StreamIdentify::STR_IPV4_DST, &ipDst);if (!ret) return true;
	ret = kernel->getIdentify(StreamIdentify::STR_PORT_SRC, &portSrc);if (!ret) return true;
	ret = kernel->getIdentify(StreamIdentify::STR_PORT_DST, &portDst);if (!ret) return true;
	ret = kernel->getIdentify(StreamIdentify::STR_TCP_SESSION_PARAMS, &tcpParams);if (!ret) return true;

	tcp<SMB_Handler>(kernel,ipSrc,ipDst,portSrc,portDst,tcpParams,d,l);

	return true;
}

bool __stdcall StreamModule::processNoData()
{
	return true;
}

bool __stdcall StreamModule::processTimeout()
{
	timeout_sessions<SMB_Handler>();

	kernel->showStats(QObject::tr("Open TCP sessions").toStdString().c_str(), qPrintable(QString::number(sessions.size())) );

	float _ratio = 0;
	if (m_hndlrs_all)
		_ratio = ( (float)m_hndlrs_ok / m_hndlrs_all )*100;

	kernel->showStats(QObject::tr("Handlers Ok/All").toStdString().c_str(),
		qPrintable(QString::number(m_hndlrs_ok) + 
		"/" + QString::number(m_hndlrs_all) +
		": " + QString("%1").arg(_ratio,0,'f',3) ) );
	
	return true;
}

void __stdcall StreamModule::tellParams()
{
}

bool __stdcall StreamModule::setParameter(const char* _name, const char* _value, int _type)
{
	return true;
}

extern "C" __declspec(dllexport) IModule*  getModuleInstance()
{
	return reinterpret_cast<IModule*>(new StreamModule());;
}

extern "C" __declspec(dllexport) void  removeModuleInstance(IModule* aVal)
{
	//call CModule destructor
	if ( aVal != NULL )
	{
		delete (StreamModule*) aVal;
	}
}