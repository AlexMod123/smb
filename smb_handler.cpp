#include "smb_handler.h"
#include "methods_files.h"
#if defined _M_IX86
#include "streamutils.h"
#elif defined _M_X64
extern "C" {
	uint16_t _htons16(uint16_t x);
};
extern "C" {
	uint32_t _htons32(uint32_t x);
};
#endif
#if defined (_MSC_VER) && (_MSC_VER < 1900) 
	#define snprintf _snprintf_s  //MSVC не считает С99 стандартом (до 1900 версии)
#endif

#define min(a,b) (a<b?a:b) 


SMB_Handler::SMB_Handler(IKernel* kernel, uint32_t ip_src, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst)
	: TCPHandler(kernel, ip_src, ip_dst, port_src, port_dst)
{
	m_req_inc = m_rep_inc = false;

	m_file_handle = 0;

	this->ip_src = ip_src;
	this->ip_dst = ip_dst;
	
	memset(currentBuffer, 0x00, SMB_MAX_SEGMENT_LENGTH);
}

SMB_Handler::~SMB_Handler()
{
	
}

// парсим буффер для типа соединения WRITE
void SMB_Handler::parseBufferWrite()
{
	int curShifft = 0;

	while (true)
	{
		if (!lenBuffWrite)
			break;

		// проверили что это SMB (фиксированая длина заголовка SMB 64 байта)
		if (bufferWRITE[curShifft + 4] == 0xFE && bufferWRITE[curShifft + 5] == 0x53 && bufferWRITE[curShifft + 6] == 0x4D && bufferWRITE[curShifft + 7] == 0x42)
		{
			// перед SMB идет 4 байта (NetBIOS)
			uint32_t lenBytePacketSMB = 0;										// длина всего SMB пакета + 4
			memcpy(&lenBytePacketSMB, bufferWRITE + curShifft, sizeof(lenBytePacketSMB));
			lenBytePacketSMB = _htons32(lenBytePacketSMB);
			lenBytePacketSMB += 4;

			if (lenBytePacketSMB > lenBuffWrite)
			{
				// сделано для того чтобы в начале буфера всегда был идентифкатор что это SMB пакет
				memcpy(bufferWRITE, bufferWRITE + curShifft, lenBuffWrite);		// перезаписываем буффер 
				break;
			}

			// определяем тип команды
			// нас интересуют только WRITE или CLOSE
			if (bufferWRITE[curShifft + 16] == SMB_HEADER_TYPE_WRITE)			// фиксированная длина заголовка WRITE 49 байт
			{
				curShifft += 16;
				uint32_t lenData = 0;											// длина поля данных (узнали размер пакета который надо собрать)
				currentOffsetLen = 0;											// смещение в файле от прошлого пакета по байтам 

				curShifft += 56;				memcpy(&lenData, bufferWRITE + curShifft, sizeof(lenData));
				curShifft += 4;					memcpy(&currentOffsetLen, bufferWRITE + curShifft, sizeof(currentOffsetLen));

				// + 8 байт смещение + 16 байт идентификатор файла + 4 байта № канала + 4 байта резерв + 8 байт НУ
				curShifft += 40;												// пропускаем их до начала данных

				int fixOff = 116;												// итого до начала данных необходимо пропустить 117 байт (4 + 64 + 49): 117 - 1 тк счтаем с 0

				if ((lenBuffWrite - fixOff) >= lenData)							// пишем ЦЕЛЫЙ пакет данных в сессию
				{
					memcpy(currentBuffer + lenCurrentBuff, bufferWRITE + curShifft, lenData);					// пишем данные в буффер для последующей записи в файл
					lenCurrentBuff += lenData;
					flushBuffer();
				}
				else															// если пакет НЕ ЦЕЛЫЙ до выходим из цикла и ждем пока буффер накопиться
				{
					// сделано для того чтобы в начале буфера всегда был идентифкатор что это SMB пакет
					// в теории такого быть не может
					memcpy(bufferWRITE, bufferWRITE + curShifft, lenBuffWrite);	// перезаписываем буфер
					break;
				}
				curShifft -= fixOff;											// вернули сдвиг в начало SMB пакета для последующего корретного чтения данных из буфера
			}
			else if (bufferWRITE[curShifft + 16] == SMB_HEADER_TYPE_CLOSE)
			{
				uint32_t currenTreeId = 0;
				curShifft += 40;				memcpy(&currenTreeId, bufferWRITE + curShifft, sizeof(currenTreeId));
				if (currenTreeId == sessionTreeId)								// сверяем идентификаторы сессии
					closeFile(false);

				curShifft -= 40;
			}

			curShifft += lenBytePacketSMB;										// сдвигаемся на длину SMB пакета
			lenBuffWrite -= lenBytePacketSMB;
		}
		else {
			// неизвестные данные или каким то образом сбился сдвиг в буфере
			break;
		}
	}
}

// парсим буффер для типа соединения READ
void SMB_Handler::parseBufferRead() 
{
	int curShifft = 0;

	while (true)
	{
		if (!lenBuffRead)
			break;

		// проверили что это SMB (фиксированая длина заголовка SMB 64 байта)
		if (bufferREAD[curShifft+4] == 0xFE && bufferREAD[curShifft+5] == 0x53 && bufferREAD[curShifft+6] == 0x4D && bufferREAD[curShifft+7] == 0x42)
		{
			// перед SMB идет 4 байта (NetBIOS)
			uint32_t lenBytePacketSMB = 0;															// длина всего SMB пакета + 4
			memcpy(&lenBytePacketSMB, bufferREAD + curShifft, sizeof(lenBytePacketSMB));
			lenBytePacketSMB = _htons32(lenBytePacketSMB);
			lenBytePacketSMB += 4;

			if (lenBytePacketSMB > lenBuffRead)
			{
				// сделано для того чтобы в начале буфера всегда был идентифкатор что это SMB пакет
				memcpy(bufferREAD, bufferREAD + curShifft, lenBuffRead);							// перезаписываем буффер 
				break;
			}

			// определяем тип команды
			// нас интересуют только READ или CLOSE
			if (bufferREAD[curShifft+16] == SMB_HEADER_TYPE_READ)									// фиксированная длина заголовка READ 17 байт
			{
				curShifft += 16;
				uint32_t lenData = 0;																// длина поля данных (узнали размер пакета который надо собрать)
				uint32_t lenOffsetData = 0;															// смещение в файле от прошлого пакета по байтам 
				
				curShifft += 56;				memcpy(&lenData, bufferREAD + curShifft, sizeof(lenData));
				curShifft += 4;					memcpy(&lenOffsetData, bufferREAD + curShifft, sizeof(lenOffsetData));

				curShifft += 8;																		// неустановленные 4 байта (всегда 0) пропускаем их до начала данных
				int fixOff = 84;																	// итого до начала данных необходимо пропустить 85 байт (4 + 64 + 17): 85 - 1 тк счтаем с 0

				if ((lenBuffRead - fixOff) >= lenData)												// пишем ЦЕЛЫЙ пакет данных в сессию
				{
					memcpy(currentBuffer + lenCurrentBuff, bufferREAD + curShifft, lenData);		// пишем данные в буффер для последующей записи в файл
					lenCurrentBuff += lenData;
					flushBuffer();
				}
				else																				// если пакет НЕ ЦЕЛЫЙ до выходим из цикла и ждем пока буффер накопиться
				{
					// сделано для того чтобы в начале буфера всегда был идентифкатор что это SMB пакет
					// в теории такого быть не может
					memcpy(bufferREAD, bufferREAD + curShifft, lenBuffRead);						// перезаписываем буфер
					break;
				}
				curShifft -= fixOff;																// вернули сдвиг в начало SMB пакета для последующего корретного чтения данных из буфера
			}
			else if (bufferREAD[curShifft + 16] == SMB_HEADER_TYPE_CLOSE)
			{
				uint32_t currenTreeId = 0;
				curShifft += 40;				memcpy(&currenTreeId, bufferREAD + curShifft, sizeof(currenTreeId));
				if(currenTreeId == sessionTreeId)													// сверяем идентификаторы сессии
					closeFile(false);

				curShifft -= 40;
			}

			curShifft += lenBytePacketSMB;															// сдвигаемся на длину SMB пакета
			lenBuffRead -= lenBytePacketSMB;
		}
		else {
			// неизвестные данные или каким то образом сбился сдвиг в буфере
			break;
		}
	}
}

// ищем SMB + проверяем тип трафика
SMB_Handler::COMMAND_TYPE SMB_Handler::parseSMBHeader(unsigned char* payload, int payload_len)
{
	if (payload_len < 17)
	{
		if (isOpenSession)
			return COMMAND_TYPE::DATA;

		return COMMAND_TYPE::UNK;
	}

	// ищем идентификатор SMB
	if (payload[4] == 0xFE && payload[5] == 0x53 && payload[6] == 0x4D && payload[7] == 0x42)
	{
		if (payload[16] == SMB_HEADER_TYPE_WRITE && payload_len >= 117)									// однозначно определяем что тип передачи write (в read длина пакета типа WRITE = 84)
		{
			// принцип работы следующий
			// как только прошла первая команда WRITE начинаем писать буффер размером 2^17 - 131072
			// буфер заканчивается по длине или как только прошла команда на закрытие соединения
			// после наполнения буфера начинаем парсить его на наличие всевозможных команд
			// данные пишем в сессию, остальные команды пропускаем

			if ((lenBuffWrite + payload_len) > MAX_LENGTH_BUFF_WRITE)
				parseBufferWrite();																		// парсим накопившийся буффер

			sessionTreeId = 0;																			// получаем идентификатор дерева текуще сессии
			memcpy(&sessionTreeId, payload + 40, sizeof(sessionTreeId));

			// продолжаем копить буффер до максимума
			memcpy(bufferWRITE + lenBuffWrite, payload, payload_len);									// пишем данные в буффер 
			lenBuffWrite += payload_len;
			
			return COMMAND_TYPE::WRITE;
		}
		else if (payload[16] == SMB_HEADER_TYPE_READ && (payload_len % 117))							// 117 - длина стандартного пакета типа READ когда данные передаются по соединению WRITE
		{
			// принцип работы следующий
			// как только прошла первая команда READ начинаем писать буффер размером 2^17 - 131072
			// буфер заканчивается по длине или как только прошла команда на закрытие соединения
			// после наполнения буфера начинаем парсить его на наличие всевозможных команд
			// данные пишем в сессию, остальные команды пропускаем

			if ((lenBuffRead + payload_len) > MAX_LENGTH_BUFF_READ)
				parseBufferRead();																		// парсим накопившийся буффер

			sessionTreeId = 0;																			// получаем идентификатор дерева текуще сессии
			memcpy(&sessionTreeId, payload + 40, sizeof(sessionTreeId));

			// продолжаем копить буффер до максимума
			memcpy(bufferREAD + lenBuffRead, payload, payload_len);										// пишем данные в буффер 
			lenBuffRead += payload_len;

			return COMMAND_TYPE::READ;
		}
		else if (payload[16] == SMB_HEADER_TYPE_CLOSE)													// тип CLOSE - закрытие текущего файла (увязать с конкретной сессией нет возможности по этому в тупую)
		{
			uint32_t currenTreeId = 0;
			memcpy(&currenTreeId, payload + 40, sizeof(currenTreeId));

			if (isOpenSession && (currenTreeId == sessionTreeId))										// сверяем идентификаторы сессии
			{
				isOpenSession = false;

				//memset(currentBuffer, 0x00, SMB_MAX_SEGMENT_LENGTH);
				lenCurrentBuff = 0;
				m_result = TCPHANDLER_RESULT_DONE_OK;
				return COMMAND_TYPE::CLOSE;
			}
			else
				return COMMAND_TYPE::UNK;
		}
		else
			return COMMAND_TYPE::UNK;
	}

	return COMMAND_TYPE::DATA;
}

int SMB_Handler::procSMB(unsigned char* d, int payload_len)
{
	if (!isOpenSession)	// проверяем была ли открыта сессия на запись
	{
		switch (parseSMBHeader(d, payload_len))															// открытие сессии
		{
		case COMMAND_TYPE::WRITE:
			isOpenSession = true;
			m_result = TCPHANDLER_RESULT_NOT_FOUND;

			sessionType = SESSION_TYPE::WRITE;
			break;
		case COMMAND_TYPE::READ:
			isOpenSession = true;
			m_result = TCPHANDLER_RESULT_NOT_FOUND;

			sessionType = SESSION_TYPE::READ;
			break;
		default:
			return payload_len;
		}
	}
	else
	{
		switch (parseSMBHeader(d, payload_len))															// обработка поступающих данных для открытой сессии
		{
		case COMMAND_TYPE::DATA: {

			switch (sessionType)
			{
			case SESSION_TYPE::READ: {
				if ((lenBuffRead + payload_len) > MAX_LENGTH_BUFF_READ)
					parseBufferRead();																	// парсим накопившийся буффер

				// продолжаем копить буффер до максимума
				memcpy(bufferREAD + lenBuffRead, d, payload_len);										// пишем данные в буффер 
				lenBuffRead += payload_len;
				break;
			}
			case SESSION_TYPE::WRITE: {

				if ((lenBuffWrite + payload_len) > MAX_LENGTH_BUFF_WRITE)
					parseBufferWrite();																	// парсим накопившийся буффер

				// продолжаем копить буффер до максимума
				memcpy(bufferWRITE + lenBuffWrite, d, payload_len);										// пишем данные в буффер 
				lenBuffWrite += payload_len;
				break;
			}
			default:
				break;
			}
			break;
		}
		case COMMAND_TYPE::CLOSE:
			// случай когда размер сессии меньше макс размера буфера при закрытии сессии
			switch (sessionType)
			{
				case SESSION_TYPE::READ: {
					parseBufferRead();																	// парсим накопившийся буффер
					break;
				}
				case SESSION_TYPE::WRITE: {
					parseBufferWrite();																	// парсим накопившийся буффер
					break;
				}
			}

			closeFile(false);
			break;
		default:
			return payload_len;
		}
	}
}

int SMB_Handler::onRequestStream( unsigned char *d, int payload_len, bool inc, bool push )
{
	if (inc) m_req_inc = true;
	if (!payload_len)
		return payload_len;

	return procSMB(d, payload_len);
}

int SMB_Handler::onReplyStream( unsigned char *d, int payload_len, bool inc, bool push )
{
	if (inc) m_rep_inc = true;
	if (!payload_len)	
		return payload_len;

	return procSMB(d, payload_len);
}

// сброс буффера
void SMB_Handler::flushBuffer()
{
	switch (sessionType)
	{
	case SMB_Handler::SESSION_TYPE::READ: {
		writeSession(currentBuffer, lenCurrentBuff);
		lenCurrentBuff = 0;
		break;
	}
	case SMB_Handler::SESSION_TYPE::WRITE: {
		if (offsetLenData == currentOffsetLen)														// ожидаемый сдиг и фактический совпали
		{
			writeSession(currentBuffer, lenCurrentBuff);
			offsetLenData += lenCurrentBuff;														// задали смещение которое ожидаем следующим
		}
		else {																						// ожидаемый сдиг и фактический не совпали (кладем пакет в стек)
			SMBSegment* newSegment = new SMBSegment(currentBuffer, lenCurrentBuff, currentOffsetLen);
			m_smbQueue.push(newSegment);
		}

		while (m_smbQueue.size())																	// проверяем если пакеты в стеке для записи в файл							
		{
			SMBSegment* it = m_smbQueue.top();

			if (offsetLenData == it->shifftPayload)
			{
				writeSession(it->data, it->lenPayload);
				offsetLenData += it->lenPayload;													// задали смещение которое ожидаем следующим

				m_smbQueue.pop();
				delete it;

				continue;
			}
			else
				break;
		}

		//memset(currentBuffer, 0, SMB_MAX_SEGMENT_LENGTH);
		lenCurrentBuff = 0;
		break;
	}
	case SMB_Handler::SESSION_TYPE::UNK:
		break;
	default:
		break;
	}
}

// сброс стека сегментов
void SMB_Handler::flushQueue(bool& state)
{
	// в случае если в стеке остались сегменты файла, но были пропущены остальные куски файла то забиваем пропуски нулями
	while (m_smbQueue.size())
	{
		SMBSegment* it = m_smbQueue.top();

		if (offsetLenData == it->shifftPayload)
		{
			writeSession(it->data, it->lenPayload);
			offsetLenData += it->lenPayload;														// задали смещение которое ожидаем следующим

			m_smbQueue.pop();
			delete it;

			continue;
		}
		else																						// добиваем нулями до куска данных
		{
			int allowZero = it->shifftPayload - offsetLenData;

			if ((allowZero  < 0) || (allowZero > SMB_MAX_SEGMENT_LENGTH))
			{
				state = true;																		// файл будем в INCOMPLETE
				m_smbQueue.pop();
				delete it;
				continue;
			}

			uint8_t padding[SMB_MAX_SEGMENT_LENGTH];
			memset(padding, 0x00, allowZero);
			writeSession(padding, allowZero);

			offsetLenData += allowZero;
			state = true;																			// файл будем в INCOMPLETE
		}
	}
}

// пишем текуший сеанс
void SMB_Handler::writeSession(unsigned char* payload, int payload_len)
{
	if (!m_file_handle)
		createSession();

	if (m_file_handle && payload_len)
	{		
		if (payload_len > MAX_SEGMENT_LENGTH)														// делим пакет на сегменты
		{
			cacheWrite(m_kernel, m_file_handle, FILEOFFSET_CONTINUE, payload, MAX_SEGMENT_LENGTH);

			int ost = payload_len % MAX_SEGMENT_LENGTH;
			cacheWrite(m_kernel, m_file_handle, FILEOFFSET_CONTINUE, payload+ MAX_SEGMENT_LENGTH, ost);
		}
		else
			cacheWrite(m_kernel, m_file_handle, FILEOFFSET_CONTINUE, payload, payload_len);
	}
}

void SMB_Handler::onClose( bool haveFin )
{
	if (m_file_handle)
		closeFile(m_result != TCPHANDLER_RESULT_DONE_OK);
}

void SMB_Handler::createSession()
{
	m_kernel->putIdentify(StreamIdentify::STR_IPV4_SRC, &m_ipAdrSource);
	m_kernel->putIdentify(StreamIdentify::STR_IPV4_DST, &m_ipAdrDestination);

	m_kernel->putIdentify(StreamIdentify::STR_PORT_SRC, &m_portSource);
	m_kernel->putIdentify(StreamIdentify::STR_PORT_DST, &m_portDestination);

	StreamIdentify::idtypeUInt16 protocolId = StreamProtocolInfo::APP_LAYER_PROT_SMB;
	m_kernel->putIdentify(StreamIdentify::STR_PROTOCOL_APPLICATION_LAYER, &protocolId);
	//получаем хэндл нового файла
	m_file_handle = cacheCreate(m_kernel, "");
}

void SMB_Handler::closeFile( bool isBad )
{
	if (m_file_handle)
	{
		flushQueue(isBad);

		cacheClose(m_kernel, m_file_handle, isBad);
		m_file_handle = 0;
		sessionType = SESSION_TYPE::UNK;
	}
}