#include "../smb_handler.h"
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
	#define snprintf _snprintf_s  //MSVC �� ������� �99 ���������� (�� 1900 ������)
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

// ������ ������ ��� ���� ���������� WRITE
void SMB_Handler::parseBufferWrite()
{
	int curShifft = 0;

	while (true)
	{
		if (!lenBuffWrite)
			break;

		// ��������� ��� ��� SMB (������������ ����� ��������� SMB 64 �����)
		if (bufferWRITE[curShifft + 4] == 0xFE && bufferWRITE[curShifft + 5] == 0x53 && bufferWRITE[curShifft + 6] == 0x4D && bufferWRITE[curShifft + 7] == 0x42)
		{
			// ����� SMB ���� 4 ����� (NetBIOS)
			uint32_t lenBytePacketSMB = 0;										// ����� ����� SMB ������ + 4
			memcpy(&lenBytePacketSMB, bufferWRITE + curShifft, sizeof(lenBytePacketSMB));
			lenBytePacketSMB = _htons32(lenBytePacketSMB);
			lenBytePacketSMB += 4;

			if (lenBytePacketSMB > lenBuffWrite)
			{
				// ������� ��� ���� ����� � ������ ������ ������ ��� ������������ ��� ��� SMB �����
				memcpy(bufferWRITE, bufferWRITE + curShifft, lenBuffWrite);		// �������������� ������ 
				break;
			}

			// ���������� ��� �������
			// ��� ���������� ������ WRITE ��� CLOSE
			if (bufferWRITE[curShifft + 16] == SMB_HEADER_TYPE_WRITE)			// ������������� ����� ��������� WRITE 49 ����
			{
				curShifft += 16;
				uint32_t lenData = 0;											// ����� ���� ������ (������ ������ ������ ������� ���� �������)
				currentOffsetLen = 0;											// �������� � ����� �� �������� ������ �� ������ 

				curShifft += 56;				memcpy(&lenData, bufferWRITE + curShifft, sizeof(lenData));
				curShifft += 4;					memcpy(&currentOffsetLen, bufferWRITE + curShifft, sizeof(currentOffsetLen));

				// + 8 ���� �������� + 16 ���� ������������� ����� + 4 ����� � ������ + 4 ����� ������ + 8 ���� ��
				curShifft += 40;												// ���������� �� �� ������ ������

				int fixOff = 116;												// ����� �� ������ ������ ���������� ���������� 117 ���� (4 + 64 + 49): 117 - 1 �� ������ � 0

				if ((lenBuffWrite - fixOff) >= lenData)							// ����� ����� ����� ������ � ������
				{
					memcpy(currentBuffer + lenCurrentBuff, bufferWRITE + curShifft, lenData);					// ����� ������ � ������ ��� ����������� ������ � ����
					lenCurrentBuff += lenData;
					flushBuffer();
				}
				else															// ���� ����� �� ����� �� ������� �� ����� � ���� ���� ������ ����������
				{
					// ������� ��� ���� ����� � ������ ������ ������ ��� ������������ ��� ��� SMB �����
					// � ������ ������ ���� �� �����
					memcpy(bufferWRITE, bufferWRITE + curShifft, lenBuffWrite);	// �������������� �����
					break;
				}
				curShifft -= fixOff;											// ������� ����� � ������ SMB ������ ��� ������������ ���������� ������ ������ �� ������
			}
			else if (bufferWRITE[curShifft + 16] == SMB_HEADER_TYPE_CLOSE)
			{
				uint32_t currenTreeId = 0;
				curShifft += 40;				memcpy(&currenTreeId, bufferWRITE + curShifft, sizeof(currenTreeId));
				if (currenTreeId == sessionTreeId)								// ������� �������������� ������
					closeFile(false);

				curShifft -= 40;
			}

			curShifft += lenBytePacketSMB;										// ���������� �� ����� SMB ������
			lenBuffWrite -= lenBytePacketSMB;
		}
		else {
			// ����������� ������ ��� ����� �� ������� ������ ����� � ������
			break;
		}
	}
}

// ������ ������ ��� ���� ���������� READ
void SMB_Handler::parseBufferRead() 
{
	int curShifft = 0;

	while (true)
	{
		if (!lenBuffRead)
			break;

		// ��������� ��� ��� SMB (������������ ����� ��������� SMB 64 �����)
		if (bufferREAD[curShifft+4] == 0xFE && bufferREAD[curShifft+5] == 0x53 && bufferREAD[curShifft+6] == 0x4D && bufferREAD[curShifft+7] == 0x42)
		{
			// ����� SMB ���� 4 ����� (NetBIOS)
			uint32_t lenBytePacketSMB = 0;															// ����� ����� SMB ������ + 4
			memcpy(&lenBytePacketSMB, bufferREAD + curShifft, sizeof(lenBytePacketSMB));
			lenBytePacketSMB = _htons32(lenBytePacketSMB);
			lenBytePacketSMB += 4;

			if (lenBytePacketSMB > lenBuffRead)
			{
				// ������� ��� ���� ����� � ������ ������ ������ ��� ������������ ��� ��� SMB �����
				memcpy(bufferREAD, bufferREAD + curShifft, lenBuffRead);							// �������������� ������ 
				break;
			}

			// ���������� ��� �������
			// ��� ���������� ������ READ ��� CLOSE
			if (bufferREAD[curShifft+16] == SMB_HEADER_TYPE_READ)									// ������������� ����� ��������� READ 17 ����
			{
				curShifft += 16;
				uint32_t lenData = 0;																// ����� ���� ������ (������ ������ ������ ������� ���� �������)
				uint32_t lenOffsetData = 0;															// �������� � ����� �� �������� ������ �� ������ 
				
				curShifft += 56;				memcpy(&lenData, bufferREAD + curShifft, sizeof(lenData));
				curShifft += 4;					memcpy(&lenOffsetData, bufferREAD + curShifft, sizeof(lenOffsetData));

				curShifft += 8;																		// ��������������� 4 ����� (������ 0) ���������� �� �� ������ ������
				int fixOff = 84;																	// ����� �� ������ ������ ���������� ���������� 85 ���� (4 + 64 + 17): 85 - 1 �� ������ � 0

				if ((lenBuffRead - fixOff) >= lenData)												// ����� ����� ����� ������ � ������
				{
					memcpy(currentBuffer + lenCurrentBuff, bufferREAD + curShifft, lenData);		// ����� ������ � ������ ��� ����������� ������ � ����
					lenCurrentBuff += lenData;
					flushBuffer();
				}
				else																				// ���� ����� �� ����� �� ������� �� ����� � ���� ���� ������ ����������
				{
					// ������� ��� ���� ����� � ������ ������ ������ ��� ������������ ��� ��� SMB �����
					// � ������ ������ ���� �� �����
					memcpy(bufferREAD, bufferREAD + curShifft, lenBuffRead);						// �������������� �����
					break;
				}
				curShifft -= fixOff;																// ������� ����� � ������ SMB ������ ��� ������������ ���������� ������ ������ �� ������
			}
			else if (bufferREAD[curShifft + 16] == SMB_HEADER_TYPE_CLOSE)
			{
				uint32_t currenTreeId = 0;
				curShifft += 40;				memcpy(&currenTreeId, bufferREAD + curShifft, sizeof(currenTreeId));
				if(currenTreeId == sessionTreeId)													// ������� �������������� ������
					closeFile(false);

				curShifft -= 40;
			}

			curShifft += lenBytePacketSMB;															// ���������� �� ����� SMB ������
			lenBuffRead -= lenBytePacketSMB;
		}
		else {
			// ����������� ������ ��� ����� �� ������� ������ ����� � ������
			break;
		}
	}
}

// ���� SMB + ��������� ��� �������
SMB_Handler::COMMAND_TYPE SMB_Handler::parseSMBHeader(unsigned char* payload, int payload_len)
{
	if (payload_len < 17)
	{
		if (isOpenSession)
			return COMMAND_TYPE::DATA;

		return COMMAND_TYPE::UNK;
	}

	// ���� ������������� SMB
	if (payload[4] == 0xFE && payload[5] == 0x53 && payload[6] == 0x4D && payload[7] == 0x42)
	{
		if (payload[16] == SMB_HEADER_TYPE_WRITE && payload_len >= 117)									// ���������� ���������� ��� ��� �������� write (� read ����� ������ ���� WRITE = 84)
		{
			// ������� ������ ���������
			// ��� ������ ������ ������ ������� WRITE �������� ������ ������ �������� 2^17 - 131072
			// ����� ������������� �� ����� ��� ��� ������ ������ ������� �� �������� ����������
			// ����� ���������� ������ �������� ������� ��� �� ������� ������������ ������
			// ������ ����� � ������, ��������� ������� ����������

			if ((lenBuffWrite + payload_len) > MAX_LENGTH_BUFF_WRITE)
				parseBufferWrite();																		// ������ ������������ ������

			sessionTreeId = 0;																			// �������� ������������� ������ ������ ������
			memcpy(&sessionTreeId, payload + 40, sizeof(sessionTreeId));

			// ���������� ������ ������ �� ���������
			memcpy(bufferWRITE + lenBuffWrite, payload, payload_len);									// ����� ������ � ������ 
			lenBuffWrite += payload_len;
			
			return COMMAND_TYPE::WRITE;
		}
		else if (payload[16] == SMB_HEADER_TYPE_READ && (payload_len % 117))							// 117 - ����� ������������ ������ ���� READ ����� ������ ���������� �� ���������� WRITE
		{
			// ������� ������ ���������
			// ��� ������ ������ ������ ������� READ �������� ������ ������ �������� 2^17 - 131072
			// ����� ������������� �� ����� ��� ��� ������ ������ ������� �� �������� ����������
			// ����� ���������� ������ �������� ������� ��� �� ������� ������������ ������
			// ������ ����� � ������, ��������� ������� ����������

			if ((lenBuffRead + payload_len) > MAX_LENGTH_BUFF_READ)
				parseBufferRead();																		// ������ ������������ ������

			sessionTreeId = 0;																			// �������� ������������� ������ ������ ������
			memcpy(&sessionTreeId, payload + 40, sizeof(sessionTreeId));

			// ���������� ������ ������ �� ���������
			memcpy(bufferREAD + lenBuffRead, payload, payload_len);										// ����� ������ � ������ 
			lenBuffRead += payload_len;

			return COMMAND_TYPE::READ;
		}
		else if (payload[16] == SMB_HEADER_TYPE_CLOSE)													// ��� CLOSE - �������� �������� ����� (������� � ���������� ������� ��� ����������� �� ����� � �����)
		{
			uint32_t currenTreeId = 0;
			memcpy(&currenTreeId, payload + 40, sizeof(currenTreeId));

			if (isOpenSession && (currenTreeId == sessionTreeId))										// ������� �������������� ������
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
	if (!isOpenSession)	// ��������� ���� �� ������� ������ �� ������
	{
		switch (parseSMBHeader(d, payload_len))															// �������� ������
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
		switch (parseSMBHeader(d, payload_len))															// ��������� ����������� ������ ��� �������� ������
		{
		case COMMAND_TYPE::DATA: {

			switch (sessionType)
			{
			case SESSION_TYPE::READ: {
				if ((lenBuffRead + payload_len) > MAX_LENGTH_BUFF_READ)
					parseBufferRead();																	// ������ ������������ ������

				// ���������� ������ ������ �� ���������
				memcpy(bufferREAD + lenBuffRead, d, payload_len);										// ����� ������ � ������ 
				lenBuffRead += payload_len;
				break;
			}
			case SESSION_TYPE::WRITE: {

				if ((lenBuffWrite + payload_len) > MAX_LENGTH_BUFF_WRITE)
					parseBufferWrite();																	// ������ ������������ ������

				// ���������� ������ ������ �� ���������
				memcpy(bufferWRITE + lenBuffWrite, d, payload_len);										// ����� ������ � ������ 
				lenBuffWrite += payload_len;
				break;
			}
			default:
				break;
			}
			break;
		}
		case COMMAND_TYPE::CLOSE:
			// ������ ����� ������ ������ ������ ���� ������� ������ ��� �������� ������
			switch (sessionType)
			{
				case SESSION_TYPE::READ: {
					parseBufferRead();																	// ������ ������������ ������
					break;
				}
				case SESSION_TYPE::WRITE: {
					parseBufferWrite();																	// ������ ������������ ������
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

// ����� �������
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
		if (offsetLenData == currentOffsetLen)														// ��������� ���� � ����������� �������
		{
			writeSession(currentBuffer, lenCurrentBuff);
			offsetLenData += lenCurrentBuff;														// ������ �������� ������� ������� ���������
		}
		else {																						// ��������� ���� � ����������� �� ������� (������ ����� � ����)
			SMBSegment* newSegment = new SMBSegment(currentBuffer, lenCurrentBuff, currentOffsetLen);
			m_smbQueue.push(newSegment);
		}

		while (m_smbQueue.size())																	// ��������� ���� ������ � ����� ��� ������ � ����							
		{
			SMBSegment* it = m_smbQueue.top();

			if (offsetLenData == it->shifftPayload)
			{
				writeSession(it->data, it->lenPayload);
				offsetLenData += it->lenPayload;													// ������ �������� ������� ������� ���������

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

// ����� ����� ���������
void SMB_Handler::flushQueue(bool& state)
{
	// � ������ ���� � ����� �������� �������� �����, �� ���� ��������� ��������� ����� ����� �� �������� �������� ������
	while (m_smbQueue.size())
	{
		SMBSegment* it = m_smbQueue.top();

		if (offsetLenData == it->shifftPayload)
		{
			writeSession(it->data, it->lenPayload);
			offsetLenData += it->lenPayload;														// ������ �������� ������� ������� ���������

			m_smbQueue.pop();
			delete it;

			continue;
		}
		else																						// �������� ������ �� ����� ������
		{
			int allowZero = it->shifftPayload - offsetLenData;

			if ((allowZero  < 0) || (allowZero > SMB_MAX_SEGMENT_LENGTH))
			{
				state = true;																		// ���� ����� � INCOMPLETE
				m_smbQueue.pop();
				delete it;
				continue;
			}

			uint8_t padding[SMB_MAX_SEGMENT_LENGTH];
			memset(padding, 0x00, allowZero);
			writeSession(padding, allowZero);

			offsetLenData += allowZero;
			state = true;																			// ���� ����� � INCOMPLETE
		}
	}
}

// ����� ������� �����
void SMB_Handler::writeSession(unsigned char* payload, int payload_len)
{
	if (!m_file_handle)
		createSession();

	if (m_file_handle && payload_len)
	{		
		if (payload_len > MAX_SEGMENT_LENGTH)														// ����� ����� �� ��������
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
	//�������� ����� ������ �����
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