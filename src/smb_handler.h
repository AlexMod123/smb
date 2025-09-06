#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H

#include <QDebug>

#include <queue>

#include <QRegularExpression>

#include "tcp/tcphandler.h"

#define SMB_HEADER_TYPE_REQUSET			0x00	// Client to Server
#define SMB_HEADER_TYPE_RESPONSE		0x01	// Server to Client

#define SMB_HEADER_TYPE_CLOSE			0x06
#define SMB_HEADER_TYPE_READ			0x08
#define SMB_HEADER_TYPE_WRITE			0x09

#define SMB_MAX_SEGMENT_LENGTH			65536
#define MAX_SEGMENT_LENGTH				65535		// uint16_t
#define MAX_LENGTH_BUFF_READ			131072
#define MAX_LENGTH_BUFF_WRITE			131072

class IKernel;

struct SMBSegment
{
public:
	SMBSegment(unsigned char* d, const uint32_t& l, const uint32_t& shifft)
	{
		this->lenPayload = l;
		this->shifftPayload = shifft;

		if (l <= SMB_MAX_SEGMENT_LENGTH)
		{
			this->lenPayload = l;
			memcpy(data, d, l);
		}
		else
			this->lenPayload = 0;
	}

	uint32_t lenPayload;
	uint32_t shifftPayload;
	uint8_t data[SMB_MAX_SEGMENT_LENGTH]{};
};

class LessThanByLen
{
public:
	bool operator()(const SMBSegment* lhs, const SMBSegment* rhs) const
	{
		return lhs->shifftPayload > rhs->shifftPayload;
	}
	bool operator()(const SMBSegment& lhs, const SMBSegment& rhs) const
	{
		return lhs.shifftPayload < rhs.shifftPayload;
	}
	bool operator()(const SMBSegment* lhs, const SMBSegment& rhs) const
	{
		return lhs->shifftPayload < rhs.shifftPayload;
	}
	bool operator()(std::shared_ptr<SMBSegment> lhs, std::shared_ptr<SMBSegment> rhs) const
	{
		return lhs->shifftPayload < rhs->shifftPayload;
	}
};

class SMB_Handler final : TCPHandler
{
public:
	SMB_Handler(IKernel* kernel, uint32_t ip_src, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst);
	~SMB_Handler() override;

	int onRequestStream(unsigned char* payload, int payload_len, bool inc, bool push) override;
	int onReplyStream(unsigned char* payload, int payload_len, bool inc, bool push) override;

	void onClose(bool haveFin) override;
	void createSession() override;

	void closeFile(bool isOk);

private:
	enum class COMMAND_TYPE { READ, WRITE, CLOSE, DATA, UNK };

	enum class SESSION_TYPE { READ, WRITE, UNK };

	SESSION_TYPE sessionType{SESSION_TYPE::UNK};

	unsigned char currentBuffer[SMB_MAX_SEGMENT_LENGTH]{};
	int lenCurrentBuff{0};

	unsigned char bufferREAD[MAX_LENGTH_BUFF_READ]{};
	int lenBuffRead{0};

	unsigned char bufferWRITE[MAX_LENGTH_BUFF_WRITE]{};
	int lenBuffWrite{0};
	uint64_t currentOffsetLen{0};
	uint64_t offsetLenData{0};
	uint32_t sessionTreeId{0};
	bool m_req_inc, m_rep_inc;

	int m_file_handle;
	bool isOpenSession{false};

	uint32_t ip_src, ip_dst;

	std::priority_queue<std::shared_ptr<SMBSegment>, std::deque<std::shared_ptr<SMBSegment>>, LessThanByLen> m_smbQueue;

	int procSMB(unsigned char* payload, int payload_len);
	COMMAND_TYPE parseSMBHeader(unsigned char* payload, int payload_len);
	void writeSession(unsigned char* payload, int payload_len);

	void flushBuffer();
	void flushQueue(bool& state);

	void parseBufferRead();
	void parseBufferWrite();
};


#endif // HTTP_HANDLER_H
