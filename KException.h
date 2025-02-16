#pragma once

#include <string>
#include <vector>

#define WHT_B( str ) "\x1b[1m" str "\x1b[0m"
#define WHT_BU( str ) "\x1b[1;4m" str "\x1b[0m"
#define GRN_B( str ) "\x1b[1;32m" str "\x1b[0m"
#define YLW_B( str ) "\x1b[1;33m" str "\x1b[0m"
#define MGT_B( str ) "\x1b[1;35m" str "\x1b[0m"
#define CYN_B( str ) "\x1b[1;36m" str "\x1b[0m"

// --------------------------------------------------------------------
class KException
{
	enum { EN_max_pcs_bts = 8 };

public:
	KException(const char* pmsg, int start_idx_of_bt = 1);
//	KException(std::string msg) : KException(msg.c_str()) {}
	KException(const std::string& msg) : KException(msg.c_str(), 2) {}

	void Wrt_to(FILE *fd) const;
	void DBG_Show() const { this->Wrt_to(stdout); };

private:
	std::string m_msg;

	// backtrace 情報
	int m_pcs_bts;
	std::vector<std::string> m_bts;
};

// --------------------------------------------------------------------
#define THROW( msg ) throw KException{ msg }

