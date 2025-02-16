#define BOOST_STACKTRACE_USE_BACKTRACE
#include <boost/stacktrace.hpp>

#include "KException.h"

// --------------------------------------------------------------------
KException::KException(const char* pmsg, const int start_idx_of_bt)
{
	m_msg = m_msg + "\n\x1b[1;35m!!! \x1b[0;35m" + pmsg + "\x1b[39m";

	// -----------------------------------------
	boost::stacktrace::basic_stacktrace bt = boost::stacktrace::stacktrace();
	m_pcs_bts = bt.size() - start_idx_of_bt;
	if (m_pcs_bts > EN_max_pcs_bts) { m_pcs_bts = EN_max_pcs_bts; }

	for (int i = start_idx_of_bt; i <= m_pcs_bts; ++i)
	{
		std::string str_bt;
		str_bt.reserve(150);  // 暫定的な処置
		str_bt = str_bt + bt[i].name()
				+ "\x1b[1;33m " + bt[i].source_file()
				+ "\x1b[1;32m L" + std::to_string(bt[i].source_line()) + "\x1b[0;39m\n";

		m_bts.push_back(str_bt);
	}
}

// --------------------------------------------------------------------
void KException::Wrt_to(FILE* fd) const
{
	fprintf(fd, m_msg.c_str());
	fprintf(fd, "\n\n\x1b[1m[stack trace]\x1b[0m\n");

	for (auto str : m_bts)
		{ fprintf(fd, str.c_str()); }

	fprintf(fd, "\n");
}
