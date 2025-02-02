#include	<unistd.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include <net/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include <sys/ioctl.h>

#include "KException.h"
#include "KSocket.h"

///////////////////////////////////////////////////////////////////////
// KIF_Info
void KIF_Info::Set_NickName(const char* pname)
{
	if (m_nick_name.length() > 0)
		{ THROW("m_nick_name.length() > 0"); }

	m_nick_name = pname;
}

// --------------------------------------------------------------------
void KIF_Info::Set_MacAddr(const uint64_t mac_addr)
{
	if ((mac_addr & 0xffff'0000'0000'0000u) != 0)
		{ THROW("(mac_addr & 0xffff'ffff'fffff) != 0"); }

	if (m_mac_addr != 0)
		{ THROW("m_mac_addr != 0"); }

	m_mac_addr = mac_addr;
	m_str_mac_addr = KIF_Info::CStr_frm_mac_addr(mac_addr);
}

// --------------------------------------------------------------------
// KIF_Info::Add_v6_addr_by_cstr
uint64_t KIF_Info::Add_v6_addr_by_cstr(const char* ptr)
{
	uint8_t dst[20];  // 本当は [16] で良いはず
	if (inet_pton(AF_INET6, ptr, dst) <= 0)
		{ THROW("inet_pton(AF_INET6, ptr, dst) <= 0"); }

	m_pcs_v6_addr++;
	m_vec_bin2_v6.push_back(*(uint64_t*)dst);
	m_vec_bin2_v6.push_back(*(uint64_t*)(dst + 8));
	m_vec_str_v6.push_back(ptr);

	return *(uint64_t*)(dst + 8);
}

// --------------------------------------------------------------------
// uint64_t KIF_Info::Add_v6_addr_by_bin2
uint64_t KIF_Info::Add_v6_addr_by_bin2(const void* ptr)
{
	const char* pstr_v6 = KIF_Info::CStr_frm_v6_addr(ptr);

	m_pcs_v6_addr++;
	m_vec_bin2_v6.push_back(*(uint64_t*)ptr);
	m_vec_bin2_v6.push_back(*(uint64_t*)((uint8_t*)ptr + 8));
	m_vec_str_v6.push_back(pstr_v6);

	return *(uint64_t*)((uint8_t*)ptr + 8);
}

// --------------------------------------------------------------------
// KIF_Info::Contains_v6_addr
bool KIF_Info::Contains_v6_addr(const uint64_t* const p_ui64) const
{
	if (m_pcs_v6_addr == 0) { return false; }

	const uint64_t* pary = m_vec_bin2_v6.data();
	for (int i = m_pcs_v6_addr; i > 0; --i, pary += 2)
	{
		if (p_ui64[0] == pary[0] && p_ui64[1] == pary[1]) { return true; }
	}
	return false;
}

// ---------------------------------------------------------------
// KIF_Info::CStr_frm_mac_addr
static char s_mac_addr_cstr[20];  // 本当は [18] で良い
const char* KIF_Info::CStr_frm_mac_addr(const uint64_t mac_addr)
{
	char* pdst = s_mac_addr_cstr;
	uint64_t mac = mac_addr;
	for (int i = 6;; )
	{
		snprintf(pdst, 3, "%02x", (uint8_t)(mac & 0xff));
		if (--i == 0) { break; }

		mac >>= 8;
		*(pdst + 2) = ':';
		pdst += 3;
	}
	
	s_mac_addr_cstr[17] = 0; // 念のため
	return s_mac_addr_cstr;
}

// ---------------------------------------------------------------
// KIF_Info::CStr_frm_v6_addr
static char s_v6_addr_cstr[INET6_ADDRSTRLEN + 1];  // +1 は念のため
const char* KIF_Info::CStr_frm_v6_addr(const void* const ptr)
{
	if (inet_ntop(AF_INET6, ptr, s_v6_addr_cstr, INET6_ADDRSTRLEN + 1) == NULL)
		{ THROW("inet_ntop() == NULL"); }
	return s_v6_addr_cstr;
}

// --------------------------------------------------------------------
void KIF_Info::DBG_ShowSelf(FILE* fd) const
{
	fprintf(fd, "--- if name -> %s\n", m_if_name.c_str());
	if (m_nick_name.length() == 0)
		{ fprintf(fd, "   nick name -> -\n"); }
	else
		{ fprintf(fd, "   nick name -> %s\n", m_nick_name.c_str()); }

	fprintf(fd, "   mac addr -> %s\n", m_str_mac_addr.c_str());

	// v4 addr の表示
	if (m_bin_v4 == 0)
		{ fprintf(fd, "   v4 addr -> -\n"); }
	else
		{ fprintf(fd, "   v4 addr -> %s\n", m_str_v4.c_str()); }

	// v6 addr の表示
	if (m_pcs_v6_addr == 0)
		{ fprintf(fd, "   v6 addr -> -\n\n"); }
	else
	{
		fprintf(fd, "   v6 addr\n");
		for (std::string str_v6 : m_vec_str_v6)
		{
			fprintf(fd, "      %s\n", str_v6.c_str());
		}
		fprintf(fd, "\n");
	}
}


///////////////////////////////////////////////////////////////////////
// KSocket
KSocket::KSocket(
		const char* const if_name, const ifaddrs* const p1st_ifaddrs,
		const int protocol, const bool bPromisc)
	: KIF_Info{ if_name }
{
	if (protocol != ETH_P_ALL && protocol != ETH_P_IP && protocol != ETH_P_IPV6)
		{ THROW("unknown -> protocol"); }

   // ------------------------------------------------
	// p1st_ifaddrs を利用して ipv4, ipv6 アドレスを取得
	{
		std::vector<in6_addr> vec_addr_v6;
		std::vector<std::string> vec_str_v6;

		// INET_ADDRSTRLEN = 16, INET6_ADDRSTRLEN = 46
		char str_addr[INET6_ADDRSTRLEN + 1];
		for (const ifaddrs* ifa = p1st_ifaddrs; ifa != NULL; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr == NULL)
			{
				// ifa が point to point などの if で、アドレスを持たない場合の処理
				continue;
			}
			if (m_if_name.compare(ifa->ifa_name) != 0) { continue; }

			const sa_family_t family = ifa->ifa_addr->sa_family;
			if (family == AF_PACKET) { continue; }
			
			if (family == AF_INET)
			{
				if (m_bin_v4 != 0)
					{ THROW("m_bin_v4 != 0"); }

				const sockaddr_in* psockaddr_v4 = (const sockaddr_in*)ifa->ifa_addr;
				m_bin_v4 = psockaddr_v4->sin_addr.s_addr;

				if (inet_ntop(AF_INET, &psockaddr_v4->sin_addr, str_addr, INET6_ADDRSTRLEN + 1) == NULL)
					{ THROW("inet_ntop() == NULL"); }
				m_str_v4 = str_addr;
				continue;
			}
			else if (family == AF_INET6)
			{
				const sockaddr_in6* psockaddr_v6 = (const sockaddr_in6*)ifa->ifa_addr ;
				vec_addr_v6.push_back(psockaddr_v6->sin6_addr);

				if (inet_ntop(AF_INET6, &psockaddr_v6->sin6_addr, str_addr, INET6_ADDRSTRLEN + 1) == NULL)
					{ THROW("inet_ntop() == NULL"); }
				vec_str_v6.push_back(str_addr);
				continue;
			}

			THROW("detect -> family != AF_INET / AF_INET6");
		}

		// ----------------------------
		m_pcs_v6_addr += vec_addr_v6.size();
		if (m_pcs_v6_addr > 0)
		{
			m_vec_bin2_v6.reserve(m_pcs_v6_addr * 2 + 4);  // ローカルアドレス等の追加を想定して +4
			m_vec_str_v6.reserve(m_pcs_v6_addr + 2);

			for (const in6_addr& addr_v6 : vec_addr_v6)
			{
				const uint64_t* psrc = (const uint64_t*)&addr_v6;
				m_vec_bin2_v6.push_back(*psrc);
				m_vec_bin2_v6.push_back(*(psrc + 1));
			}

			for (const std::string& str_v6 : vec_str_v6)
			{
				m_vec_str_v6.push_back(str_v6);
			}
		}
	}

   // ------------------------------------------------
	// m_fd の取得
	// PF_PACKET, SOCK_RAW : L2 から生パケットを受け取る
	m_fd = socket(PF_PACKET, SOCK_RAW, htons(protocol));
   if (m_fd < 0)
      { THROW("socket() < 0"); }

	// ------------------------------------------------
	// インターフェイス index を取得する
	const u_int if_idx = if_nametoindex(if_name);
	if (if_idx == 0)
	{
      close(m_fd);
      m_fd = -1;  // 念のため
      THROW("if_nametoindex() == 0 / confirm device-name");
	}

	// ------------------------------------------------
	// bind（bind しない場合、全インタフェースからの受信となる）
	{
		sockaddr_ll sa = {};  // リンクレベルヘッダ情報
		sa.sll_family = PF_PACKET;
		sa.sll_protocol = htons(protocol);		
		sa.sll_ifindex = if_idx;
		if (bind(m_fd, (sockaddr*)&sa, sizeof(sa)) < 0)
		{
			close(m_fd);
			m_fd = -1;  // 念のため
			THROW("bind() < 0");
		}
	}

	// ---------------------------------------
	if (bPromisc)
	{
		packet_mreq mr = {};
		mr.mr_ifindex = if_idx;
		mr.mr_type = PACKET_MR_PROMISC;

		if((setsockopt(m_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr))) < 0)
		{
			close(m_fd);
			m_fd = -1;  // 念のため
			THROW("setsockopt() < 0");
		}
	}

	// ---------------------------------------
	// m_mac_addr の取得
	{
		ifreq ifr = {};
		strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
		if (ioctl(m_fd, SIOCGIFHWADDR, &ifr) < 0)
		{
			close(m_fd);
			m_fd = -1;  // 念のため
			THROW("ioctl() < 0");
		}
		m_mac_addr = (*(uint64_t*)ifr.ifr_hwaddr.sa_data) & 0xffff'ffff'ffff;
		m_str_mac_addr = KIF_Info::CStr_frm_mac_addr(m_mac_addr);
	}
}

// --------------------------------------------------------------------
KSocket::~KSocket()
{
   if (m_fd >= 0) { close(m_fd); }
}

