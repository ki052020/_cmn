#pragma once
#include <memory>
#include <string.h>
#include	<unistd.h>
#include <ifaddrs.h>


///////////////////////////////////////////////////////////////////////
// KIF_Info
class KIF_Info
{
public:
   KIF_Info(const char* if_name) : m_if_name{ if_name } {}
   KIF_Info(const char* if_name, const ifaddrs* const p1st_ifaddrs);
   virtual ~KIF_Info() noexcept {}

   void Set_NickName(const char* pname);
   void Set_MacAddr(uint64_t mac_addr);

   // 戻り値 -> 下位 64bit が、インターフェイス識別子として返される
   uint64_t Add_v6_addr_by_cstr(const char* ptr);
   uint64_t Add_v6_addr_by_bin2(const void* ptr);

   // -----------------------------------------
   uint64_t mac_addr() const { return m_mac_addr; }

   const std::string& Get_Name() const
      { return (m_nick_name.length() > 0) ? m_nick_name : m_if_name; }

   // -----------------------------------------
   // 戻り値には \0 が付加されている（１８文字のバッファが返される）
   // 戻り値のバッファは内部バッファ（delete してはならない）
   // mac_addr は、little endian。上位２byte は 0 となるはず（上位２byte は無視される）
   static const char* CStr_frm_mac_addr(uint64_t mac_addr);

   // 戻り値には \0 が付加されている（INET6_ADDRSTRLEN のバッファが返される）
   // 戻り値のバッファは内部バッファ（delete してはならない）
   // 変換に失敗したときは「例外が送出」される
   static const char* CStr_frm_v6_addr(const void* ptr);

   bool Contains_v6_addr(const uint64_t* p_ui64) const;

   void DBG_ShowSelf(FILE* fd = stdout) const;

   // -----------------------------------------
protected:
   const std::string m_if_name;
   std::string m_nick_name;

   uint64_t m_mac_addr = 0;
   std::string m_str_mac_addr;

   uint32_t m_bin_v4 = 0;
   std::string m_str_v4;

   // 検索が高速になるように uint64_t を用いている
   int m_pcs_v6_addr = 0;
   std::vector<uint64_t> m_vec_bin2_v6;
   std::vector<std::string> m_vec_str_v6;
};


///////////////////////////////////////////////////////////////////////
// KSocket
// 原則として、ソケットのクローズを確実にするために存在している
class KSocket : public KIF_Info
{
public:
   // protocol = ETH_P_ALL / ETH_P_IP / ETH_P_IPV6
   KSocket(const KIF_Info& if_info, int protocol, bool bPromisc);
   KSocket(KIF_Info&& if_info, int protocol, bool bPromisc);	
   virtual ~KSocket() noexcept;

   int fd() const { return m_fd; }
	int Read(void* pbuf, int bytes) const
		{ return (int)read(m_fd, pbuf, (size_t)bytes); }
	int Wrt(const void* const pbuf, const int bytes) const {
		const int bytes_wtn = (int)write(m_fd, pbuf, (size_t)bytes);
		if (bytes_wtn != bytes)
			{ THROW("bytes_wtn != bytes"); }
		return bytes_wtn;
	}
   
protected:
   int m_fd = -1;
	
	// ----------------------
	void Ctor_innrer(int protocol, bool bPromisc);
};

