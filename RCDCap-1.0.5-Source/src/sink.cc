/*   RCDCap
 *   Copyright (C) 2012  Zdravko Velinov
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "rcdcap/sink.hh"
#include "rcdcap/exception.hh"
#include "rcdcap/packet-headers.hh"

#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <time.h>

#include <boost/scope_exit.hpp>

#ifndef _WIN32
#   include <net/if.h>
#   include <linux/if_tun.h>
#   include <sys/types.h>
#   include <sys/stat.h>
#   include <fcntl.h>
#   include <sys/syscall.h>
#   include <sys/socket.h>
#   include <netpacket/packet.h>
#endif

namespace RCDCap
{
using std::placeholders::_1;
using std::placeholders::_2;

DataSink::DataSink(boost::asio::io_service& io_service, DataSource& src)
    :   m_DataSource(src),
        m_Processed(0),
        m_IOService(io_service)
{
}

size_t DataSink::getProcessed() const
{
    return m_Processed;
}

ConsoleSink::ConsoleSink(boost::asio::io_service& io_service, DataSource& src)
    :   TextSink(io_service, src)
{
}

ConsoleSink::~ConsoleSink()
{
}

void ConsoleSink::notify(PacketInfo* packet_info, size_t packets)
{
    this->writeInfo(std::cout, packet_info, packets);
}

TextSink::TextSink(boost::asio::io_service& io_service, DataSource& src)
    :   DataSink(io_service, src)
{
}

void TextSink::writeInfo(std::ostream& os, PacketInfo* packet_info, size_t packets)
{
    auto& buffer = m_DataSource.getBuffer();    
    auto status = buffer.acquireSequence(packet_info, &packets);
    if(!status)
        return;
    
    m_IOService.post(std::bind(&TextSink::writeInfoImpl, this, std::ref(os), packet_info, packets));
}

void TextSink::writeInfoImpl(std::ostream& os, PacketInfo* packet_info, size_t packets)
{
    size_t chunk_size = 0;
    auto& buffer = m_DataSource.getBuffer();
    for(; packets--; packet_info = buffer.next(packet_info))
    {
        ++m_Processed;
        struct tm* time_info;
        auto& pcap_packet_header = packet_info->getPCAPHeader(); 
        auto timestamp = pcap_packet_header.getTimestamp();
        time_t sec = static_cast<time_t>(timestamp.getSeconds());
        time_info = localtime(&sec);
        os  << std::dec
            << std::setfill('0')
            << std::setw(2) << time_info->tm_hour << ":"
            << std::setw(2) << time_info->tm_min << ":"
            << std::setw(2) << time_info->tm_sec << "."
            << std::setw(6) << timestamp.getMicroseconds() << " ";
        switch(packet_info->getLinkType())
        {
        case DLT_EN10MB:
        {
            auto&   eth_packet = reinterpret_cast<const MACHeader&>(*GetPacket(packet_info));
            mac_t   src_mac = eth_packet.getSMacAddress(),
                    dst_mac = eth_packet.getDMacAddress();
            os << src_mac << " -> " << dst_mac;
        }   break;
    //  case DLT_IEEE802_11:
    //      break;
        }
        os << std::endl;
        chunk_size += packet_info->getAllocatedSize();
    }

    buffer.popSequence(chunk_size);
    packets = 0;
    auto* next_packet_info = buffer.acquireSequence(&packets);
    if(!next_packet_info)
        return;
    
    m_IOService.post(std::bind(&TextSink::writeInfoImpl, this, std::ref(os), next_packet_info, packets));
}

TextFileSink::TextFileSink(boost::asio::io_service& io_service, DataSource& src, const std::string& filename)
    :   TextSink(io_service, src),
        m_File(filename.c_str(), std::ios::out)
{
}

TextFileSink::~TextFileSink()
{
}

void TextFileSink::notify(PacketInfo* packet_info, size_t packets)
{
    this->writeInfo(m_File, packet_info, packets);
}

BinarySink::BinarySink(boost::asio::io_service& io_service, DataSource& src)
    :   DataSink(io_service, src)
{
}

BinarySink::~BinarySink()
{
}

void BinarySink::writeHeader(std::ostream& fs)
{
    auto linktype = m_DataSource.getLinkType();
    PCAPFileHeader pcap_header(m_DataSource.getSnapshot(), linktype == DLT_RAW ? DLT_EN10MB : linktype);
    fs.write(reinterpret_cast<char*>(&pcap_header), sizeof(pcap_header));
}

void BinarySink::writePacket(std::ostream& os, PacketInfo* packet_info, size_t packets)
{
    auto& buffer = m_DataSource.getBuffer(); 
    auto status = buffer.acquireSequence(packet_info, &packets);
    if(!status)
        return;

    m_IOService.post(std::bind(&BinarySink::writePacketImpl, this, std::ref(os), packet_info, packets));
}

void BinarySink::writePacketImpl(std::ostream& os, PacketInfo* packet_info, size_t packets)
{
    auto& buffer = m_DataSource.getBuffer();
    size_t chunk_len = 0;
    while(packets--)
    {
        ++m_Processed;
        auto& pcap_header = packet_info->getPCAPHeader();
        os.write(reinterpret_cast<char*>(&pcap_header), sizeof(PCAPPacketHeader) + pcap_header.getCapturedLength());
        chunk_len += packet_info->getAllocatedSize();
        packet_info = buffer.next(packet_info);
    }
    buffer.popSequence(chunk_len);

    auto* next_packet_info = buffer.acquireSequence(&packets);
    if(!next_packet_info)
        return;
    m_IOService.post(std::bind(&BinarySink::writePacketImpl, this, std::ref(os), next_packet_info, packets));
}

BinaryConsoleSink::BinaryConsoleSink(boost::asio::io_service& io_service, DataSource& src)
    :   BinarySink(io_service, src)
{
    this->writeHeader(std::cout);
}

BinaryConsoleSink::~BinaryConsoleSink()
{
}

void BinaryConsoleSink::notify(PacketInfo* packet_info, size_t packets)
{
    this->writePacket(std::cout, packet_info, packets);
}

BinaryFileSink::BinaryFileSink(boost::asio::io_service& io_service, DataSource& src, const std::string& filename)
    :   BinarySink(io_service, src),
        m_File(filename.c_str(), std::ios::out | std::ios::binary)
{
    this->writeHeader(m_File);
}

BinaryFileSink::~BinaryFileSink()
{
}

void BinaryFileSink::notify(PacketInfo* packet_info, size_t packets)
{
    this->writePacket(m_File, packet_info, packets);
}

TAPDeviceSink::TAPDeviceSink(boost::asio::io_service& io_service, DataSource& src, uint32 ip, const std::string& devname, uint32 flags)
    :   DataSink(io_service, src),
        m_SD(io_service),
        m_Flags(flags)
{
    int             sock = -1;
    BOOST_SCOPE_EXIT( (sock) )
    {
        if(sock != -1)
            close(sock);
    } BOOST_SCOPE_EXIT_END
    TAPDevice       ifr;
    this->createTapDevice(ifr, devname, flags & RCDCAP_SINK_OPTION_PERSIST);
    this->setIP(ifr, sock, ip);
    this->start(ifr, sock);
}

TAPDeviceSink::~TAPDeviceSink()
{
}

void TAPDeviceSink::notify(PacketInfo* packet_info, size_t packets)
{
    auto& buffer = m_DataSource.getBuffer();
    auto status = buffer.acquireSequence(packet_info, &packets);
    if(!status)
        return;
    
    writeSequence(packet_info, packets);
}

// TODO: Is that the most efficient way?
void TAPDeviceSink::writeCompleted(PacketInfo* packet_info, size_t packets, size_t transferred_chunk, const boost::system::error_code& ec, std::size_t bytes_transferred)
{
    ++m_Processed;
    boost::asio::detail::throw_error(ec);
    assert(bytes_transferred == packet_info->getPCAPHeader().getCapturedLength());
    auto& buffer = m_DataSource.getBuffer();
    
    if(packets)
    {
        assert(buffer.size());
        packet_info = buffer.next(packet_info);
        auto&   pcap_header = packet_info->getPCAPHeader();
        auto*   packet = GetPacket(packet_info);
        auto    origlen = pcap_header.getOriginalLength(),
                caplen = pcap_header.getCapturedLength();
        if(origlen != caplen && !(m_Flags & RCDCAP_SINK_OPTION_FORCE))
        {
            if(m_Flags & RCDCAP_SINK_OPTION_IGNORE)
            {
                auto& buffer = m_DataSource.getBuffer();
                transferred_chunk += packet_info->getAllocatedSize();
                for(;;)
                {
                    packet_info = buffer.next(packet_info);
                    ++m_Processed;
                    --packets;
                    if(packets == 0)
                    {
                        break;
                    }
                    
                    auto& next_header = packet_info->getPCAPHeader();
                    if(next_header.getOriginalLength() == next_header.getCapturedLength())
                    {
                        break;
                    }
                    
                    transferred_chunk += packet_info->getAllocatedSize();
                }
                if(packets)
                {
                    packet = GetPacket(packet_info);
                    auto& next_header = packet_info->getPCAPHeader();
                    boost::asio::async_write(m_SD, boost::asio::buffer(packet, next_header.getCapturedLength()),
                                             std::bind(&TAPDeviceSink::writeCompleted, this, packet_info, --packets,
                                                       transferred_chunk + packet_info->getAllocatedSize(), _1, _2));
                }
                else
                {
                    buffer.popSequence(transferred_chunk);
                    auto next_packet_info = buffer.acquireSequence(&packets);
                    if(!next_packet_info)
                        return;
                    writeSequence(next_packet_info, packets);
                }
                return;
            }
            std::stringstream ss;
            ss << "Invalid length; the complete packet must be captured in order to output it to a TAP device.\n"
                  "Original length: " << origlen << "; the length of the received packet: " << caplen << '.';
            THROW_EXCEPTION(ss.str());
        }
        boost::asio::async_write(m_SD, boost::asio::buffer(packet, pcap_header.getCapturedLength()),
                                 std::bind(&TAPDeviceSink::writeCompleted, this, packet_info, --packets, transferred_chunk + packet_info->getAllocatedSize(), _1, _2));
    }
    else
    {
        buffer.popSequence(transferred_chunk);
        auto next_packet_info = buffer.acquireSequence(&packets);
        if(!next_packet_info)
            return;
        writeSequence(next_packet_info, packets);
    }
}

void TAPDeviceSink::writeSequence(PacketInfo* packet_info, size_t packets)
{
    auto&   pcap_header = packet_info->getPCAPHeader();
    auto    origlen = pcap_header.getOriginalLength(),
            caplen = pcap_header.getCapturedLength();
    auto*   packet = GetPacket(packet_info);
    if(origlen != caplen && !(m_Flags & RCDCAP_SINK_OPTION_FORCE))
    {
        if(m_Flags & RCDCAP_SINK_OPTION_IGNORE)
        {
            auto& buffer = m_DataSource.getBuffer();
            size_t ignored_cargo = packet_info->getAllocatedSize();
            for(;;)
            {
                packet_info = buffer.next(packet_info);
                ++m_Processed;
                --packets;
                if(packets == 0)
                    break;
                
                auto& next_header = packet_info->getPCAPHeader();
                if(next_header.getOriginalLength() == next_header.getCapturedLength())
                {
                    break;
                }

                ignored_cargo += packet_info->getAllocatedSize();
            }
            if(packets)
            {
                packet = GetPacket(packet_info);
                auto& next_header = packet_info->getPCAPHeader();
                boost::asio::async_write(m_SD, boost::asio::buffer(packet, next_header.getCapturedLength()),
                                         std::bind(&TAPDeviceSink::writeCompleted, this, packet_info, --packets, ignored_cargo + packet_info->getAllocatedSize(), _1, _2));
            }
            else
            {
                buffer.popSequence(ignored_cargo);
                auto next_packet_info = buffer.acquireSequence(&packets);
                if(!next_packet_info)
                    return;
                writeSequence(next_packet_info, packets);
            }
            
            return;
        }
        std::stringstream ss;
        ss << "Invalid length; the complete packet must be captured in order to output it to a TAP device.\n"
            "Original length: " << origlen << "; the length of the received packet: " << caplen << '.';
        THROW_EXCEPTION(ss.str());
    }
    assert(pcap_header.getCapturedLength());
    boost::asio::async_write(m_SD, boost::asio::buffer(packet, pcap_header.getCapturedLength()),
                             std::bind(&TAPDeviceSink::writeCompleted, this, packet_info, --packets,  packet_info->getAllocatedSize(), _1, _2));
}

#define MAX_KEY_LENGTH 255
#define DEVICE_DIR "\\\\.\\Global\\"

#ifdef _WIN32
void ThrowWin32ErrorException(const char* err_str)
{
    LPVOID lpMsgBuf = nullptr;
    auto err = GetLastError();
    DWORD res = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
                              FORMAT_MESSAGE_ALLOCATE_BUFFER |
                              FORMAT_MESSAGE_IGNORE_INSERTS,
                              nullptr,
                              err,
                              MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                              (LPTSTR)&lpMsgBuf,
                              0,
                              nullptr);
    BOOST_SCOPE_EXIT((lpMsgBuf))
    {
        if (lpMsgBuf)
            LocalFree(lpMsgBuf);
    } BOOST_SCOPE_EXIT_END

    std::stringstream ss;
    ss << err_str;
    if (lpMsgBuf)
        ss << ": " << (char*)lpMsgBuf;
    else
        ss << ": 0x" << std::hex << GetLastError();

    THROW_EXCEPTION(ss.str());
}

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE (10, METHOD_BUFFERED)

typedef unsigned long IPADDR;
#endif

void TAPDeviceSink::createTapDevice(TAPDevice& ifr, const std::string& devname, bool persistent)
{
#ifdef _WIN32
    std::stringstream ss;
    ss << DEVICE_DIR;

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

    HKEY hAdapterKey = nullptr;
    BOOST_SCOPE_EXIT( (hAdapterKey) )
    {
        if(hAdapterKey)
            RegCloseKey(hAdapterKey);
    } BOOST_SCOPE_EXIT_END

    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    TEXT(ADAPTER_KEY),
                    0,
                    KEY_READ,
                    &hAdapterKey) != ERROR_SUCCESS)
    {
        THROW_EXCEPTION("Failed to get registry key: " ADAPTER_KEY);
    }

    TCHAR    achKey[MAX_KEY_LENGTH];
    DWORD    cbName;
    TCHAR    achClass[MAX_PATH] = TEXT("");
    DWORD    cchClassName = MAX_PATH;
    DWORD    cSubKeys = 0;
    DWORD    cbMaxSubKey;
    DWORD    cchMaxClass;
    DWORD    cValues;
    DWORD    cchMaxValue;
    DWORD    cbMaxValueData;
    DWORD    cbSecurityDescriptor;
    FILETIME ftLastWriteTime;

    DWORD retCode = RegQueryInfoKey(hAdapterKey,
                                    achClass,
                                    &cchClassName,
                                    NULL,
                                    &cSubKeys,
                                    &cbMaxSubKey,
                                    &cchMaxClass,
                                    &cValues,
                                    &cchMaxValue,
                                    &cbMaxValueData,
                                    &cbSecurityDescriptor,
                                    &ftLastWriteTime);

    if (!cSubKeys)
        THROW_EXCEPTION("Cannot find the tap device sub key");

    DWORD i;
    CHAR value[MAX_KEY_LENGTH];

    for (i = 0; i < cSubKeys; i++)
    {
        cbName = MAX_KEY_LENGTH;
        retCode = RegEnumKeyEx(hAdapterKey, i,
                                achKey,
                                &cbName,
                                NULL,
                                NULL,
                                NULL,
                                &ftLastWriteTime);
        if (retCode != ERROR_SUCCESS)
        {
            continue;
        }

        DWORD num = MAX_KEY_LENGTH;
        auto status = RegGetValue(hAdapterKey,
                                  achKey,
                                  TEXT("ComponentId"),
                                  RRF_RT_REG_SZ,
                                  0,
                                  value,
                                  &num);
        if(status != ERROR_SUCCESS)
            continue;

        if(strncmp(value, "tap0", 4))
            continue;

        num = MAX_KEY_LENGTH;
        status = RegGetValue(hAdapterKey,
                             achKey,
                             TEXT("NetCfgInstanceId"),
                             RRF_RT_REG_SZ,
                             0,
                             value,
                             &num);
        if(status == ERROR_SUCCESS)
            break;
    }

    if(i == cSubKeys)
        THROW_EXCEPTION("Failed to find tap device subkey value");

    ss << value << ".tap";
    auto tap_str = ss.str();

    HANDLE ptr = CreateFileA(tap_str.c_str(),
                             GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING,
                             FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    if(ptr == INVALID_HANDLE_VALUE)
    {
        ThrowWin32ErrorException("failed to open tap");
    }

    m_SD.assign(ptr);
#else
    int err;
    m_SD.assign(::open("/dev/net/tun", O_RDWR));
    if(!m_SD.is_open())
        THROW_EXCEPTION(std::string("could not open /dev/net/tun: ") + strerror(errno));
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if(!devname.empty())
        strncpy(ifr.ifr_name, devname.c_str(), IFNAMSIZ);
    err = ioctl(m_SD.native_handle(), TUNSETIFF, reinterpret_cast<void*>(&ifr));
    if(err < 0)
        THROW_EXCEPTION(std::string("could not create the TAP device: ") + strerror(errno));
    err = ioctl(m_SD.native_handle(), TUNSETPERSIST, static_cast<int>(persistent));
    if(err < 0)
        THROW_EXCEPTION(std::string("could not set in ") + 
                        (persistent ? "persistent" : "non-persistent") + " mode: " + strerror(errno));
#endif
}

void TAPDeviceSink::setIP(TAPDevice& ifr, int& sock, uint32 ip)
{
#if _WIN32
    IPADDR psock[4];
    psock[0] = ip;
    psock[1] = 0xFFFFFFU;
    psock[2] = psock[3] = 0;

    DWORD len;
    if(DeviceIoControl(m_SD.native_handle(), TAP_IOCTL_CONFIG_DHCP_MASQ,
                        &psock, sizeof(psock), &psock, sizeof(psock), &len, NULL) == 0)
    {
        ThrowWin32ErrorException("failed to set ip address");
    }
#else
    struct sockaddr_in addr;
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0)
        THROW_EXCEPTION(std::string("could not create a socket: ") + strerror(errno));
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = ip;
    addr.sin_family = AF_INET;
    memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
    if(ioctl(sock, SIOCSIFADDR, reinterpret_cast<void*>(&ifr)) < 0)
        THROW_EXCEPTION(std::string("could not set the specified ip address: ") + strerror(errno));
#endif
}

void TAPDeviceSink::start(TAPDevice& ifr, int sock)
{
#if _WIN32
    DWORD len;
    ULONG flag = 1;
    auto status = DeviceIoControl(m_SD.native_handle(),
                                  TAP_IOCTL_SET_MEDIA_STATUS,
                                  &flag, sizeof(flag),
                                  &flag, sizeof(flag), &len, NULL);
    if (!status)
    {
        ThrowWin32ErrorException("failed to to setup tap device");
    }
#else
    ifr.ifr_flags |= IFF_UP;
    ifr.ifr_flags |= IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, reinterpret_cast<void*>(&ifr)) < 0)
        THROW_EXCEPTION(std::string("could not start the specified device: ") + strerror(errno));
#endif
}

InjectionSink::InjectionSink(boost::asio::io_service& io_service, DataSource& src, const std::string& _interface)
    :   DataSink(io_service, src)
#ifndef _WIN32
    ,   m_SD(-1)
#endif
{
#ifdef _WIN32
    char errbuf[PCAP_ERRBUF_SIZE];
    m_Handle = pcap_open_live(_interface.c_str(), -1, 1, -1, errbuf);
    if (!m_Handle)
        THROW_EXCEPTION("could not open device " + _interface + ": " + errbuf +
                        "\nMake sure that you have enough permissions.");
#else
    m_SD = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if(m_SD < 0)
        THROW_EXCEPTION(std::string("could not initialize raw socket: ") + strerror(errno));
    
    
    struct ifreq ifce_info;
    memset(&ifce_info, 0, sizeof(struct ifreq));
    strncpy(ifce_info.ifr_name, _interface.c_str(), IFNAMSIZ-1);
    auto ret = ioctl(m_SD, SIOCGIFINDEX, &ifce_info);
    if(ret < 0)
        THROW_EXCEPTION(std::string("failed to associate socket with network interface: ") + strerror(errno));
    
    ret = ioctl(m_SD, SIOCGIFHWADDR, &ifce_info);
    if(ret < 0)
        THROW_EXCEPTION(std::string("failed to get hardware address of network interface: ") + _interface + strerror(errno));
    
    std::copy(ifce_info.ifr_hwaddr.sa_data, ifce_info.ifr_hwaddr.sa_data + 6, m_InterfaceMAC.begin());
    
    ret = ioctl(m_SD, SIOCGIFADDR, &ifce_info);
    if(ret < 0)
        THROW_EXCEPTION(std::string("failed to get IP address of network interface: ") + _interface + strerror(errno));
    
    std::copy(ifce_info.ifr_addr.sa_data, ifce_info.ifr_addr.sa_data + 4, m_InterfaceIP.begin());
#endif
}

InjectionSink::~InjectionSink()
{
#ifdef _WIN32
    pcap_close(m_Handle);
#else
    if(m_SD >= 0)
        close(m_SD);
#endif
}

void InjectionSink::writeSequence(PacketInfo* packet_info, size_t packets)
{
    size_t chunk_size = 0;
    auto& buffer = m_DataSource.getBuffer();
    for(; packets--; packet_info = buffer.next(packet_info))
    {
        auto&   pcap_header = packet_info->getPCAPHeader();
        auto    origlen = pcap_header.getOriginalLength(),
                caplen = pcap_header.getCapturedLength();
        auto*   packet = GetPacket(packet_info);
        if(origlen != caplen)
        {
            std::stringstream ss;
            ss << "Invalid length; the complete packet must be captured in order to output it to a Ethernet device.\n"
                "Original length: " << origlen << "; the length of the received packet: " << caplen << '.';
            THROW_EXCEPTION(ss.str());
        }
        
#ifdef _WIN32
        pcap_sendpacket(m_Handle, packet, caplen);
#else
        struct sockaddr_ll socket_address;
        socket_address.sll_halen = ETH_ALEN;
        std::copy(m_InterfaceMAC.begin(), m_InterfaceMAC.end(), socket_address.sll_addr);
        auto ret = ::sendto(m_SD, packet, caplen, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
        if(ret < 0)
            THROW_EXCEPTION(std::string("failed to send packet: ") + strerror(errno));
#endif
        chunk_size += packet_info->getAllocatedSize();
    }
    buffer.popSequence(chunk_size);
}

void InjectionSink::notify(PacketInfo* packet_info, size_t packets)
{
    auto& buffer = m_DataSource.getBuffer();
    auto status = buffer.acquireSequence(packet_info, &packets);
    if(!status)
        return;
    
    writeSequence(packet_info, packets);
    auto next_packet_info = buffer.acquireSequence(&packets);
    if(!next_packet_info)
        return;
    writeSequence(next_packet_info, packets);
}

DiscardSink::DiscardSink(boost::asio::io_service& io_service, DataSource& src)
    :   DataSink(io_service, src) {}

void DiscardSink::notify(PacketInfo* packet_info, size_t packets)
{
    auto& buffer = m_DataSource.getBuffer();
    auto status = buffer.acquireSequence(packet_info, &packets);
    if(!status)
        return;
    
    // Then we write a burst
    size_t chunk_size = 0;
    for(; packets; --packets, packet_info = buffer.next(packet_info))
    {
        ++m_Processed;
        chunk_size += packet_info->getAllocatedSize();
    }
    buffer.popSequence(chunk_size);
   
    while((packet_info = buffer.acquireSequence(&packets)))
    {
        ++m_Processed;
        size_t total_bytes = 0;
        for(size_t packet_idx = 0; packet_idx < packets; ++packet_idx,
                                                         packet_info = buffer.next(packet_info))
        {
            total_bytes += packet_info->getAllocatedSize();
        }
        buffer.popSequence(total_bytes);
    }
}
}
