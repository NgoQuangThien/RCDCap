#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE CommonBufferTest
#include <boost/test/unit_test.hpp>
#include "rcdcap/source.hh"
#include "rcdcap/processor.hh"
#include "rcdcap/erspan-processor.hh"
#include "rcdcap/exception.hh"

#include <random>
#include <chrono>

const size_t PacketCount = 100000000;

class ERSPANSource : public RCDCap::DataSource
{
protected:
    size_t m_PacketsGenerated,
           m_PacketsDropped,
           m_TotalPackets;
public:
    explicit ERSPANSource(boost::asio::io_service& io_service,
        termination_handler hnd,
        size_t buffer_size,
        bool memory_locking,
        size_t burst_size,
        size_t timeout,
        size_t packet_count)
        : RCDCap::DataSource(io_service, hnd, buffer_size, memory_locking, burst_size, timeout)
        , m_TotalPackets(packet_count) {}

    virtual ~ERSPANSource() {}

    ERSPANSource(const ERSPANSource&) = delete;
    ERSPANSource& operator=(const ERSPANSource&) = delete;

    virtual void startAsync() {}
    virtual void start();
    virtual void stop() {}
    virtual void setFilterExpression(const std::string& expr) {}
    virtual std::string getName() const { return "ERSPANSource"; }
    virtual bool isFile() const { return false; }

    virtual int getLinkType() const { return DLT_EN10MB; }

    virtual int getSnapshot() const { return 1500; }

    virtual std::string getLinkTypeName() const { return "ERSPANSource"; }

    virtual size_t getPacketsCaptured() const { return m_PacketsGenerated; }
    virtual size_t getPacketsCapturedKernel() const { return m_PacketsGenerated; }
    virtual size_t getPacketsDroppedKernel() const { return 0; }
    virtual size_t getPacketsDroppedDriver() const { return 0; }
    virtual size_t getPacketsDroppedBuffer() const { return m_PacketsDropped; }

    size_t getBurstSize() const { return m_BurstSize; }
};

void ERSPANSource::start()
{
    char packet_assembly[9000 + sizeof(RCDCap::PacketInfo)];
    memset(packet_assembly, 0, sizeof(packet_assembly));

    std::random_device r;
    std::default_random_engine engine(r());
    std::uniform_int_distribution<int> distro(0, 1);
    std::uniform_int_distribution<int> caplen_distro(4, 9000);
    std::uniform_int_distribution<size_t> burst_size_distro(1, 100);

    size_t burst_size = burst_size_distro(engine);
    RCDCap::PacketInfo* first_packet = nullptr;
    for(size_t idx = 0, burst_idx = 0; idx < m_TotalPackets; idx++)
    {
        size_t offset = 0;
        //auto& mac_header = reinterpret_cast<RCDCap::MACHeader&>(packet_assembly[offset]);
        offset += sizeof(RCDCap::MACHeader);
        auto& ip_header = reinterpret_cast<RCDCap::IPv4Header&>(packet_assembly[offset]);
        ip_header.setIHL(sizeof(RCDCap::IPv4Header)/4);
        offset += ip_header.getIHL()*4;
        auto& gre_header = reinterpret_cast<RCDCap::GREHeader&>(packet_assembly[offset]);

        if(distro(engine))
        {
            gre_header.setCheksumPresent(true);
            offset += sizeof(RCDCap::GREChecksumField);
        }
        if(distro(engine))
        {
            gre_header.setSeqNumPresent(true);
            offset += sizeof(RCDCap::GRESeqNumField);
            // do something

            offset += sizeof(RCDCap::ERSPANHeader);
        }

        auto caplen = caplen_distro(engine);
        auto count = caplen + sizeof(RCDCap::PacketInfo);

        auto packet_info = m_Buffer.push(count);
        if(!packet_info)
        {
            if(burst_idx)
            {
                m_Sink->notify(first_packet, burst_idx);
                burst_idx = 0;
                burst_size = burst_size_distro(engine);
                first_packet = nullptr;
            }
            m_PacketsDropped++;
            continue;
        }

        auto _now = std::chrono::high_resolution_clock::now();
        typedef std::chrono::microseconds duration_t;
        typedef duration_t::rep rep_t;
        rep_t d = std::chrono::duration_cast<duration_t>(_now.time_since_epoch()).count();
        rep_t sec = d / 1000000;
        rep_t usec = d % 1000000;

        packet_info->init(getLinkType(), RCDCap::Time(sec, usec), caplen, 9000);

        if(!first_packet)
        {
            first_packet = packet_info;
        }

        auto packet = GetPacket(packet_info);
        memcpy(packet, packet_assembly, caplen);

        if(burst_idx + 1 == burst_size)
        {
            m_Sink->notify(first_packet, burst_size);
            burst_idx = 0;
            burst_size = burst_size_distro(engine);
            first_packet = nullptr;
        }
        else
            burst_idx++;
    }
}

BOOST_AUTO_TEST_CASE(CommonBufferTest)
{
    boost::asio::io_service io_service;

    auto src = boost::make_shared<ERSPANSource>(io_service,
        []() {},
        16384, false,
        0, 0, PacketCount);

    auto processor = boost::make_shared<RCDCap::ERSPANProcessor>(io_service, src->getBuffer(), true);
    src->attach(processor);

    auto sink = boost::make_shared<RCDCap::DiscardSink>(io_service, *src);
    processor->attach(sink);

    size_t worker_count = boost::thread::hardware_concurrency();
    std::unique_ptr<boost::thread[]> workers(new boost::thread[worker_count]);
    {
    boost::asio::io_service::work work(io_service);

    for (size_t i = 0u; i < worker_count - 1;
        ++i)
    {
        workers[i] = boost::thread(boost::bind(&boost::asio::io_service::run, &io_service));
        //auto hnd = workers[i].native_handle();
    }

    src->start();
    }
    for (size_t i = 0; i < worker_count; ++i)
        workers[i].join();    
}

