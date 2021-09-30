/*   RCDCap
 *   Copyright (C) 2013  Zdravko Velinov
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

#ifndef _QUIET_NEIGHBORHOOD_HH_
#define _QUIET_NEIGHBORHOOD_HH_

#include "rcdcap/types.hh"
#include "quiet-neighborhood-config.hh"

#include <cstring>
#include <string>

/*! \brief Specifies the available modes of execution of Quiet Neighborhood.
 * 
 *  The plug-in might be executed in two possible phases. The first one is
 *  the learning phase. It is used for capturing information about the monitored
 *  network automatically. That's particularly useful for huge networks that
 *  would be hard to describe. It automatically acquires information about the
 *  different VLANs and subnets and pushes them in a common network cache. The
 *  actual data is extracted by monitoring the ARP, DHCP, NDP and DHCPv6 traffic.
 *  After finishing the learning phase, the software switches to the active monitoring
 *  phase. It reports all inconsistencies and also acquires the data about the network.
 *  In this manner, it is possible to merge every new record automatically after
 *  manual inspection by the network administrator.
 */
enum class MonitorState
{
    LEARNING_PHASE,   //!< Considers all information as legitimate and writes it to its main table.
    MONITORING_PHASE, //!< Considers everything that was not already specified as service as harmful and writes it to its table of suspicious hosts.
};

//! Enlists some options that are described just as a single flag.
enum OptionFlags
{
    IGNORE_CACHE         = 1 << 0, //!< Ignore any previous cache and start directly into fresh learning phase.
    FORCE_LEARNING_PHASE = 1 << 1, //!< Start learning phase even if there is some cache already built.
    MERGE_VIOLATING      = 1 << 2  /*!< \brief Merge the cache of suspicious host to the cache of the legitimate hosts.
                                    *
                                    *   This option might be harmful if not used properly. You should always examine all
                                    *   errors and reports generated by the application before using this option.
                                    */
};

//! Enlists all available file formats for storing the network cache.
enum class CacheFormat
{
    JSON, //!< JavaScript Object Notation -- a simple format for describing basic objects, such as arrays and structures. That's the default file format.
    XML,  //!< Extensible Markup Language -- powerful markup language on itself. Useful for parsing the data by external application.
    INFO  //!< Boost Property Tree Information format -- simplistic file format for configuration options.
};

using RCDCap::uint32;

//! Convenience structure for passing options between the elements of the pipeline.
struct QuietNeighborhoodOptions
{
    uint32      hostPoolSize;          //!< Specifies the size of each host table.
    uint32      VLANPoolSize;          //!< Specifies the size of the VLAN table.
    uint32      subnetPoolSize;        //!< Specifies the size of each subnet table.
    size_t      DHCPServerPort;        //!< The port which is being monitored for DHCP requests.
    size_t      DHCPClientPort;        //!< The port which is being monitored for DHCP replies.
    size_t      DHCPv6ServerPort;      //!< The port which is being monitored for DHCPv6 requests.
    size_t      DHCPv6ClientPort;      //!< The port which is being monitored for DHCPv6 replies.
    size_t      learningPhase;         //!< How long the learning phase lasts.
    size_t      IPv4MinMask;           //!< The minimum IPv4 subnet mask. Used for speeding up the subnet aggregation process.
    size_t      IPv4MaxMask;           //!< The maximum IPv4 subnet mask. Used for placing an upper bound on subnet size.
    size_t      IPv6MinMask;           //!< The minimum IPv6 subnet mask. Used for speeding up the subnet aggregation process.
    size_t      IPv6MaxMask;           //!< The maximum IPv6 subnet mask. Used for placing an upper bound on subnet size.
    std::string networkCache;          //!< The path to the file which contains all legitimate network cache entries.
    std::string networkViolationCache; //!< The path to the file which contains all entries about suspicious hosts and subnets.
    CacheFormat networkCacheFormat;    //!< The format of the network cache file.
    size_t      flags;                 //!< Contains options passed as flags.
};

#ifdef DISABLE_QUIET_NEIGHBORHOOD_LOGGING
/*! \brief The main logging function.
 *  
 *  It is provided as a macro function, so that it is easier to replace it with some other mechanism.
 * 
 *  \param type     the type of the message that is being logged.
 *  \param format   format string which follows the general principles for using functions, such as
 *                  printf.
 */
#   define LOG_MESSAGE(type, format, ...)
#else
#   define LOG_MESSAGE(type, format, ...) syslog(log, format, ##__VA_ARGS__)
#endif

#endif // _QUIET_NEIGHBORHOOD_HH_