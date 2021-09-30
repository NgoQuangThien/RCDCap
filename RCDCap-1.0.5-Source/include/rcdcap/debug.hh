/*   RCDCap
 *   Copyright (C) 2020  Zdravko Velinov
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

#ifndef _RCDCAP_DEBUG_HH_
#define _RCDCAP_DEBUG_HH_

#include "exception.hh"

#include <chrono>

#define BOMB(detonation_time) { \
    static auto start = std::chrono::high_resolution_clock::now(); \
    if(std::chrono::high_resolution_clock::now() - start > std::chrono::seconds(detonation_time)) \
        THROW_EXCEPTION("BOOM!"); \
    }

#endif // _RCDCAP_DEBUG_HH_