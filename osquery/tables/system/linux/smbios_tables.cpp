/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iomanip>
#include <sstream>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <boost/noncopyable.hpp>
#include <thread>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tables/system/smbios_utils.h"
#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

#define kLinuxSMBIOSRawAddress_ 0xF0000
#define kLinuxSMBIOSRawLength_ 0x10000
#define WORD(x) (uint16_t)((x)[0]+((x)[1]<<8))

const std::string kLinuxEFISystabPath = "/sys/firmware/efi/systab";

class LinuxSMBIOSParser : public SMBIOSParser {
 public:
  /// Attempt to read the system table and SMBIOS from an address.
  void readFromAddress(size_t address, size_t length);

  /// Parse the SMBIOS address from an EFI systab file.
  void readFromSystab(const std::string& systab);

  /// Cross version/boot read initializer.
  bool discover();

  /// Check if the read was successful.
  bool valid() { return (data_ != nullptr && table_data_ != nullptr); }

 public:
  virtual ~LinuxSMBIOSParser() {
    if (data_ != nullptr) {
      free(data_);
    }
    if (table_data_ != nullptr) {
      free(table_data_);
    }
  }

 private:
  bool discoverTables(size_t address, size_t length);

  /// Hold the raw SMBIOS memory read.
  uint8_t* data_{nullptr};
};

void LinuxSMBIOSParser::readFromAddress(size_t address, size_t length) {
  auto status = osquery::readRawMem(address, length, (void**)&data_);
  if (!status.ok() || data_ == nullptr) {
    return;
  }

  // Search for the SMBIOS/DMI tables magic header string.
  size_t offset;
  for (offset = 0; offset <= 0xFFF0; offset += 16) {
    // Could look for "_SM_" for the SMBIOS header, but the DMI header exists
    // in both SMBIOS and the legacy DMI spec.
    if (memcmp(data_ + offset, "_DMI_", 5) == 0) {
      auto dmi_data = (DMIEntryPoint*)(data_ + offset);
      if (discoverTables(dmi_data->tableAddress, dmi_data->tableLength)) {
        break;
      }
    }
  }
}

void LinuxSMBIOSParser::readFromSystab(const std::string& systab) {
  std::string content;
  if (!readFile(kLinuxEFISystabPath, content).ok()) {
    return;
  }

  for (const auto& line : osquery::split(content, "\n")) {
    if (line.find("SMBIOS") == 0) {
      auto details = osquery::split(line, "=");
      if (details.size() == 2 && details[1].size() > 2) {
        long long int address;
        safeStrtoll(details[1], 16, address);
        readFromAddress(address, kLinuxSMBIOSRawLength_);
      }
    }
  }
}

bool LinuxSMBIOSParser::discoverTables(size_t address, size_t length) {
  // Linux will expose the SMBIOS/DMI entry point structures, which contain
  // a member variable with the DMI tables start address and size.
  // This applies to both the EFI-variable and physical memory search.
  auto status = osquery::readRawMem(address, length, (void**)&table_data_);
  if (!status.ok() || table_data_ == nullptr) {
    return false;
  }

  // The read was successful, save the size and wait for requests to parse.
  table_size_ = length;
  return true;
}

bool LinuxSMBIOSParser::discover() {
  if (osquery::isReadable(kLinuxEFISystabPath)) {
    readFromSystab(kLinuxEFISystabPath);
  } else {
    readFromAddress(kLinuxSMBIOSRawAddress_, kLinuxSMBIOSRawLength_);
  }
  return valid();
}

QueryData genSMBIOSTables(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size) {
    genSMBIOSTable(index, hdr, address, size, results);
  }));

  return results;
}

/// Read a string using the index that is offset-bytes within address.
std::string dmi_string(uint8_t* data, uint8_t* address, size_t offset) {
  auto index = (uint8_t)(*(address + offset));
  auto bp = (char*)data;
  while (index > 1) {
    while (*bp != 0) {
      bp++;
    }
    bp++;
    index--;
  }

  return std::string(bp);
}

QueryData genPlatformInfo(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size) {
    if (hdr->type != kSMBIOSTypeBIOS || size < 0x12) {
      return;
    }

    Row r;
    // The DMI string data uses offsets (indexes) into a data section that
    // trails the header and structure offsets.
    uint8_t* data = address + hdr->length;
    r["vendor"] = dmi_string(data, address, 0x04);
    r["version"] = dmi_string(data, address, 0x05);
    r["date"] = dmi_string(data, address, 0x08);

    // Firmware load address as a WORD.
    size_t firmware_address = (address[0x07] << 8) + address[0x06];
    std::stringstream hex_id;
    hex_id << std::hex << std::setw(4) << std::setfill('0') << firmware_address;
    r["address"] = "0x" + hex_id.str();

    // Firmware size as a count of 64k blocks.
    size_t firmware_size = (address[0x09] + 1) << 6;
    r["size"] = std::to_string(firmware_size * 1024);

    // Minor and major BIOS revisions.
    r["overall_status.bios_v"] = std::to_string((size_t)address[0x14]) + "." +
                    std::to_string((size_t)address[0x15]);
    r["volume_size"] = "0";
    r["extra"] = "";
    results.push_back(r);
  }));

  return results;
}

static void cpuid(int op, int *eax, int *ebx, int *ecx, int *edx)
{
    __asm__ __volatile("cpuid"
                : "=a" (*eax),
                  "=b" (*ebx),
                  "=c" (*ecx),
                  "=d" (*edx)
                : "a" (op)
                : "cc" );
}

static bool checkTurboStatus()
{
  //turbo state flag
  int eax, ebx, ecx, edx;
  cpuid (6, &eax, &ebx, &ecx, &edx);
  return ((eax & 0x2) >> 1);
}

#define HT_BIT             0x10000000     // EDX[28]  Bit 28 is set if HT is supported
static bool checkHTStatus()
{
  int eax, ebx, ecx, edx;
  cpuid (1, &eax, &ebx, &ecx, &edx);
  return edx & HT_BIT;
}

static int getSocketNum(void)
{
  FILE *cmd = popen("grep '^physical' /proc/cpuinfo | tail -1 | cut -d':' -f2 | tr -d ' '", "r");
  if (cmd == NULL)
    return -1;

  unsigned nprocs;
  size_t n;
  char buff[8];

  if ((n = fread(buff, 1, sizeof(buff)-1, cmd)) <= 0)
    return -1;

  buff[n] = '\0';
  if (sscanf(buff, "%u", &nprocs) != 1)
    return -1;

  pclose(cmd);

  return nprocs + 1;
}

QueryData genCPUInfo(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size) {
    if (hdr->type != 4 || size < 0x1a) {
      return;
    }

    Row r;
    uint8_t* data = address + hdr->length;
    r["timestamp"] = std::to_string(time(NULL));
    r["basic.manufacturer"] = dmi_string(data, address, 0x07);
    r["basic.model"] = dmi_string(data, address, 0x10);
    r["basic.slot"] = dmi_string(data, address, 0x04);
    std::stringstream id;
    id << std::dec << WORD(address + 0x14);
    r["basic.freq"] = id.str();
    r["performace.turbo"] = checkTurboStatus() ? "ON" : "OFF";
    r["performace.ht"] = checkHTStatus() ? "ON" : "OFF";
    r["basic.core_n"] = INTEGER(sysconf(_SC_NPROCESSORS_CONF)/getSocketNum());
    r["basic.l2_c"] = INTEGER(sysconf(_SC_LEVEL2_CACHE_SIZE));
    r["basic.l3_c"] = INTEGER(sysconf(_SC_LEVEL3_CACHE_SIZE));
    results.push_back(r);
  }));

  return results;
}

static int hostnameToIp(char * hostname , char* ip)
{
  struct hostent *he;
  struct in_addr **addr_list;
  int i;

  if ((he = gethostbyname(hostname)) == NULL)
    return -1;
  addr_list = (struct in_addr **) he->h_addr_list;

  for (i = 0; addr_list[i] != NULL; i++) {
    strcpy(ip , inet_ntoa(*addr_list[i]) );
    return 0;
  }

  return -2;
}

QueryData genMBInfo(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size) {
    if (hdr->type != 2 || size < 0x8) {
      return;
    }

    Row r;
    uint8_t* data = address + hdr->length;
    r["overall_status.mb_v"] = dmi_string(data, address, 0x06);

    results.push_back(r);
  }));

  return results;
}

QueryData genServerInfo(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size) {
    if (hdr->type != 1 || size < 0x8) {
      return;
    }

    Row r;
    uint8_t* data = address + hdr->length;
    r["timestamp"] = std::to_string(time(NULL));
    r["basic.manufacturer"] = dmi_string(data, address, 0x04);
    r["basic.model"] = dmi_string(data, address, 0x05);
    r["basic.raw_model"] = dmi_string(data, address, 0x05);
    r["basic.sn"] = dmi_string(data, address, 0x07);
    char hostname[1024];
    int ret = gethostname(hostname, 1024);
    if (ret < 0 ) {
      r["overall_status.hostname"] = "unknown";
      r["overall_status.main_ip"] = "unknown";
    } else {
      r["overall_status.hostname"] = hostname;
      char ip[100];
      int ret = hostnameToIp(hostname, ip);
      if (ret < 0)
        r["overall_status.main_ip"] = "unknown";
      else
        r["overall_status.main_ip"] = ip;
    }
    r["overall_status.cpu_n"] = INTEGER(getSocketNum());

    results.push_back(r);
  }));

  return results;
}

static int getDIMMSize(uint16_t code)
{
  int size = 0;
  if(code == 0 || code == 0xFFFF)
    size = 0;
  else {
    if (code & 0x8000)
      size = code / 1024;
    else
      size = code;
  }
  return size;
}

QueryData genDIMMInfo(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size) {
    if (hdr->type != 17 || size < 0x1b) {
      return;
    }

    Row r;
    uint8_t* data = address + hdr->length;
    r["timestamp"] = std::to_string(time(NULL));
    r["basic.manufacturer"] = dmi_string(data, address, 0x17);
    r["basic.model"] = dmi_string(data, address, 0x1a);
    r["basic.sn"] = dmi_string(data, address, 0x18);
    r["basic.slot"] = dmi_string(data, address, 0x10);
    r["basic.capacity"] = INTEGER(getDIMMSize(WORD(address + 0x0C)));
    if (size >= 0x22)
      r["basic.freq"] = INTEGER(WORD(address + 0x20));
    else
      r["basic.freq"] = INTEGER(0);
    if (size >= 0x28)
      r["basic.volt"] = INTEGER(WORD(address + 0x26));
    else
      r["basic.volt"] = INTEGER(0);
    r["basic.logicalslot"] = INTEGER(0);
    results.push_back(r);
  }));

  return results;
}

QueryData genDIMMNum(QueryContext& context) {
  LinuxSMBIOSParser parser;
  if (!parser.discover()) {
    VLOG(1) << "Could not read SMBIOS memory";
    return {};
  }

  QueryData results;
  parser.tables(([&results](
      size_t index, const SMBStructHeader* hdr, uint8_t* address, size_t size) {
    if (hdr->type != 16 || size < 0xf) {
      return;
    }

    Row r;
    r["overall_status.dimm_mn"] = INTEGER(WORD(address + 0x0d));
    results.push_back(r);
  }));

  return results;
}

}
}
