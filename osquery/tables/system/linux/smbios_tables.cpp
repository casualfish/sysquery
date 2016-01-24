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

#include <boost/noncopyable.hpp>

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
    r["revision"] = std::to_string((size_t)address[0x14]) + "." +
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
    r["vendor"] = base64Encode(dmi_string(data, address, 0x07));
    r["model"] = base64Encode(dmi_string(data, address, 0x10));
    r["slot"] = base64Encode(dmi_string(data, address, 0x04));
    std::stringstream id;
    id << std::dec << WORD(address + 0x14);
    r["maxfreq"] = base64Encode(id.str());
    r["turbo"] = base64Encode(checkTurboStatus() ? "ON" : "OFF");
    int eax, ebx, ecx, edx;
    char vendor[12];
    cpuid(0, &eax, &ebx, &ecx, &edx);
    ((unsigned *)vendor)[0] = ebx; // EBX
    ((unsigned *)vendor)[1] = edx; // EDX
    ((unsigned *)vendor)[2] = ecx; // ECX
    std::string cpuVendor = std::string(vendor, 12);
    // Get CPU features
    cpuid(1, &eax, &ebx, &ecx, &edx);
    unsigned cpuFeatures = edx; // EDX
    // Logical core count per CPU
    cpuid(1, &eax, &ebx, &ecx, &edx);
    unsigned logical = (ebx >> 16) & 0xff; // EBX[23:16]
    unsigned cores = logical;
    if (cpuVendor == "GenuineIntel") {
      // Get DCP cache info
      cpuid(4, &eax, &ebx, &ecx, &edx);
      cores = ((eax >> 26) & 0x3f) + 1; // EAX[31:26] + 1
    } else if (cpuVendor == "AuthenticAMD") {
      // Get NC: Number of CPU cores - 1
      cpuid(0x80000008, &eax, &ebx, &ecx, &edx);
      cores = ((unsigned)(ecx & 0xff)) + 1; // ECX[7:0] + 1
    }
    bool hyperThreads = cpuFeatures & (1 << 28) && cores < logical;
    r["ht"] = base64Encode(hyperThreads ? "ON" : "OFF");
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
    r["vendor"] = base64Encode(dmi_string(data, address, 0x04));
    r["model"] = base64Encode(dmi_string(data, address, 0x05));
    r["raw_model"] = base64Encode(dmi_string(data, address, 0x05));
    r["sn"] = base64Encode(dmi_string(data, address, 0x07));
    char hostname[1024];
    int ret = gethostname(hostname, 1024);
    if (ret < 0 )
      r["hostname"] = "unknown";
    else
      r["hostname"] = base64Encode(hostname);

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

static int getDIMMWidth(uint16_t code)
{
  int width = 0;
  if (code == 0xFFFF || code == 0 || code < 32)
    width = 0;
  else
    width = code;
  return width;
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
    r["vendor"] = base64Encode(dmi_string(data, address, 0x17));
    r["model"] = base64Encode(dmi_string(data, address, 0x1a));
    r["sn"] = base64Encode(dmi_string(data, address, 0x18));
    r["slot"] = base64Encode(dmi_string(data, address, 0x10));
    std::stringstream id;
    id << std::dec << getDIMMSize(WORD(address + 0x0C));
    r["capacity"] = id.str();
    id.clear();
    id << std::dec << getDIMMWidth(WORD(address + 0x0A));
    r["width"] = id.str();
    results.push_back(r);
  }));

  return results;
}

}
}
