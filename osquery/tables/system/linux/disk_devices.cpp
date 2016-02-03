/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string.hpp>

#include <libudev.h>
#include <blkid/blkid.h>
#include <unistd.h>
#include <fcntl.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

static void getDiskDevice(struct udev_device *dev, QueryData &results) {
  Row r;
  const char *name = udev_device_get_devnode(dev);
  if (name == nullptr || major(udev_device_get_devnum(dev)) != 8 || 
        strcmp(udev_device_get_devtype(dev), "disk")) {
    //only get info of disk
    return;
  }

  r["timestamp"] = std::to_string(time(NULL));
  r["basic.rpm"] = INTEGER(7200);
  r["basic.media"] = udev_device_get_devtype(dev);
  r["basic.model"] = udev_device_get_property_value(dev, "ID_MODEL");
  r["basic.interface"] = udev_device_get_property_value(dev, "ID_VENDOR");
  r["basic.sn"] = udev_device_get_property_value(dev, "ID_SERIAL");
  r["basic.manufacturer"] = udev_device_get_property_value(dev, "ID_MODEL");
  int fd = open(udev_device_get_devnode(dev), O_RDONLY);
  if (fd < 0)
    r["basic.capacity"] = INTEGER(0);
  else {
    off_t size = lseek(fd, 0, SEEK_END);
    r["basic.capacity"] = INTEGER(size);
    close(fd);
  }
  blkid_probe pr = blkid_new_probe_from_filename(udev_device_get_devnode(dev));
  if (!pr) {
    r["basic.lss"] = INTEGER(0);
    r["basic.pss"] = INTEGER(0);
  } else {
    blkid_topology tp = blkid_probe_get_topology(pr);
    r["basic.lss"] = INTEGER(blkid_topology_get_logical_sector_size(tp));
    r["basic.pss"] = INTEGER(blkid_topology_get_physical_sector_size(tp));
    blkid_free_probe(pr);
  }

  results.push_back(r);
}

QueryData genDiskDevs(QueryContext &context) {
  if (getuid() || geteuid()) {
    VLOG(1) << "Not running as root, some column data not available";
  }

  QueryData results;

  struct udev *udev = udev_new();
  if (udev == nullptr) {
    return {};
  }

  struct udev_enumerate *enumerate = udev_enumerate_new(udev);
  udev_enumerate_add_match_subsystem(enumerate, "block");
  udev_enumerate_scan_devices(enumerate);

  struct udev_list_entry *devices, *dev_list_entry;
  devices = udev_enumerate_get_list_entry(enumerate);
  udev_list_entry_foreach(dev_list_entry, devices) {
    const char *path = udev_list_entry_get_name(dev_list_entry);
    struct udev_device *dev = udev_device_new_from_syspath(udev, path);
    if (path != nullptr && dev != nullptr) {
      getDiskDevice(dev, results);
    }
    udev_device_unref(dev);
  }

  udev_enumerate_unref(enumerate);
  udev_unref(udev);

  return results;
}
}
}
