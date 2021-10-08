////////////////////////////////////////////////////////////////////////////////////
//
// SamplesLoader loads probe sample data from binary files
//
// Xpedite probes store timing and performance counter data using variable 
// length POD objects. A collection of sample objects is grouped and written
// as a batch. 
//
// The loader iterates through the POD collection,  to extract 
// records in string format for consumption by the profiler
//
// Author: Manikandan Dhamodharan, Morgan Stanley
//
////////////////////////////////////////////////////////////////////////////////////

#pragma once

#include <xpedite/util/Errno.H>
#include <xpedite/framework/Persister.H>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <regex>
#include <fstream>

namespace xpedite { namespace framework {

  struct ProbeInfo
  {
       public:

       uint32_t id;
       const void *recorder_return_site;
       std::string name;
       std::string file;
       uint32_t line;
       std::string function;

       std::string toString() const {
         std::ostringstream os;
         os << "Probe [" << name << " " <<  std::hex << recorder_return_site << "]"
         << " " << file << ":" << std::dec << line << ":" << function << "()";
         return os.str();
       };
  };

  class SamplesLoader
  {
    int _fd;
    const FileHeader* _fileHeader;
    std::unordered_map<const void *, ProbeInfo> _returnSiteMap;
    CallSiteMap _callSiteMap;
    const SegmentHeader* _segmentHeader;
    unsigned _size;

    const void* samplesEnd() const noexcept {
      return reinterpret_cast<const char*>(_fileHeader) + _size;
    }

    SamplesLoader(const SamplesLoader&)            = delete;
    SamplesLoader& operator=(const SamplesLoader&) = delete;
    SamplesLoader(SamplesLoader&&)                 = delete;
    SamplesLoader& operator=(SamplesLoader&&)      = delete;

    public:

    class Iterator : public std::iterator<std::input_iterator_tag, const probes::Sample>
    {
      const probes::Sample* _samples;
      const void* _end;
      unsigned _size;
      timespec _segmentStartTime;

      public:

      explicit Iterator(const SegmentHeader* samplesHeader_, const void* end_)
        : _samples {reinterpret_cast<const probes::Sample*>(end_)}, _end {end_}, _size {}, _segmentStartTime {} {
        if(samplesHeader_ < _end) {
          std::tie(_samples, _size) = samplesHeader_->samples();
          _segmentStartTime = samplesHeader_->time();
        }
      }

      explicit Iterator(const void* begin_, const void* end_)
        : _samples {reinterpret_cast<const probes::Sample*>(begin_)}, _end {end_}, _size {}, _segmentStartTime {} {
      }

      Iterator& operator++() {
        if(_samples < _end) {
          _size -= _samples->size();
          _samples = _samples->next();
          if(!_size && _samples < _end) {
            auto samplesHeader = reinterpret_cast<const SegmentHeader*>(_samples);
            _segmentStartTime = samplesHeader->time();
            std::tie(_samples, _size) = samplesHeader->samples();
          }
        }
        return *this;
      }

      Iterator operator++(int) {
        Iterator i {*this};
        operator++();
        return i;
      }

      bool operator==(Iterator other_) const {
        return _samples == other_._samples && _end == other_._end;
      }

      bool operator!=(Iterator other_) const {
        return !(*this == other_);
      }

      reference operator*() const {
        return *_samples;
      }

      const timespec& segmentStartTime() const noexcept {
        return _segmentStartTime;
      }
    };

    explicit SamplesLoader(const char* path_)
      : _fd {}, _fileHeader {}, _returnSiteMap {}, _callSiteMap {}, _segmentHeader {}, _size {} {
      load(path_);
    }

    explicit SamplesLoader(const char* path_, const char* appinfo_path_)
      : _fd {}, _fileHeader {}, _returnSiteMap {}, _callSiteMap {}, _segmentHeader {}, _size {} {
      load(path_);
      std::ifstream appinfo;
      appinfo.open(appinfo_path_);
      if (!appinfo.is_open()) {
           throw std::runtime_error{ errorMsg("failed to open appinfo file") };
      }
      std::string appinfo_line;
      std::string id_prefix = "Id=";
      while (std::getline(appinfo, appinfo_line) ) {
         // Extraction of several sub-matches
         const std::regex probe_info_regex("Id=([0-9]+) \\| Probe=([^|]+)\\| CallSite=([^|]+)\\| RecorderReturnSite=([^ ]+) \\| Status=[^|]+\\| Name=([^|]+) \\| File=([^|]+) \\| Line=([0-9]+) \\| Function=([^|]+) .*");
         std::smatch probe_info_match;
         if (std::regex_match(appinfo_line, probe_info_match, probe_info_regex)) {

              uint32_t id = stoul(probe_info_match[1].str(), nullptr, 10);
              const void *recorder_return_site = (const void*)stoull(probe_info_match[4].str(), nullptr, 0);
              std::string name = (probe_info_match[5].str());
              std::string file = (probe_info_match[6].str());
              uint32_t line = stoul(probe_info_match[7].str(), nullptr, 0);
              std::string function = (probe_info_match[8].str());

              ProbeInfo probe_info {
                   id,
                   recorder_return_site,
                   name,
                   file,
                   line,
                   function
              };
              _returnSiteMap.emplace(recorder_return_site, probe_info);
         }
      }
    }

    ~SamplesLoader() {
      if(_fileHeader) {
        munmap(const_cast<FileHeader*>(_fileHeader), _size);
      }
      if(_fd) {
        close(_fd);
      }
    }

    std::string errorMsg(const char* msg_) {
      util::Errno e;
      std::ostringstream os;
      os << msg_ << " - " << e.asString();
      return os.str();
    }

    void load(const char* path_) {
      int _fd = open(path_, O_RDONLY);
      if (_fd < 0) {
        throw std::runtime_error {errorMsg("failed to open samples file")};
      }

      struct stat buf;
      if(fstat(_fd, &buf)) {
        throw std::runtime_error {errorMsg("failed to stat samples file")};
      }
      _size = buf.st_size;

      char* ptr {};
      if((ptr = static_cast<char*>(mmap(nullptr, _size, PROT_READ, MAP_SHARED, _fd, 0))) == MAP_FAILED) {
        throw std::runtime_error {errorMsg("failed to mmap file")};
      }

      _fileHeader = reinterpret_cast<const FileHeader*>(ptr);
      if(!_fileHeader->isValid()) {
        throw std::runtime_error {errorMsg("detected data corruption - mismatch in header signature")};
      }

      const CallSiteInfo* callSites;
      uint64_t callSiteCount;
      std::tie(callSites, callSiteCount) = _fileHeader->callSites();
      for(unsigned i=0; i<callSiteCount; ++i) {
        _callSiteMap.add(callSites[i]);
      }
      _segmentHeader = _fileHeader->segmentHeader();
    }

    const CallSiteInfo* locateCallSite(const void* callSite_) const noexcept {
      return _callSiteMap.locateInfo(callSite_);
    }

    uint32_t pmcCount()             const noexcept { return _fileHeader->pmcCount(); }
    const CallSiteMap callSiteMap() const noexcept { return _callSiteMap;            }
    const std::unordered_map<const void *, ProbeInfo> returnSiteMap() const noexcept { return _returnSiteMap; }

    Iterator begin() const { return Iterator {_segmentHeader, samplesEnd()}; }
    Iterator end() const   { return Iterator {samplesEnd(), samplesEnd()};   }

    uint64_t tscHz() const noexcept {
      if(_fileHeader) {
        return _fileHeader->tscHz();
      }
      return {};
    }
  };

}}
