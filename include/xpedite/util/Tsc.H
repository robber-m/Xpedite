///////////////////////////////////////////////////////////////////////////////
//
// Assembly code to read time stamp counter from cpu
//
// Logic to estimate frequency of cpu time stamp counter
//
// Author: Manikandan Dhamodharan, Morgan Stanley
//
///////////////////////////////////////////////////////////////////////////////

#pragma once
#include <cstdint>
#include <cstddef>
#include <math.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <xmmintrin.h>
#include <xpedite/platform/Builtins.H>

#ifndef RDTSC
#define RDTSC() ({                                                \
  uint32_t lo, hi;                                                \
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));            \
  (uint64_t)hi << 32 | lo;                                        \
})
#endif

#ifndef RDPMC
#define RDPMC(pmu) ({                                             \
  unsigned hi, lo;                                                \
  __asm__ __volatile__("rdpmc" : "=a"(lo), "=d"(hi) : "c"(pmu));  \
  (unsigned long)hi << 32 | lo;                                   \
})
#endif

namespace xpedite { namespace util {

  constexpr uint64_t NANOS {1000000000};
  inline uint64_t estimateTscHz() noexcept {
    timespec  begin, end;
    auto beginTsc1 = RDTSC();
    if(clock_gettime(CLOCK_REALTIME, &begin)) {
      return {};
    }
    auto endTsc1 = RDTSC();

    usleep(10000);

    auto beginTsc2 = RDTSC();
    if(clock_gettime(CLOCK_REALTIME, &end)) {
      return {};
    }
    auto endTsc2 = RDTSC();

    auto elapsedNsec = (end.tv_sec - begin.tv_sec) * NANOS + (end.tv_nsec - begin.tv_nsec);
    auto elapsedTsc = (beginTsc2 + endTsc2) / 2 - (beginTsc1 + endTsc1) / 2;
    return elapsedTsc * NANOS / elapsedNsec;
  }

  inline uint64_t timespecToPosixNanoseconds(const timespec &ts)
  {
     return (uint64_t)ts.tv_sec * NANOS + ts.tv_nsec;
  }

  inline timespec posixNanosecondsToTimespec(const uint64_t posixNanoseconds)
  {
    timespec ts;
    uint64_t posixSeconds = posixNanoseconds / NANOS;
    ts.tv_sec = posixSeconds;
    ts.tv_nsec = posixNanoseconds - (posixSeconds * NANOS);
    return ts;
  }

  // NOTE: tsc and posixNanoseconds should both represent the same point in time
  struct TscPosixPair {
    uint64_t tsc;
    int64_t posixNanoseconds;
  };

  // TODO: assert 16-byte alignment for atomicity
  // Supports thread-safe calibration and scaling of Tsc values to Nanoseconds since the UNIX Epoch
  union TscToPosixScaleFactor {
    struct {
      double  ratio;
      int64_t offset;
    };
    __m128 vec;

    TscToPosixScaleFactor() : ratio {0}, offset {0} {
    }

    inline __m128 load() { // TODO: private?
      volatile TscToPosixScaleFactor *volatileThis = this;
      // TODO: assert 16-byte alignment for atomicity
      return volatileThis->vec;
    }

    inline void store( __m128 val_ ) { // TODO: private?
      volatile TscToPosixScaleFactor *volatileThis = this;
      // TODO: assert 16-byte alignment for atomicity
      volatileThis->vec = val_;
    }

    // Once initialized, the scale factor will always remain initialized
    bool isInitialized() {
      volatile TscToPosixScaleFactor *volatileThis = this;
      return volatileThis->ratio == 0;
    }

    // Single-writer, but multiple readers may simultaneously call apply()
    // returns true on success
    bool calibrate(uint32_t calibrationIntervalMicroseconds, uint64_t tscHz, const TscPosixPair &previous, const TscPosixPair &current) {
      TscToPosixScaleFactor currentScaleFactor;
      if ( XPEDITE_UNLIKELY(isInitialized() == false) ) {
        // First time calculating scale, don't have to worry about old scaling coeffs
        currentScaleFactor.ratio  = (double) (current.posixNanoseconds - previous.posixNanoseconds) / (current.tsc - previous.tsc);
        currentScaleFactor.offset = current.posixNanoseconds - (int64_t)(current.tsc * currentScaleFactor.ratio);
      } else {
        const uint64_t minimumCalibrationTscInterval = calibrationIntervalMicroseconds * ((double)tscHz / 1000000) * 9 / 10; // TODO: how did Matt come up with this value? Starting to understand.. limit == .10 meaning the ratio is only allowed to change 10% per interval. There should be 10 TSC intervals in a calibration interval... or maybe it means, if the new ratio is more than 10% larger or smaller than the old, change the offset and use the old ratio. Otherwise, adjust both the ratio and offset.


        /* System clock can be adjusted by ntpd. To avoid seeing large system clock change over a very small
           number of TSC ticks, which leads to too-large slope in linear transfer function, make sure enough
           TSC ticks have elapsed since last sample */
        if ((current.tsc - previous.tsc) < minimumCalibrationTscInterval) return false;

        TscToPosixScaleFactor previousScaleFactor;
        previousScaleFactor.vec = load();

        // Calculate posix time from the new timestamp using the old scaling coefficients
        uint64_t currentTscConvertedPosixNanoseconds = apply(current.tsc);

        // Correct the conversion curve in a continous fashion (no discontinuous jumps forward or backward in posix time).
        // Calculate new coefficients so error is estimated to taper to zero by the next calibration time.
        // The graph of new conversions is the line from point (cur_tsc, cur_posix + err_posix) through point
        // (2 * cur_tsc - prev_tsc, 2 * cur_posix - prev_posix)
        currentScaleFactor.ratio  = (double) ((int64_t)2 * (int64_t)current.posixNanoseconds - (int64_t)previous.posixNanoseconds - (int64_t)currentTscConvertedPosixNanoseconds) / (current.tsc - previous.tsc);
        double percentChange = (currentScaleFactor.ratio - previousScaleFactor.ratio) / previousScaleFactor.ratio;
        constexpr double limit {0.10};

        if (fabs(percentChange) > limit) {
          currentScaleFactor.ratio = previousScaleFactor.ratio; // Use the old ratio if the new one changed too dramatically
          currentScaleFactor.offset = current.posixNanoseconds - (int64_t)(current.tsc * currentScaleFactor.ratio);
        } else {
          currentScaleFactor.offset = currentTscConvertedPosixNanoseconds - (int64_t)(current.tsc * currentScaleFactor.ratio);
        }
      }

      // Publish the new factor atomically
      store( currentScaleFactor.vec );
      return true;
    }


    // Multi-reader, scale tsc values to nanoseconds since the UNIX epoch
    inline uint64_t apply(uint64_t tsc) {
      //assert( isInitialized() == true ); // Calibrate must have been called once before calling apply()
      TscToPosixScaleFactor coherentScaleFactor;
      // read atomically to allow for thread-safe calibration
      coherentScaleFactor.vec = load();
      return (uint64_t) ((int64_t) (tsc * coherentScaleFactor.ratio) + coherentScaleFactor.offset);
    }
  };

  // Convert tsc values to/from POSIX nanoseconds since the UNIX epoch
  class TscConverter
  {
    public:
      static TscConverter &instance() {
        static TscConverter instance;
        return instance;
      }

      // thread-safe w/r/t the calibration thread
      inline uint64_t toPosixNanoseconds(uint64_t tsc) {
        return _tscToPosixScaleFactor.apply(tsc);
      }

    private:
      static constexpr uint32_t SYNC_USECS {100000}; // 100 milliseconds
      TscConverter() {
        _calibrationThread = std::thread(calibrate, &_tscToPosixScaleFactor);
        // Block in the constructor until the calibration thread completes initialization
        while (_tscToPosixScaleFactor.ratio == 0) {
             usleep(SYNC_USECS);
        }
      }

      // Delete copy/move so extra instances can't be created/moved.
      TscConverter(const TscConverter&) = delete;
      TscConverter& operator=(const TscConverter&) = delete;
      TscConverter(TscConverter&&) = delete;
      TscConverter& operator=(TscConverter&&) = delete;

      TscToPosixScaleFactor _tscToPosixScaleFactor;
      std::thread _calibrationThread;

      static TscPosixPair getTscAndPosixNanoseconds() {
        uint64_t tsc = 0;
        int64_t posix = 0;

        timespec ts;
        uint64_t start_timestamp, end_timestamp;

        // To protect against a context switch in middle of reading, try three times and save the quickest read time
        uint64_t shortest_read_time = 0;
        for (int i = 0; i < 3; i++) {
          start_timestamp = RDTSC();
          clock_gettime(CLOCK_REALTIME, &ts);
          end_timestamp = RDTSC();

          uint64_t read_time = end_timestamp - start_timestamp;
          if (shortest_read_time == 0 || read_time < shortest_read_time) {
            shortest_read_time = read_time;
            tsc = (start_timestamp + end_timestamp) / 2;
            posix = timespecToPosixNanoseconds(ts);
          }
        }
        return TscPosixPair{tsc, posix};
      }

      // calibrate the TSC to POSIX time scale factor
      static void calibrate(TscToPosixScaleFactor *tscToPosixScaleFactor)
      {
        static uint64_t tscHz = estimateTscHz();
        auto previous = getTscAndPosixNanoseconds();

        while (true) {
          usleep(SYNC_USECS);

          auto current = getTscAndPosixNanoseconds();

          if ( tscToPosixScaleFactor->calibrate(SYNC_USECS, tscHz, previous, current) ) {
            previous = current;
          }
        }
      }
  };

}}
