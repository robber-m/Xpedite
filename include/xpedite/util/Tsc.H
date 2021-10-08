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

  inline uint64_t timespecToPosixNanoseconds(timespec &ts)
  {
     return (uint64_t)ts.tv_sec * NANOS + ts.tv_nsec;
  }

  inline timespec posixNanosecondsToTimespec(uint64_t posixNanoseconds)
  {
    timespec ts;
    uint64_t posixSeconds = posixNanoseconds / NANOS;
    ts.tv_sec = posixSeconds;
    ts.tv_nsec = posixNanoseconds - (posixSeconds * NANOS);
    return ts;
  }

  // convert tsc values to/from POSIX nanoseconds since the UNIX epoch
  class TscConverter
  {
    public:
      static TscConverter &instance() {
        static TscConverter instance;
        return instance;
      }

      // thread-safe w/r/t the calibration thread
      uint64_t toPosixNanoseconds(uint64_t tsc) {
           TscScaleFactor scaleFactor;
           scaleFactor.vec = _tscToPosixScaleFactor.vec;

           return (uint64_t) ((int64_t) (tsc * scaleFactor.ratio) + scaleFactor.offset);
      }

    private:

      union TscScaleFactor {
        struct {
          double  ratio;
          int64_t offset;
        };
        __m128 vec;
      };

      static constexpr uint32_t SYNC_USECS {100000}; // 100 milliseconds
      TscConverter() {
        _tscToPosixScaleFactor.ratio = 0;
        _tscToPosixScaleFactor.offset = 0;

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

      volatile TscScaleFactor _tscToPosixScaleFactor;
      std::thread _calibrationThread;

      static std::tuple<uint64_t, int64_t> getTscAndPosixNanoseconds() {
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
        return std::make_tuple(tsc, posix);
      }

      // calibrate the TSC to POSIX time scale factor
      static void calibrate(volatile TscScaleFactor *tscToPosixScaleFactor)
      {
        static uint64_t tscHz = estimateTscHz();
        const uint64_t minimumCalibrationTscInterval = SYNC_USECS * ((double)tscHz / 1000000) * 9 / 10; // TODO: how did Matt come up with this value?

        int64_t previousPosixNanoseconds, currentPosixNanoseconds = 0;
        uint64_t previousTsc, currentTsc = 0;

        std::tie(previousTsc, previousPosixNanoseconds) = getTscAndPosixNanoseconds();

        bool initialized = false;

        while (true) {
          usleep(SYNC_USECS);

          std::tie(currentTsc, currentPosixNanoseconds) = getTscAndPosixNanoseconds();

          /* System clock can be adjusted by ntpd. To avoid seeing large system clock change over a very small
             number of TSC ticks, which leads to too-large slope in linear transfer function, make sure enough
             TSC ticks have elapsed since last sample */
          if ((currentTsc - previousTsc) < minimumCalibrationTscInterval) continue;

          TscScaleFactor scaleFactor;
          if (!initialized) {
            /// First time calculating scale, don't have to worry about old scaling coeffs
            scaleFactor.ratio  = (double) (currentPosixNanoseconds - previousPosixNanoseconds) / (currentTsc - previousTsc);
            scaleFactor.offset = currentPosixNanoseconds - (int64_t)(currentTsc * scaleFactor.ratio);
          } else {
            TscScaleFactor previousScaleFactor;
            previousScaleFactor.vec = tscToPosixScaleFactor->vec;
            /// Calc posix time from current timestamp using old scaling coeffs
            uint64_t currentTscConvertedPosixNanoseconds = instance().toPosixNanoseconds(currentTsc);

            // Correct the conversion curve in a continous fashion (no discontinuous jumps forward or backward in posix time).
            // Calc new coeffs so error is estimated to taper to zero by the next calibration time.
            // The graph of new conversion is line from point (cur_t, cur_p+err_p) thru point (2*cur_t-last_t, 2*cur_p-last_p).
            // Where *_t is timestamp_time and *_p is posix_time.
            scaleFactor.ratio  = (double) ((int64_t)2 * (int64_t)currentPosixNanoseconds - (int64_t)previousPosixNanoseconds - (int64_t)currentTscConvertedPosixNanoseconds) / (currentTsc - previousTsc);
            double percentage = (scaleFactor.ratio - previousScaleFactor.ratio) / previousScaleFactor.ratio;
            constexpr double limit {0.10};

            if (fabs(percentage) > limit) {
              scaleFactor.ratio = previousScaleFactor.ratio;
              scaleFactor.offset = currentPosixNanoseconds - (int64_t)(currentTsc * scaleFactor.ratio);
            } else {
              scaleFactor.offset = currentTscConvertedPosixNanoseconds - (int64_t)(currentTsc * scaleFactor.ratio);
            }
          }

          // Publish the two factors atomically
          // assert(IS_ALIGNED16(tscToPosixScaleFactor));
          tscToPosixScaleFactor->vec = scaleFactor.vec;

          initialized = true;
          previousTsc = currentTsc;
          previousPosixNanoseconds = currentPosixNanoseconds;
        }
      }
  };

}}
