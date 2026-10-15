/**
 * @file src/stream.cpp
 * @brief Definitions for the streaming protocols.
 */

// standard includes
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <mutex>
#include <future>
#include <queue>

// lib includes
#include <boost/endian/arithmetic.hpp>
#include <boost/endian/conversion.hpp>
#include <openssl/err.h>

extern "C" {
  // clang-format off
#include <moonlight-common-c/src/Limelight-internal.h>
#include "rswrapper.h"
  // clang-format on
}

// local includes
#include "config.h"
#include "crypto.h"
#include "display_device.h"
#include "globals.h"
#include "input.h"
#include "logging.h"
#include "network.h"
#include "platform/common.h"
#include "process.h"
#include "stream.h"
#include "sync.h"
#include "system_tray.h"
#include "thread_safe.h"
#include "utility.h"

#define IDX_START_A 0
#define IDX_START_B 1
#define IDX_INVALIDATE_REF_FRAMES 2
#define IDX_LOSS_STATS 3
#define IDX_INPUT_DATA 5
#define IDX_RUMBLE_DATA 6
#define IDX_TERMINATION 7
#define IDX_PERIODIC_PING 8
#define IDX_REQUEST_IDR_FRAME 9
#define IDX_ENCRYPTED 10
#define IDX_HDR_MODE 11
#define IDX_RUMBLE_TRIGGER_DATA 12
#define IDX_SET_MOTION_EVENT 13
#define IDX_SET_RGB_LED 14
#define IDX_EXEC_SERVER_CMD 15
#define IDX_SET_CLIPBOARD 16
#define IDX_FILE_TRANSFER_NONCE_REQUEST 17
#define IDX_SET_ADAPTIVE_TRIGGERS 18

static const short packetTypes[] = {
  0x0305,  // Start A
  0x0307,  // Start B
  0x0301,  // Invalidate reference frames
  0x0201,  // Loss Stats
  0x0204,  // Frame Stats (unused)
  0x0206,  // Input data
  0x010b,  // Rumble data
  0x0109,  // Termination
  0x0200,  // Periodic Ping
  0x0302,  // IDR frame
  0x0001,  // fully encrypted
  0x010e,  // HDR mode
  0x5500,  // Rumble triggers (Sunshine protocol extension)
  0x5501,  // Set motion event (Sunshine protocol extension)
  0x5502,  // Set RGB LED (Sunshine protocol extension)
  0x3000,  // Execute Server Command (Apollo protocol extension)
  0x3001,  // Set Clipboard (Apollo protocol extension)
  0x3002,  // File transfer nonce request (Apollo protocol extension)
  0x5503,  // Set Adaptive triggers (Sunshine protocol extension)
};

namespace asio = boost::asio;
namespace sys = boost::system;

using asio::ip::tcp;
using asio::ip::udp;

using namespace std::literals;

namespace stream {

  enum class socket_e : int {
    video,  ///< Video
    audio  ///< Audio
  };

#pragma pack(push, 1)

  struct video_short_frame_header_t {
    uint8_t *payload() {
      return (uint8_t *) (this + 1);
    }

    std::uint8_t headerType;  // Always 0x01 for short headers

    // Sunshine extension
    // Frame processing latency, in 1/10 ms units
    //     zero when the frame is repeated or there is no backend implementation
    boost::endian::little_uint16_at frame_processing_latency;

    // Currently known values:
    // 1 = Normal P-frame
    // 2 = IDR-frame
    // 4 = P-frame with intra-refresh blocks
    // 5 = P-frame after reference frame invalidation
    std::uint8_t frameType;

    // Length of the final packet payload for codecs that cannot handle
    // zero padding, such as AV1 (Sunshine extension).
    boost::endian::little_uint16_at lastPayloadLen;

    std::uint8_t unknown[2];
  };

  static_assert(
    sizeof(video_short_frame_header_t) == 8,
    "Short frame header must be 8 bytes"
  );

  struct video_packet_raw_t {
    uint8_t *payload() {
      return (uint8_t *) (this + 1);
    }

    RTP_PACKET rtp;
    char reserved[4];

    NV_VIDEO_PACKET packet;
  };

  struct video_packet_enc_prefix_t {
    std::uint8_t iv[12];  // 12-byte IV is ideal for AES-GCM
    std::uint32_t frameNumber;
    std::uint8_t tag[16];
  };

  struct audio_packet_t {
    RTP_PACKET rtp;
  };

  struct control_header_v2 {
    std::uint16_t type;
    std::uint16_t payloadLength;

    uint8_t *payload() {
      return (uint8_t *) (this + 1);
    }
  };

  struct control_terminate_t {
    control_header_v2 header;

    std::uint32_t ec;
  };

  struct control_rumble_t {
    control_header_v2 header;

    std::uint32_t useless;

    std::uint16_t id;
    std::uint16_t lowfreq;
    std::uint16_t highfreq;
  };

  struct control_rumble_triggers_t {
    control_header_v2 header;

    std::uint16_t id;
    std::uint16_t left;
    std::uint16_t right;
  };

  struct control_set_motion_event_t {
    control_header_v2 header;

    std::uint16_t id;
    std::uint16_t reportrate;
    std::uint8_t type;
  };

  struct control_set_rgb_led_t {
    control_header_v2 header;

    std::uint16_t id;
    std::uint8_t r;
    std::uint8_t g;
    std::uint8_t b;
  };

  struct control_adaptive_triggers_t {
    control_header_v2 header;

    std::uint16_t id;
    /**
     * 0x04 - Right trigger
     * 0x08 - Left trigger
     */
    std::uint8_t event_flags;
    std::uint8_t type_left;
    std::uint8_t type_right;
    std::uint8_t left[DS_EFFECT_PAYLOAD_SIZE];
    std::uint8_t right[DS_EFFECT_PAYLOAD_SIZE];
  };

  struct control_hdr_mode_t {
    control_header_v2 header;

    std::uint8_t enabled;

    // Sunshine protocol extension
    SS_HDR_METADATA metadata;
  };

  typedef struct control_encrypted_t {
    std::uint16_t encryptedHeaderType;  // Always LE 0x0001
    std::uint16_t length;  // sizeof(seq) + 16 byte tag + secondary header and data

    // seq is accepted as an arbitrary value in Moonlight
    std::uint32_t seq;  // Monotonically increasing sequence number (used as IV for AES-GCM)

    uint8_t *payload() {
      return (uint8_t *) (this + 1);
    }

    // encrypted control_header_v2 and payload data follow
  } *control_encrypted_p;

  struct audio_fec_packet_t {
    RTP_PACKET rtp;
    AUDIO_FEC_HEADER fecHeader;
  };

#pragma pack(pop)

  constexpr std::size_t round_to_pkcs7_padded(std::size_t size) {
    return ((size + 15) / 16) * 16;
  }

  constexpr std::size_t MAX_AUDIO_PACKET_SIZE = 1400;

  using audio_aes_t = std::array<char, round_to_pkcs7_padded(MAX_AUDIO_PACKET_SIZE)>;

  // FrogtaleTV patch: video NACK / retransmit for lossy links.
  //
  // Over Starlink the downlink stalls for 30-80 ms every few seconds and drops what was in
  // flight. Stock Moonlight can only answer with an RFI, which costs a round trip plus an IDR
  // and visibly stutters; GeForce Now instead NACKs the missing packets and gets them resent.
  // We keep the last HISTORY sent video packets (already encrypted, exactly as sent) per client
  // endpoint, and a patched client sends "FTNK" + ranges of missing RTP sequence numbers on the
  // video socket. Stock clients never send FTNK, so this changes nothing for them.
  namespace nack {
    constexpr std::size_t HISTORY = 4096;
    constexpr std::size_t MAX_RANGES = 64;
    constexpr uint16_t BURST_PACKETS = 4;  // a NACK range at least this long is a loss burst
    constexpr uint16_t LEARN_BURST_PACKETS = 8;  // ... and this long is a stall worth learning from

    struct history_t {
      std::mutex mutex;
      std::uintptr_t native_socket = 0;
      asio::ip::address address;
      uint16_t port = 0;
      asio::ip::address local_address;
      std::size_t prefixsize = 0;
      std::size_t blocksize = 0;
      std::array<uint16_t, HISTORY> seqs {};
      std::array<bool, HISTORY> valid {};
      std::array<bool, HISTORY> loss_counted {};  // this slot's packet already counted as lost once
      std::vector<char> packets;
      uint64_t resent = 0;
      uint64_t unavailable = 0;

      // Set once this client has sent an FTNK, i.e. it is a patched client that will use duplicates.
      bool nacking = false;
      std::deque<std::pair<std::chrono::steady_clock::time_point, uint16_t>> duplicates;
      uint64_t duplicated = 0;

      // Adaptive bitrate (frogtale_adaptive_bitrate): loss = NACKed / sent outside handoff windows
      safe::mail_raw_t::event_t<int> bitrate_events;
      int base_kbps = 0;
      int current_kbps = 0;
      int clean_seconds = 0;
      uint64_t sent = 0;
      uint64_t nacked_off_window = 0;
      uint64_t last_sent = 0;
      uint64_t last_nacked = 0;
      std::chrono::steady_clock::time_point last_eval;

      // Adaptive FEC: all NACKed packets (bursts and scattered) outside handoff windows
      uint64_t nacked_all_off_window = 0;
      uint64_t last_nacked_all = 0;
      int fec_boost = 0;  // FEC percentage to use instead of the configured one, 0 = configured
      int fec_clean_seconds = 0;
      int mild_loss_seconds = 0;  // consecutive seconds of 1-3% loss
      int lossy_seconds = 0;  // consecutive seconds over 3% loss

      // Delay-based step-down (frogtale_delay_ms): queueing delay reported by the client ("FTDL")
      uint64_t delay_reports = 0;
      int delay_over_streak = 0;
      int delay_max_ms = 0;  // highest report since the last evaluation, to gate climbing
      std::chrono::steady_clock::time_point last_delay_step;
      int queue_ceiling_kbps = 0;  // rate the last step-down started from; climbs near it go slowly
      std::chrono::steady_clock::time_point last_cut;

      // Handoff copies scale with how the last handoff window went: 2 = 40/80 ms (+120 in the core
      // window), 1 = one copy at 60 ms, 0 = none. Judged by the worst queueing delay the client
      // reported inside the window.
      int dup_level = 2;
      bool window_open = false;
      int window_max_queue_ms = 0;
    };

    // Starlink reconfigures its links every 15 s at :12/:27/:42/:57 past the minute (UTC), and
    // the downlink drops what is in flight for 30-80 ms. Sending each packet a second time
    // DUP_DELAYS later, only around those moments, lets a copy land after the stall instead of
    // the client waiting a full round trip for a NACKed resend (~65 ms to a home host).
    // Two copies: hold times with a single 60 ms copy came out at 35-48 ms, i.e. most stalls are only
    // ~15-25 ms, so a 30 ms copy covers them quickly and the 60 ms one backs up longer stalls.
    // 2026-10-13 daytime stalls ran ~60-80 ms (holds 22-75 ms even with copies at 30/60), which
    // swallowed both copies; 40/80 still covers short stalls with the first copy.
    constexpr std::array<std::chrono::milliseconds, 2> DUP_DELAYS {std::chrono::milliseconds(40), std::chrono::milliseconds(80)};
    constexpr int64_t WINDOW_BEFORE_MS = 700;
    constexpr int64_t WINDOW_AFTER_MS = 700;
    constexpr int64_t SCHEDULE_WINDOW_MS = 1200;  // around the schedule: covers +-1 s shifts plus the stall

    // The fixed schedule above assumes an accurate host clock and that Starlink keeps reconfiguring
    // at :12/:27/:42/:57. Learn the real moment instead: the client NACKs right after each stall, so
    // NACK arrival times bunch up at one phase of the 15 s cycle. A decaying histogram of NACK phases
    // in 100 ms buckets finds that phase. Until it is confident we keep the fixed schedule.
    constexpr int64_t CYCLE_MS = 15000;
    constexpr int64_t BUCKET_MS = 100;
    constexpr int BUCKETS = CYCLE_MS / BUCKET_MS;

    std::mutex phase_mutex;
    std::array<double, BUCKETS> phase_histogram {};
    int64_t learned_phase_ms = -1;  // phase of NACK arrivals within the cycle, or -1 = not learned

    int64_t cycle_phase(int64_t epoch_ms) {
      return ((epoch_ms - 12000) % CYCLE_MS + CYCLE_MS) % CYCLE_MS;  // 0 = scheduled handoff
    }

    int64_t epoch_now_ms() {
      return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void learn_handoff_phase() {
      std::lock_guard lg {phase_mutex};
      // Halve old evidence every 45 s, so a shifted stall moment takes over within a few handoffs
      static auto last_learn = std::chrono::steady_clock::now();
      auto now = std::chrono::steady_clock::now();
      double age_s = std::chrono::duration<double>(now - last_learn).count();
      last_learn = now;
      double decay = std::pow(0.5, age_s / 45.0);
      for (auto &bucket : phase_histogram) {
        bucket *= decay;
      }
      phase_histogram[cycle_phase(epoch_now_ms()) / BUCKET_MS] += 1.0;

      // Sum each bucket with its neighbours, since a stall can straddle a bucket edge
      double total = 0, best = 0;
      int best_bucket = -1;
      for (int b = 0; b < BUCKETS; b++) {
        total += phase_histogram[b];
        double around = phase_histogram[(b + BUCKETS - 1) % BUCKETS] + phase_histogram[b] + phase_histogram[(b + 1) % BUCKETS];
        if (around > best) {
          best = around;
          best_bucket = b;
        }
      }

      // Off-schedule NACKs (random loss) spread over the cycle; a handoff peak only needs to stand out.
      int64_t learned = (best >= 3.0 && best >= 0.5 * total) ? best_bucket * BUCKET_MS + BUCKET_MS / 2 : -1;

      // Once a minute, say what we see, so a missed window can be diagnosed from the info log
      static auto last_report = std::chrono::steady_clock::now();
      if (std::chrono::steady_clock::now() - last_report > std::chrono::minutes(1)) {
        last_report = std::chrono::steady_clock::now();
        BOOST_LOG(info) << "FrogtaleTV NACK: phase peak "sv << best_bucket * BUCKET_MS + BUCKET_MS / 2 << " ms holds "sv
                        << (int) (100 * best / std::max(total, 1e-9)) << "% of NACKs (weight "sv << best << "), using "sv
                        << (learned >= 0 ? learned : 0) << " ms"sv << (learned >= 0 ? "" : " (fixed schedule)");
      }
      if ((learned < 0) != (learned_phase_ms < 0) ||
          (learned >= 0 && std::abs(learned - learned_phase_ms) > 200 && std::abs(learned - learned_phase_ms) < CYCLE_MS - 200)) {
        if (learned >= 0) {
          BOOST_LOG(info) << "FrogtaleTV NACK: handoff stalls learned at "sv << learned << " ms into the 15 s cycle (schedule says 0)"sv;
        } else {
          BOOST_LOG(info) << "FrogtaleTV NACK: handoff phase no longer clear, using the fixed schedule"sv;
        }
      }
      learned_phase_ms = learned;
    }

    bool in_handoff_window() {
      auto phase = cycle_phase(epoch_now_ms());
      int64_t center;
      {
        std::lock_guard lg {phase_mutex};
        // NACKs arrive just after a stall ends, so a learned phase sits slightly late; keep the
        // window wide enough before it to cover the stall itself.
        // Starlink's stall moment moves: on 2026-10-13 the Deck's NTP clock saw -0.49 s, then +0.03 s,
        // then -0.81 s, each steady for many minutes. Follow the learned phase (now fed by bursts
        // only); without one, use the schedule with a wider window.
        center = learned_phase_ms < 0 ? 0 : learned_phase_ms;
        // Every shift seen so far stayed within +-1 s of the schedule. While the learned phase is in
        // that range, cover the whole range, so a shift needs no relearning (a 1-minute rough patch
        // at 12:13 on 2026-10-13 was the window narrowed on the old phase).
        auto off_schedule = std::min(center, CYCLE_MS - center);
        if (learned_phase_ms < 0 || off_schedule <= 1000) {
          return phase >= CYCLE_MS - SCHEDULE_WINDOW_MS || phase <= SCHEDULE_WINDOW_MS;
        }
      }
      auto d = ((phase - center) % CYCLE_MS + CYCLE_MS) % CYCLE_MS;
      return d >= CYCLE_MS - WINDOW_BEFORE_MS || d <= WINDOW_AFTER_MS;
    }

    // Close to a confidently learned stall moment: worth a third, later copy. Some handoff holds on
    // 2026-10-13 still took 60-91 ms, i.e. stalls outlasted the 80 ms copy.
    bool in_core_window() {
      std::lock_guard lg {phase_mutex};
      if (learned_phase_ms < 0) {
        return false;
      }
      auto d = ((cycle_phase(epoch_now_ms()) - learned_phase_ms) % CYCLE_MS + CYCLE_MS) % CYCLE_MS;
      return d >= CYCLE_MS - 500 || d <= 500;
    }

    std::mutex histories_mutex;
    std::map<udp::endpoint, std::shared_ptr<history_t>> histories;

    std::shared_ptr<history_t> find(const udp::endpoint &peer) {
      std::lock_guard lg {histories_mutex};
      auto it = histories.find(peer);
      return it == histories.end() ? nullptr : it->second;
    }

    std::shared_ptr<history_t> get_or_create(const udp::endpoint &peer) {
      std::lock_guard lg {histories_mutex};
      if (!histories.count(peer) && histories.size() >= 4) {
        // Each new session uses a new client port; drop stale histories (~6 MB each).
        for (auto &[endpoint, old] : histories) {
          BOOST_LOG(info) << "FrogtaleTV NACK: "sv << endpoint.address().to_string() << ':' << endpoint.port()
                          << " resent "sv << old->resent << ", unavailable "sv << old->unavailable
                          << ", duplicated "sv << old->duplicated;
        }
        histories.clear();
      }
      auto &history = histories[peer];
      if (!history) {
        history = std::make_shared<history_t>();
      }
      return history;
    }

    // Remember one shard exactly as it went on the wire (prefix + payload).
    void store(history_t &history, uint16_t seq, const char *prefix, std::size_t prefixsize, const char *data, std::size_t blocksize) {
      std::lock_guard lg {history.mutex};
      if (history.prefixsize != prefixsize || history.blocksize != blocksize) {
        history.prefixsize = prefixsize;
        history.blocksize = blocksize;
        history.packets.assign(HISTORY * (prefixsize + blocksize), 0);
        history.valid.fill(false);
      }
      auto slot = seq % HISTORY;
      auto *dst = &history.packets[slot * (prefixsize + blocksize)];
      if (prefixsize) {
        std::memcpy(dst, prefix, prefixsize);
      }
      std::memcpy(dst + prefixsize, data, blocksize);
      history.seqs[slot] = seq;
      history.valid[slot] = true;
      history.loss_counted[slot] = false;
      history.sent++;

      // No copies while adaptive bitrate has stepped down: then the link is congested (on 2026-10-13
      // a movie streamed on the same Starlink and loss stayed 13-42% even at 3.3 Mbps), and tripling
      // our own traffic in each window only adds to it.
      bool congested = config::stream.frogtale_adaptive_bitrate && history.base_kbps && history.current_kbps < history.base_kbps;
      if (history.nacking && !congested && history.dup_level > 0 && in_handoff_window()) {
        auto now = std::chrono::steady_clock::now();
        if (history.dup_level == 1) {
          history.duplicates.emplace_back(now + std::chrono::milliseconds(60), seq);
        } else {
          for (auto delay : DUP_DELAYS) {
            history.duplicates.emplace_back(now + delay, seq);
          }
          if (in_core_window()) {
            history.duplicates.emplace_back(now + std::chrono::milliseconds(120), seq);
          }
        }
      }
    }

    void send_slot(history_t &history, uint16_t seq) {
      auto slot = seq % HISTORY;
      if (!history.valid[slot] || history.seqs[slot] != seq) {
        return;
      }
      auto *src = &history.packets[slot * (history.prefixsize + history.blocksize)];
      auto send_info = platf::send_info_t {
        history.prefixsize ? src : nullptr,
        history.prefixsize,
        src + history.prefixsize,
        history.blocksize,
        history.native_socket,
        history.address,
        history.port,
        history.local_address,
      };
      platf::send(send_info);
    }

    void set_bitrate(history_t &history, int target, const char *reason, double value) {
      if (std::abs(target - history.current_kbps) * 20 >= history.current_kbps) {
        history.bitrate_events->raise(target);
        BOOST_LOG(info) << "FrogtaleTV ABR: "sv << reason << ' ' << value << " -> "sv << target << " kbps (base "sv << history.base_kbps << ")"sv;
        history.current_kbps = target;
      }
    }

    // GeForce Now steps its bitrate down on loss (bwe.packetLossHighThresholdx100 100 = 1%,
    // packetLossLowThresholdx100 20 = 0.2%, lossyFrameStepDownRatio 50). Handoff windows are excluded:
    // their loss is expected and the copies cover it. Runs once a second per client.
    void adapt_bitrate(history_t &history, std::chrono::steady_clock::time_point now) {
      if (!config::stream.frogtale_adaptive_bitrate || !history.nacking || !history.bitrate_events || !history.base_kbps) {
        return;
      }
      if (now - history.last_eval < std::chrono::seconds(1)) {
        return;
      }
      auto sent = history.sent - history.last_sent;
      auto nacked = history.nacked_off_window - history.last_nacked;
      history.last_eval = now;
      history.last_sent = history.sent;
      history.last_nacked = history.nacked_off_window;
      if (sent < 100) {
        return;  // not streaming, or nothing changing on screen
      }

      double loss = (double) nacked / (double) sent;

      // Rain loses packets here and there rather than whole frames, which FEC repairs on the
      // client with no round trip. GeForce Now raises FEC during lossy periods
      // (bwe.fecLimitForBitrateIncrease 40); the bitrate usually steps down at the same time, so
      // the total stays similar.
      double loss_all = (double) (history.nacked_all_off_window - history.last_nacked_all) / (double) sent;
      history.last_nacked_all = history.nacked_all_off_window;
      int fec = loss_all > 0.04 ? 60 : loss_all > 0.01 ? 40 : 0;
      if (fec > history.fec_boost) {
        history.fec_boost = fec;
        history.fec_clean_seconds = 0;
        BOOST_LOG(info) << "FrogtaleTV FEC: loss "sv << (int) (loss_all * 1000) / 10.0 << "% -> "sv << fec << "%"sv;
      } else if (history.fec_boost && loss_all < 0.003) {
        if (++history.fec_clean_seconds >= 8) {
          history.fec_boost = history.fec_boost > 40 ? 40 : 0;
          history.fec_clean_seconds = 0;
          BOOST_LOG(info) << "FrogtaleTV FEC: clean -> "sv << (history.fec_boost ? history.fec_boost : config::stream.fec_percentage) << "%"sv;
        }
      } else {
        history.fec_clean_seconds = 0;
      }
      int delay_max_ms = history.delay_max_ms;
      history.delay_max_ms = 0;
      int target = history.current_kbps;
      if (loss <= 0.01) {
        history.mild_loss_seconds = 0;
      }
      // A Starlink storm on 2026-10-13 12:37 lost 12-42% of packets for ~30 s; at the old 50% floor
      // (6.7 Mbps) that still stuttered constantly. GeForce Now's floor is 1 Mbps
      // (minimumBitrateKbps 1000). Step hard on heavy loss and allow down to a quarter.
      // A fade (rain, an obstruction, a stall outside the schedule) loses nearly everything for
      // ~1 s and then the link is fine again; a lower bitrate doesn't make it fade less. On the
      // evening of 2026-10-15 (heavy rain) each fade cut 13.4 -> 1.7 Mbps within 2 s and took 15-30 s
      // to climb back, every 1-3 minutes, while GeForce Now on the same link held its rate. Like it,
      // react to loss that persists: one lossy second only stops the climb (FEC is already boosted
      // above); 2 s over 10% cuts 40%, 3 s over 3% (or 1-3% for 3 s) cuts 15%; at most one cut per
      // 2 s from any signal. Loss alone goes no lower than a third of the base unless it lasts 5 s
      // (the 2026-10-13 12:37 storm lost 12-42% for ~30 s and did need the floor).
      history.lossy_seconds = loss > 0.03 ? history.lossy_seconds + 1 : 0;
      bool can_cut = now - history.last_cut >= std::chrono::seconds(2);
      int loss_floor = history.lossy_seconds >= 5 ? history.base_kbps / 8 : history.base_kbps / 3;
      if (loss > 0.10 && history.lossy_seconds >= 2) {
        if (can_cut) {
          target = std::max(std::min(loss_floor, history.current_kbps), history.current_kbps * 6 / 10);
          history.last_cut = now;
        }
        history.clean_seconds = 0;
      } else if (history.lossy_seconds >= 3 || (loss > 0.01 && ++history.mild_loss_seconds >= 3)) {
        // 1-3% for a single second is a Starlink blip that the FEC boost above already repairs;
        // cutting for it made the picture go soft for 10-15 s at a time (2026-10-15 11:26-11:29).
        if (can_cut) {
          target = std::max(std::min(loss_floor, history.current_kbps), history.current_kbps * 85 / 100);
          history.mild_loss_seconds = 0;
          // Sustained loss is a capacity problem: climb back slowly near here (see below)
          history.queue_ceiling_kbps = history.current_kbps;
          history.last_cut = now;
        }
        history.clean_seconds = 0;
      } else if (loss > 0.01) {
        history.clean_seconds = 0;
      } else if (loss < 0.002 && (!history.delay_reports || !config::stream.frogtale_delay_ms || delay_max_ms < config::stream.frogtale_delay_ms)) {
        // 8 clean seconds per step (was 5): the climb bounced down and up 120 times in one session.
        // With delay reports, a second only counts as clean if the queue also stayed under half the
        // threshold, so the climb stops where the link starts queueing instead of where it drops.
        // GeForce Now on 2026-10-13 (movie on the same Starlink): its bitrate sat at ~1.7 Mbps for
        // minutes, then climbed back to 12 Mbps within seconds, with RTD flat at 35-45 ms. With delay
        // reports confirming an empty queue, climb like that (+20% every 4 s); on loss alone, keep
        // the cautious 8 s / +10%.
        // 2026-10-15 14:18: after a real congestion cut to the floor, the climb crept 1.7 -> 3.9 Mbps
        // in 17 s. Clean was gated on the queue staying under half the threshold (15 ms), but
        // Starlink's idle reading is 15-16 ms, so most seconds didn't count. Gate on the threshold
        // itself, and climb +30% every 2 s on a confirmed-clear link (floor to full in ~16 s).
        // 2026-10-15 15:55-15:58: a delay step 13.4 -> 11.4 Mbps was undone 2-4 s later, twice,
        // while the link kept queueing 60-150 ms, and it ended in a 350 ms freeze. Like WebRTC's
        // link-capacity estimate: within 80% of the rate where the queue last built, climb +5%
        // per 6 clean seconds; far below it, the fast climb above still applies, up to 80% of it.
        // The ceiling expires 60 s after the last delay step (Starlink congestion passes), and
        // 10% past it the climb is fast again: the link has shown it can take more.
        bool queue_known_empty = history.delay_reports && config::stream.frogtale_delay_ms;
        if (history.queue_ceiling_kbps && now - history.last_cut > std::chrono::seconds(60)) {
          history.queue_ceiling_kbps = 0;
        }
        bool near_ceiling = history.queue_ceiling_kbps && history.current_kbps * 10 >= history.queue_ceiling_kbps * 8 &&
                            history.current_kbps * 10 < history.queue_ceiling_kbps * 11;
        int need = near_ceiling ? 6 : queue_known_empty ? 2 : 8;
        if (++history.clean_seconds >= need && history.current_kbps < history.base_kbps) {
          int step = near_ceiling ? history.current_kbps / 20 : queue_known_empty ? history.current_kbps * 3 / 10 : history.current_kbps / 10;
          target = std::min(history.base_kbps, std::max(history.current_kbps + step, history.current_kbps + 300));
          if (!near_ceiling && history.queue_ceiling_kbps && history.current_kbps < history.queue_ceiling_kbps) {
            target = std::min(target, std::max(history.current_kbps + 300, history.queue_ceiling_kbps * 8 / 10));
          }
          history.clean_seconds = 0;
        }
      } else {
        history.clean_seconds = 0;
      }

      set_bitrate(history, target, "loss %", (int) (loss * 1000) / 10.0);
    }

    // GeForce Now (WebRTC) backs off as soon as one-way delay climbs, i.e. a queue is building
    // somewhere on the path, instead of waiting for that queue to overflow. On 2026-10-13 a movie
    // on the same Starlink pushed loss to 13-42% before the loss-based step-down could react.
    // The client reports the median queueing delay over each 250 ms ("FTDL"). Two reports in a
    // row over frogtale_delay_ms step down 15% (WebRTC's 0.85), or 40% when the queue is over
    // 4x that; at most one step per second so the encoder change can show. Reports inside
    // handoff windows are ignored: a satellite switch changes the path delay itself.
    void handle_delay(const udp::endpoint &peer, const char *payload, std::size_t bytes) {
      auto history = find(peer);
      if (!history || bytes < 4) {
        return;
      }
      uint16_t queue_ms;
      std::memcpy(&queue_ms, payload, sizeof(queue_ms));
      queue_ms = boost::endian::little_to_native(queue_ms);

      bool off_window = !in_handoff_window();
      auto now = std::chrono::steady_clock::now();

      std::lock_guard lg {history->mutex};
      history->delay_reports++;
      if (!off_window) {
        history->delay_over_streak = 0;
        history->window_open = true;
        history->window_max_queue_ms = std::max<int>(history->window_max_queue_ms, queue_ms);
        return;
      }
      if (history->window_open) {
        // A handoff window just ended. On a calm link the copies make handoffs nearly invisible
        // (median pause 64 -> 9 ms, 2026-10-13). On 2026-10-15 15:55-16:11 the link was congested
        // and nearly every 60-200 ms queue reading fell inside a window, i.e. 3-4x our traffic for
        // 2.4 s of every 15 was adding to the queue it was meant to beat. Step down a level after a
        // window that queued 80 ms or more, back up after one under 40 ms.
        history->window_open = false;
        int level = history->dup_level;
        if (history->window_max_queue_ms >= 80 && level > 0) {
          level--;
        } else if (history->window_max_queue_ms < 40 && level < 2) {
          level++;
        }
        if (level != history->dup_level) {
          BOOST_LOG(info) << "FrogtaleTV DUP: window queue "sv << history->window_max_queue_ms << " ms -> copies level "sv << level;
          history->dup_level = level;
        }
        history->window_max_queue_ms = 0;
      }
      history->delay_max_ms = std::max<int>(history->delay_max_ms, queue_ms);

      int threshold = config::stream.frogtale_delay_ms;
      if (!config::stream.frogtale_adaptive_bitrate || !threshold || !history->bitrate_events || !history->base_kbps) {
        return;
      }
      if (queue_ms < threshold) {
        history->delay_over_streak = 0;
        return;
      }
      if (++history->delay_over_streak < 2 || now - history->last_delay_step < std::chrono::seconds(1)) {
        return;
      }
      // Just after a fade the backlog drains through the link and reads as a 100-200 ms queue;
      // 18:58:28 and 18:59:28 on 2026-10-15 cut for that on top of the loss cut in the same second.
      if (now - history->last_cut < std::chrono::seconds(2)) {
        return;
      }
      history->delay_over_streak = 0;
      history->last_delay_step = now;
      history->clean_seconds = 0;
      history->queue_ceiling_kbps = history->current_kbps;
      history->last_cut = now;
      int target = queue_ms >= threshold * 4 ? history->current_kbps * 6 / 10 : history->current_kbps * 85 / 100;
      set_bitrate(*history, std::max(history->base_kbps / 8, target), "queue ms", queue_ms);
    }

    // Sends due duplicates for every client. One thread for the process, started on first use.
    void duplicate_thread() {
      platf::adjust_thread_priority(platf::thread_priority_e::high);
      while (true) {
        std::this_thread::sleep_for(1ms);
        std::vector<std::shared_ptr<history_t>> all;
        {
          std::lock_guard lg {histories_mutex};
          for (auto &[endpoint, history] : histories) {
            all.push_back(history);
          }
        }
        auto now = std::chrono::steady_clock::now();
        for (auto &history : all) {
          std::lock_guard lg {history->mutex};
          adapt_bitrate(*history, now);

          auto &queue = history->duplicates;
          for (auto it = queue.begin(); it != queue.end();) {
            if (it->first <= now) {
              send_slot(*history, it->second);
              history->duplicated++;
              it = queue.erase(it);
            } else {
              ++it;
            }
          }
        }
      }
    }

    void ensure_duplicate_thread() {
      static std::once_flag once;
      std::call_once(once, []() {
        std::thread {duplicate_thread}.detach();
      });
    }

    // Payload after the "FTNK" magic: uint16 count, then count x (uint16 first, uint16 length), little endian.
    void handle(const udp::endpoint &peer, const char *payload, std::size_t bytes) {
      auto history = find(peer);
      if (!history || bytes < 2) {
        return;
      }

      uint16_t count;
      std::memcpy(&count, payload, sizeof(count));
      count = std::min<uint16_t>(boost::endian::little_to_native(count), MAX_RANGES);
      if (bytes < 2 + count * 4u) {
        return;
      }

      ensure_duplicate_thread();

      // Learn the handoff phase only from bursts. Every NACK made the histogram noise, but a
      // handoff stall loses dozens of packets in a row, which random loss almost never does.
      {
        uint16_t longest = 0;
        for (uint16_t r = 0; r < count; r++) {
          uint16_t length;
          std::memcpy(&length, payload + 4 + r * 4, sizeof(length));
          longest = std::max<uint16_t>(longest, boost::endian::little_to_native(length));
        }
        if (longest >= LEARN_BURST_PACKETS) {
          learn_handoff_phase();
        }
      }

      bool off_window = !in_handoff_window();

      std::lock_guard lg {history->mutex};
      history->nacking = true;
      for (uint16_t r = 0; r < count; r++) {
        uint16_t first, length;
        std::memcpy(&first, payload + 2 + r * 4, sizeof(first));
        std::memcpy(&length, payload + 4 + r * 4, sizeof(length));
        first = boost::endian::little_to_native(first);
        length = std::min<uint16_t>(boost::endian::little_to_native(length), HISTORY / 2);
        // Only bursts count: scattered single losses (~1-2% on Starlink all the time) are repaired
        // invisibly by FEC, and counting them pinned the bitrate at its floor on 2026-10-13.
        // Each packet counts once: the client re-NACKs what is still missing twice, so counting
        // every range read a 1 s rain fade as 120-215% "loss" (2026-10-15 evening) and slammed
        // the bitrate to its floor. Packets we no longer hold (or never sent) don't count either.
        for (uint16_t i = 0; i < length; i++) {
          uint16_t seq = first + i;
          auto slot = seq % HISTORY;
          if (!history->valid[slot] || history->seqs[slot] != seq) {
            history->unavailable++;
            continue;
          }
          if (off_window && !history->loss_counted[slot]) {
            history->loss_counted[slot] = true;
            history->nacked_all_off_window++;
            if (length >= BURST_PACKETS) {
              history->nacked_off_window++;
            }
          }

          send_slot(*history, seq);
          history->resent++;
        }
      }
      BOOST_LOG(debug) << "FrogtaleTV NACK: "sv << count << " ranges, total resent "sv << history->resent
                       << ", duplicated "sv << history->duplicated;
    }
  }  // namespace nack

  using av_session_id_t = std::variant<asio::ip::address, std::string>;  // IP address or SS-Ping-Payload from RTSP handshake
  using message_queue_t = std::shared_ptr<safe::queue_t<std::pair<udp::endpoint, std::string>>>;
  using message_queue_queue_t = std::shared_ptr<safe::queue_t<std::tuple<socket_e, av_session_id_t, message_queue_t>>>;

  // return bytes written on success
  // return -1 on error
  static inline int encode_audio(bool encrypted, const audio::buffer_t &plaintext, uint8_t *destination, crypto::aes_t &iv, crypto::cipher::cbc_t &cbc) {
    // If encryption isn't enabled
    if (!encrypted) {
      std::copy(std::begin(plaintext), std::end(plaintext), destination);
      return plaintext.size();
    }

    return cbc.encrypt(std::string_view {(char *) std::begin(plaintext), plaintext.size()}, destination, &iv);
  }

  static inline void while_starting_do_nothing(std::atomic<session::state_e> &state) {
    while (state.load(std::memory_order_acquire) == session::state_e::STARTING) {
      std::this_thread::sleep_for(1ms);
    }
  }

  class control_server_t {
  public:
    int bind(net::af_e address_family, std::uint16_t port) {
      _host = net::host_create(address_family, _addr, port);

      return !(bool) _host;
    }

    // Get session associated with address.
    // If none are found, try to find a session not yet claimed. (It will be marked by a port of value 0
    // If none of those are found, return nullptr
    session_t *get_session(const net::peer_t peer, uint32_t connect_data);

    // Circular dependency:
    //   iterate refers to session
    //   session refers to broadcast_ctx_t
    //   broadcast_ctx_t refers to control_server_t
    // Therefore, iterate is implemented further down the source file
    void iterate(std::chrono::milliseconds timeout);

    /**
     * @brief Call the handler for a given control stream message.
     * @param type The message type.
     * @param session The session the message was received on.
     * @param payload The payload of the message.
     * @param reinjected `true` if this message is being reprocessed after decryption.
     */
    void call(std::uint16_t type, session_t *session, const std::string_view &payload, bool reinjected);

    void map(uint16_t type, std::function<void(session_t *, const std::string_view &)> cb) {
      _map_type_cb.emplace(type, std::move(cb));
    }

    int send(const std::string_view &payload, net::peer_t peer) {
      auto packet = enet_packet_create(payload.data(), payload.size(), ENET_PACKET_FLAG_RELIABLE);
      if (enet_peer_send(peer, 0, packet)) {
        enet_packet_destroy(packet);

        return -1;
      }

      return 0;
    }

    void flush() {
      enet_host_flush(_host.get());
    }

    // Callbacks
    std::unordered_map<std::uint16_t, std::function<void(session_t *, const std::string_view &)>> _map_type_cb;

    // All active sessions (including those still waiting for a peer to connect)
    sync_util::sync_t<std::vector<session_t *>> _sessions;

    // ENet peer to session mapping for sessions with a peer connected
    sync_util::sync_t<std::map<net::peer_t, session_t *>> _peer_to_session;

    ENetAddress _addr;
    net::host_t _host;
  };

  struct broadcast_ctx_t {
    message_queue_queue_t message_queue_queue;

    std::thread recv_thread;
    std::thread video_thread;
    std::thread audio_thread;
    std::thread control_thread;

    asio::io_context io_context;

    udp::socket video_sock {io_context};
    udp::socket audio_sock {io_context};

    control_server_t control_server;
  };

  struct session_t {
    config_t config;

    safe::mail_t mail;

    std::shared_ptr<input::input_t> input;

    std::thread audioThread;
    std::thread videoThread;

    std::chrono::steady_clock::time_point pingTimeout;

    safe::shared_t<broadcast_ctx_t>::ptr_t broadcast_ref;

    boost::asio::ip::address localAddress;

    struct {
      std::string ping_payload;

      int lowseq;
      udp::endpoint peer;

      std::optional<crypto::cipher::gcm_t> cipher;
      std::uint64_t gcm_iv_counter;

      safe::mail_raw_t::event_t<bool> idr_events;
      safe::mail_raw_t::event_t<std::pair<int64_t, int64_t>> invalidate_ref_frames_events;
      safe::mail_raw_t::event_t<int> frogtale_bitrate_events;

      std::unique_ptr<platf::deinit_t> qos;
    } video;

    struct {
      crypto::cipher::cbc_t cipher;
      std::string ping_payload;

      std::uint16_t sequenceNumber;
      // avRiKeyId == util::endian::big(First (sizeof(avRiKeyId)) bytes of launch_session->iv)
      std::uint32_t avRiKeyId;
      std::uint32_t timestamp;
      udp::endpoint peer;

      util::buffer_t<char> shards;
      util::buffer_t<uint8_t *> shards_p;

      audio_fec_packet_t fec_packet;
      std::unique_ptr<platf::deinit_t> qos;
    } audio;

    struct {
      crypto::cipher::gcm_t cipher;
      crypto::aes_t legacy_input_enc_iv;  // Only used when the client doesn't support full control stream encryption
      crypto::aes_t incoming_iv;
      crypto::aes_t outgoing_iv;

      std::uint32_t connect_data;  // Used for new clients with ML_FF_SESSION_ID_V1
      std::string expected_peer_address;  // Only used for legacy clients without ML_FF_SESSION_ID_V1

      net::peer_t peer;
      std::uint32_t seq;

      platf::feedback_queue_t feedback_queue;
      safe::mail_raw_t::event_t<video::hdr_info_t> hdr_queue;
    } control;

    std::uint32_t launch_session_id;
    std::string device_name;
    std::string device_uuid;
    crypto::PERM permission;

    std::list<crypto::command_entry_t> do_cmds;
    std::list<crypto::command_entry_t> undo_cmds;

    safe::mail_raw_t::event_t<bool> shutdown_event;
    safe::signal_t controlEnd;

    std::atomic<session::state_e> state;
  };

  /**
   * First part of cipher must be struct of type control_encrypted_t
   *
   * returns empty string_view on failure
   * returns string_view pointing to payload data
   */
  template<std::size_t max_payload_size>
  static inline std::string_view encode_control(session_t *session, const std::string_view &plaintext, std::array<std::uint8_t, max_payload_size> &tagged_cipher) {
    static_assert(
      max_payload_size >= sizeof(control_encrypted_t) + sizeof(crypto::cipher::tag_size),
      "max_payload_size >= sizeof(control_encrypted_t) + sizeof(crypto::cipher::tag_size)"
    );

    if (session->config.controlProtocolType != 13) {
      return plaintext;
    }

    auto seq = session->control.seq++;

    auto &iv = session->control.outgoing_iv;
    if (session->config.encryptionFlagsEnabled & SS_ENC_CONTROL_V2) {
      // We use the deterministic IV construction algorithm specified in NIST SP 800-38D
      // Section 8.2.1. The sequence number is our "invocation" field and the 'CH' in the
      // high bytes is the "fixed" field. Because each client provides their own unique
      // key, our values in the fixed field need only uniquely identify each independent
      // use of the client's key with AES-GCM in our code.
      //
      // The sequence number is 32 bits long which allows for 2^32 control stream messages
      // to be sent to each client before the IV repeats.
      iv.resize(12);
      std::copy_n((uint8_t *) &seq, sizeof(seq), std::begin(iv));
      iv[10] = 'H';  // Host originated
      iv[11] = 'C';  // Control stream
    } else {
      // Nvidia's old style encryption uses a 16-byte IV
      iv.resize(16);

      iv[0] = (std::uint8_t) seq;
    }

    auto packet = (control_encrypted_p) tagged_cipher.data();

    auto bytes = session->control.cipher.encrypt(plaintext, packet->payload(), &iv);
    if (bytes <= 0) {
      BOOST_LOG(error) << "Couldn't encrypt control data"sv;
      return {};
    }

    std::uint16_t packet_length = bytes + crypto::cipher::tag_size + sizeof(control_encrypted_t::seq);

    packet->encryptedHeaderType = util::endian::little(0x0001);
    packet->length = util::endian::little(packet_length);
    packet->seq = util::endian::little(seq);

    return std::string_view {(char *) tagged_cipher.data(), packet_length + sizeof(control_encrypted_t) - sizeof(control_encrypted_t::seq)};
  }

  int start_broadcast(broadcast_ctx_t &ctx);
  void end_broadcast(broadcast_ctx_t &ctx);

  static auto broadcast = safe::make_shared<broadcast_ctx_t>(start_broadcast, end_broadcast);

  session_t *control_server_t::get_session(const net::peer_t peer, uint32_t connect_data) {
    {
      // Fast path - look up existing session by peer
      auto lg = _peer_to_session.lock();
      auto it = _peer_to_session->find(peer);
      if (it != _peer_to_session->end()) {
        return it->second;
      }
    }

    // Slow path - process new session
    TUPLE_2D(peer_port, peer_addr, platf::from_sockaddr_ex((sockaddr *) &peer->address.address));
    auto lg = _sessions.lock();
    for (auto pos = std::begin(*_sessions); pos != std::end(*_sessions); ++pos) {
      auto session_p = *pos;

      // Skip sessions that are already established
      if (session_p->control.peer) {
        continue;
      }

      // Identify the connection by the unique connect data if the client supports it.
      // Only fall back to IP address matching for clients without session ID support.
      if (session_p->config.mlFeatureFlags & ML_FF_SESSION_ID_V1) {
        if (session_p->control.connect_data != connect_data) {
          continue;
        } else {
          BOOST_LOG(debug) << "Initialized new control stream session by connect data match [v2]"sv;
        }
      } else {
        if (session_p->control.expected_peer_address != peer_addr) {
          continue;
        } else {
          BOOST_LOG(debug) << "Initialized new control stream session by IP address match [v1]"sv;
        }
      }

      // Once the control stream connection is established, RTSP session state can be torn down
      rtsp_stream::launch_session_clear(session_p->launch_session_id);

      session_p->control.peer = peer;

      // Use the local address from the control connection as the source address
      // for other communications to the client. This is necessary to ensure
      // proper routing on multi-homed hosts.
      auto local_address = platf::from_sockaddr((sockaddr *) &peer->localAddress.address);
      session_p->localAddress = boost::asio::ip::make_address(local_address);

      BOOST_LOG(debug) << "Control local address ["sv << local_address << ']';
      BOOST_LOG(debug) << "Control peer address ["sv << peer_addr << ':' << peer_port << ']';

      // Insert this into the map for O(1) lookups in the future
      auto ptslg = _peer_to_session.lock();
      _peer_to_session->emplace(peer, session_p);
      return session_p;
    }

    return nullptr;
  }

  /**
   * @brief Call the handler for a given control stream message.
   * @param type The message type.
   * @param session The session the message was received on.
   * @param payload The payload of the message.
   * @param reinjected `true` if this message is being reprocessed after decryption.
   */
  void control_server_t::call(std::uint16_t type, session_t *session, const std::string_view &payload, bool reinjected) {
    // If we are using the encrypted control stream protocol, drop any messages that come off the wire unencrypted
    if (session->config.controlProtocolType == 13 && !reinjected && type != packetTypes[IDX_ENCRYPTED]) {
      BOOST_LOG(error) << "Dropping unencrypted message on encrypted control stream: "sv << util::hex(type).to_string_view();
      return;
    }

    auto cb = _map_type_cb.find(type);
    if (cb == std::end(_map_type_cb)) {
      BOOST_LOG(debug)
        << "type [Unknown] { "sv << util::hex(type).to_string_view() << " }"sv << std::endl
        << "---data---"sv << std::endl
        << util::hex_vec(payload) << std::endl
        << "---end data---"sv;
    } else {
      cb->second(session, payload);
    }
  }

  void control_server_t::iterate(std::chrono::milliseconds timeout) {
    ENetEvent event;
    auto res = enet_host_service(_host.get(), &event, timeout.count());

    if (res > 0) {
      auto session = get_session(event.peer, event.data);
      if (!session) {
        BOOST_LOG(warning) << "Rejected connection from ["sv << platf::from_sockaddr((sockaddr *) &event.peer->address.address) << "]: it's not properly set up"sv;
        enet_peer_disconnect_now(event.peer, 0);

        return;
      }

      session->pingTimeout = std::chrono::steady_clock::now() + config::stream.ping_timeout;

      switch (event.type) {
        case ENET_EVENT_TYPE_RECEIVE:
          {
            net::packet_t packet {event.packet};

            auto type = *(std::uint16_t *) packet->data;
            std::string_view payload {(char *) packet->data + sizeof(type), packet->dataLength - sizeof(type)};

            call(type, session, payload, false);
          }
          break;
        case ENET_EVENT_TYPE_CONNECT:
          BOOST_LOG(info) << "CLIENT CONNECTED"sv;
          break;
        case ENET_EVENT_TYPE_DISCONNECT:
          BOOST_LOG(info) << "CLIENT DISCONNECTED"sv;
          // No more clients to send video data to ^_^
          if (session->state == session::state_e::RUNNING) {
            session::stop(*session);
          }
          break;
        case ENET_EVENT_TYPE_NONE:
          break;
      }
    }
  }

  namespace fec {
    using rs_t = util::safe_ptr<reed_solomon, [](reed_solomon *rs) {
      reed_solomon_release(rs);
    }>;

    struct fec_t {
      size_t data_shards;
      size_t nr_shards;
      size_t percentage;

      size_t blocksize;
      size_t prefixsize;
      util::buffer_t<char> shards;
      util::buffer_t<char> headers;
      util::buffer_t<uint8_t *> shards_p;

      std::vector<platf::buffer_descriptor_t> payload_buffers;

      char *data(size_t el) {
        return (char *) shards_p[el];
      }

      char *prefix(size_t el) {
        return prefixsize ? &headers[el * prefixsize] : nullptr;
      }

      size_t size() const {
        return nr_shards;
      }
    };

    static fec_t encode(const std::string_view &payload, size_t blocksize, size_t fecpercentage, size_t minparityshards, size_t prefixsize) {
      auto payload_size = payload.size();

      auto pad = payload_size % blocksize != 0;

      auto aligned_data_shards = payload_size / blocksize;
      auto data_shards = aligned_data_shards + (pad ? 1 : 0);
      auto parity_shards = (data_shards * fecpercentage + 99) / 100;

      // increase the FEC percentage for this frame if the parity shard minimum is not met
      if (parity_shards < minparityshards && fecpercentage != 0) {
        parity_shards = minparityshards;
        fecpercentage = (100 * parity_shards) / data_shards;

        BOOST_LOG(verbose) << "Increasing FEC percentage to "sv << fecpercentage << " to meet parity shard minimum"sv << std::endl;
      }

      auto nr_shards = data_shards + parity_shards;

      // If we need to store a zero-padded data shard, allocate that first to
      // to keep the shards in order and reduce buffer fragmentation
      auto parity_shard_offset = pad ? 1 : 0;
      util::buffer_t<char> shards {(parity_shard_offset + parity_shards) * blocksize};
      util::buffer_t<uint8_t *> shards_p {nr_shards};
      std::vector<platf::buffer_descriptor_t> payload_buffers;
      payload_buffers.reserve(2);

      // Point into the payload buffer for all except the final padded data shard
      auto next = std::begin(payload);
      for (auto x = 0; x < aligned_data_shards; ++x) {
        shards_p[x] = (uint8_t *) next;
        next += blocksize;
      }
      payload_buffers.emplace_back(std::begin(payload), aligned_data_shards * blocksize);

      // If the last data shard needs to be zero-padded, we must use the shards buffer
      if (pad) {
        shards_p[aligned_data_shards] = (uint8_t *) &shards[0];

        // GCC doesn't figure out that std::copy_n() can be replaced with memcpy() here
        // and ends up compiling a horribly slow element-by-element copy loop, so we
        // help it by using memcpy()/memset() directly.
        auto copy_len = std::min<size_t>(blocksize, std::end(payload) - next);
        std::memcpy(shards_p[aligned_data_shards], next, copy_len);
        if (copy_len < blocksize) {
          // Zero any additional space after the end of the payload
          std::memset(shards_p[aligned_data_shards] + copy_len, 0, blocksize - copy_len);
        }
      }

      // Add a payload buffer describing the shard buffer
      payload_buffers.emplace_back(std::begin(shards), shards.size());

      if (fecpercentage != 0) {
        // Point into our allocated buffer for the parity shards
        for (auto x = 0; x < parity_shards; ++x) {
          shards_p[data_shards + x] = (uint8_t *) &shards[(parity_shard_offset + x) * blocksize];
        }

        // packets = parity_shards + data_shards
        rs_t rs {reed_solomon_new(data_shards, parity_shards)};

        reed_solomon_encode(rs.get(), shards_p.begin(), nr_shards, blocksize);
      }

      return {
        data_shards,
        nr_shards,
        fecpercentage,
        blocksize,
        prefixsize,
        std::move(shards),
        util::buffer_t<char> {nr_shards * prefixsize},
        std::move(shards_p),
        std::move(payload_buffers),
      };
    }
  }  // namespace fec

  /**
   * @brief Combines two buffers and inserts new buffers at each slice boundary of the result.
   * @param insert_size The number of bytes to insert.
   * @param slice_size The number of bytes between insertions.
   * @param data1 The first data buffer.
   * @param data2 The second data buffer.
   */
  std::vector<uint8_t> concat_and_insert(uint64_t insert_size, uint64_t slice_size, const std::string_view &data1, const std::string_view &data2) {
    auto data_size = data1.size() + data2.size();
    auto pad = data_size % slice_size != 0;
    auto elements = data_size / slice_size + (pad ? 1 : 0);

    std::vector<uint8_t> result;
    result.resize(elements * insert_size + data_size);

    auto next = std::begin(data1);
    auto end = std::end(data1);
    for (auto x = 0; x < elements; ++x) {
      void *p = &result[x * (insert_size + slice_size)];

      // For the last iteration, only copy to the end of the data
      if (x == elements - 1) {
        slice_size = data_size - (x * slice_size);
      }

      // Test if this slice will extend into the next buffer
      if (next + slice_size > end) {
        // Copy the first portion from the first buffer
        auto copy_len = end - next;
        std::copy(next, end, (char *) p + insert_size);

        // Copy the remaining portion from the second buffer
        next = std::begin(data2);
        end = std::end(data2);
        std::copy(next, next + (slice_size - copy_len), (char *) p + copy_len + insert_size);
        next += slice_size - copy_len;
      } else {
        std::copy(next, next + slice_size, (char *) p + insert_size);
        next += slice_size;
      }
    }

    return result;
  }

  std::vector<uint8_t> replace(const std::string_view &original, const std::string_view &old, const std::string_view &_new) {
    std::vector<uint8_t> replaced;
    replaced.reserve(original.size() + _new.size() - old.size());

    auto begin = std::begin(original);
    auto end = std::end(original);
    auto next = std::search(begin, end, std::begin(old), std::end(old));

    std::copy(begin, next, std::back_inserter(replaced));
    if (next != end) {
      std::copy(std::begin(_new), std::end(_new), std::back_inserter(replaced));
      std::copy(next + old.size(), end, std::back_inserter(replaced));
    }

    return replaced;
  }

  /**
   * @brief Pass gamepad feedback data back to the client.
   * @param session The session object.
   * @param msg The message to pass.
   * @return 0 on success.
   */
  int send_feedback_msg(session_t *session, platf::gamepad_feedback_msg_t &msg) {
    if (!session->control.peer) {
      BOOST_LOG(warning) << "Couldn't send gamepad feedback data, still waiting for PING from Moonlight"sv;
      // Still waiting for PING from Moonlight
      return -1;
    }

    std::string payload;
    if (msg.type == platf::gamepad_feedback_e::rumble) {
      control_rumble_t plaintext;
      plaintext.header.type = packetTypes[IDX_RUMBLE_DATA];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.rumble;

      plaintext.useless = 0xC0FFEE;
      plaintext.id = util::endian::little(msg.id);
      plaintext.lowfreq = util::endian::little(data.lowfreq);
      plaintext.highfreq = util::endian::little(data.highfreq);

      BOOST_LOG(verbose) << "Rumble: "sv << msg.id << " :: "sv << util::hex(data.lowfreq).to_string_view() << " :: "sv << util::hex(data.highfreq).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::rumble_triggers) {
      control_rumble_triggers_t plaintext;
      plaintext.header.type = packetTypes[IDX_RUMBLE_TRIGGER_DATA];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.rumble_triggers;

      plaintext.id = util::endian::little(msg.id);
      plaintext.left = util::endian::little(data.left_trigger);
      plaintext.right = util::endian::little(data.right_trigger);

      BOOST_LOG(verbose) << "Rumble triggers: "sv << msg.id << " :: "sv << util::hex(data.left_trigger).to_string_view() << " :: "sv << util::hex(data.right_trigger).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::set_motion_event_state) {
      control_set_motion_event_t plaintext;
      plaintext.header.type = packetTypes[IDX_SET_MOTION_EVENT];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.motion_event_state;

      plaintext.id = util::endian::little(msg.id);
      plaintext.reportrate = util::endian::little(data.report_rate);
      plaintext.type = data.motion_type;

      BOOST_LOG(verbose) << "Motion event state: "sv << msg.id << " :: "sv << util::hex(data.report_rate).to_string_view() << " :: "sv << util::hex(data.motion_type).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::set_rgb_led) {
      control_set_rgb_led_t plaintext;
      plaintext.header.type = packetTypes[IDX_SET_RGB_LED];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      auto &data = msg.data.rgb_led;

      plaintext.id = util::endian::little(msg.id);
      plaintext.r = data.r;
      plaintext.g = data.g;
      plaintext.b = data.b;

      BOOST_LOG(verbose) << "RGB: "sv << msg.id << " :: "sv << util::hex(data.r).to_string_view() << util::hex(data.g).to_string_view() << util::hex(data.b).to_string_view();
      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else if (msg.type == platf::gamepad_feedback_e::set_adaptive_triggers) {
      control_adaptive_triggers_t plaintext;
      plaintext.header.type = packetTypes[IDX_SET_ADAPTIVE_TRIGGERS];
      plaintext.header.payloadLength = sizeof(plaintext) - sizeof(control_header_v2);

      plaintext.id = util::endian::little(msg.id);
      plaintext.event_flags = msg.data.adaptive_triggers.event_flags;
      plaintext.type_left = msg.data.adaptive_triggers.type_left;
      std::ranges::copy(msg.data.adaptive_triggers.left, plaintext.left);
      plaintext.type_right = msg.data.adaptive_triggers.type_right;
      std::ranges::copy(msg.data.adaptive_triggers.right, plaintext.right);

      std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
        encrypted_payload;

      payload = encode_control(session, util::view(plaintext), encrypted_payload);
    } else {
      BOOST_LOG(error) << "Unknown gamepad feedback message type"sv;
      return -1;
    }

    if (session->broadcast_ref->control_server.send(payload, session->control.peer)) {
      TUPLE_2D(port, addr, platf::from_sockaddr_ex((sockaddr *) &session->control.peer->address.address));
      BOOST_LOG(warning) << "Couldn't send gamepad feedback to ["sv << addr << ':' << port << ']';

      return -1;
    }

    return 0;
  }

  int send_hdr_mode(session_t *session, video::hdr_info_t hdr_info) {
    if (!session->control.peer) {
      BOOST_LOG(warning) << "Couldn't send HDR mode, still waiting for PING from Moonlight"sv;
      // Still waiting for PING from Moonlight
      return -1;
    }

    control_hdr_mode_t plaintext {};
    plaintext.header.type = packetTypes[IDX_HDR_MODE];
    plaintext.header.payloadLength = sizeof(control_hdr_mode_t) - sizeof(control_header_v2);

    plaintext.enabled = hdr_info->enabled;
    plaintext.metadata = hdr_info->metadata;

    std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
      encrypted_payload;

    auto payload = encode_control(session, util::view(plaintext), encrypted_payload);
    if (session->broadcast_ref->control_server.send(payload, session->control.peer)) {
      TUPLE_2D(port, addr, platf::from_sockaddr_ex((sockaddr *) &session->control.peer->address.address));
      BOOST_LOG(warning) << "Couldn't send HDR mode to ["sv << addr << ':' << port << ']';

      return -1;
    }

    BOOST_LOG(debug) << "Sent HDR mode: " << hdr_info->enabled;
    return 0;
  }

  void controlBroadcastThread(control_server_t *server) {
    server->map(packetTypes[IDX_PERIODIC_PING], [](session_t *session, const std::string_view &payload) {
      BOOST_LOG(verbose) << "type [IDX_PERIODIC_PING]"sv;
    });

    server->map(packetTypes[IDX_START_A], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_START_A]"sv;
    });

    server->map(packetTypes[IDX_START_B], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_START_B]"sv;
    });

    server->map(packetTypes[IDX_LOSS_STATS], [&](session_t *session, const std::string_view &payload) {
      int32_t *stats = (int32_t *) payload.data();
      auto count = stats[0];
      std::chrono::milliseconds t {stats[1]};

      auto lastGoodFrame = stats[3];

      BOOST_LOG(verbose)
        << "type [IDX_LOSS_STATS]"sv << std::endl
        << "---begin stats---" << std::endl
        << "loss count since last report [" << count << ']' << std::endl
        << "time in milli since last report [" << t.count() << ']' << std::endl
        << "last good frame [" << lastGoodFrame << ']' << std::endl
        << "---end stats---";
    });

    server->map(packetTypes[IDX_REQUEST_IDR_FRAME], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_REQUEST_IDR_FRAME]"sv;

      session->video.idr_events->raise(true);
    });

    server->map(packetTypes[IDX_INVALIDATE_REF_FRAMES], [&](session_t *session, const std::string_view &payload) {
      auto frames = (std::int64_t *) payload.data();
      auto firstFrame = frames[0];
      auto lastFrame = frames[1];

      BOOST_LOG(debug)
        << "type [IDX_INVALIDATE_REF_FRAMES]"sv << std::endl
        << "firstFrame [" << firstFrame << ']' << std::endl
        << "lastFrame [" << lastFrame << ']';

      session->video.invalidate_ref_frames_events->raise(std::make_pair(firstFrame, lastFrame));
    });

    server->map(packetTypes[IDX_INPUT_DATA], [&](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_INPUT_DATA]"sv;

      auto tagged_cipher_length = util::endian::big(*(int32_t *) payload.data());
      std::string_view tagged_cipher {payload.data() + sizeof(tagged_cipher_length), (size_t) tagged_cipher_length};

      std::vector<uint8_t> plaintext;

      auto &cipher = session->control.cipher;
      auto &iv = session->control.legacy_input_enc_iv;
      if (cipher.decrypt(tagged_cipher, plaintext, &iv)) {
        // something went wrong :(

        BOOST_LOG(error) << "Failed to verify tag"sv;

        session::stop(*session);
        return;
      }

      if (tagged_cipher_length >= 16 + iv.size()) {
        std::copy(payload.end() - 16, payload.end(), std::begin(iv));
      }

      input::passthrough(session->input, std::move(plaintext), session->permission);
    });

    server->map(packetTypes[IDX_EXEC_SERVER_CMD], [server](session_t *session, const std::string_view &payload) {
      BOOST_LOG(debug) << "type [IDX_EXEC_SERVER_CMD]"sv;

      if (!(session->permission & crypto::PERM::server_cmd)) {
        BOOST_LOG(debug) << "Permission Exec Server Cmd deined for [" << session->device_name << "]";
        return;
      }

      uint8_t cmdIndex = *(uint8_t*)payload.data();

      if (cmdIndex < config::sunshine.server_cmds.size()) {
        const auto& cmd = config::sunshine.server_cmds[cmdIndex];
        BOOST_LOG(info) << "Executing server command: " << cmd.cmd_name;

        auto exec_thread = std::thread([&cmd]{
          std::error_code ec;
          auto env = proc::proc.get_env();
          boost::filesystem::path working_dir = proc::find_working_directory(cmd.cmd_val, env);
          auto child = platf::run_command(cmd.elevated, true, cmd.cmd_val, working_dir, env, nullptr, ec, nullptr);

          if (ec) {
            BOOST_LOG(error) << "Failed to execute server command: " << ec.message();
          } else {
            child.detach();
          }
        });

        exec_thread.detach();
      } else {
        BOOST_LOG(error) << "Invalid server command index: " << (int)cmdIndex;
      }
    });

    server->map(packetTypes[IDX_SET_CLIPBOARD], [server](session_t *session, const std::string_view &payload) {
      BOOST_LOG(info) << "type [IDX_SET_CLIPBOARD]: "sv << payload << " size: " << payload.size();

      if (!(session->permission & crypto::PERM::clipboard_set)) {
        BOOST_LOG(debug) << "Permission Clipboard Set deined for [" << session->device_name << "]";
        return;
      }
    });

    server->map(packetTypes[IDX_FILE_TRANSFER_NONCE_REQUEST], [server](session_t *session, const std::string_view &payload) {
      BOOST_LOG(info) << "type [IDX_FILE_TRANSFER_NONCE_REQUEST]: "sv << payload << " size: " << payload.size();

      if (!(session->permission & crypto::PERM::file_upload)) {
        BOOST_LOG(debug) << "Permission File Upload deined for [" << session->device_name << "]";
        return;
      }
    });

    server->map(packetTypes[IDX_ENCRYPTED], [server](session_t *session, const std::string_view &payload) {
      BOOST_LOG(verbose) << "type [IDX_ENCRYPTED]"sv;

      auto header = (control_encrypted_p) (payload.data() - 2);

      auto length = util::endian::little(header->length);
      auto seq = util::endian::little(header->seq);

      if (length < (16 + 4 + 4)) {
        BOOST_LOG(warning) << "Control: Runt packet"sv;
        return;
      }

      auto tagged_cipher_length = length - 4;
      std::string_view tagged_cipher {(char *) header->payload(), (size_t) tagged_cipher_length};

      auto &cipher = session->control.cipher;
      auto &iv = session->control.incoming_iv;
      if (session->config.encryptionFlagsEnabled & SS_ENC_CONTROL_V2) {
        // We use the deterministic IV construction algorithm specified in NIST SP 800-38D
        // Section 8.2.1. The sequence number is our "invocation" field and the 'CC' in the
        // high bytes is the "fixed" field. Because each client provides their own unique
        // key, our values in the fixed field need only uniquely identify each independent
        // use of the client's key with AES-GCM in our code.
        //
        // The sequence number is 32 bits long which allows for 2^32 control stream messages
        // to be received from each client before the IV repeats.
        iv.resize(12);
        std::copy_n((uint8_t *) &seq, sizeof(seq), std::begin(iv));
        iv[10] = 'C';  // Client originated
        iv[11] = 'C';  // Control stream
      } else {
        // Nvidia's old style encryption uses a 16-byte IV
        iv.resize(16);

        iv[0] = (std::uint8_t) seq;
      }

      std::vector<uint8_t> plaintext;
      if (cipher.decrypt(tagged_cipher, plaintext, &iv)) {
        // something went wrong :(

        BOOST_LOG(error) << "Failed to verify tag"sv;

        session::stop(*session);
        return;
      }

      auto type = *(std::uint16_t *) plaintext.data();
      std::string_view next_payload {(char *) plaintext.data() + 4, plaintext.size() - 4};

      if (type == packetTypes[IDX_ENCRYPTED]) {
        BOOST_LOG(error) << "Bad packet type [IDX_ENCRYPTED] found"sv;
        session::stop(*session);
        return;
      }

      // IDX_INPUT_DATA callback will attempt to decrypt unencrypted data, therefore we need pass it directly
      if (type == packetTypes[IDX_INPUT_DATA]) {
        plaintext.erase(std::begin(plaintext), std::begin(plaintext) + 4);
        input::passthrough(session->input, std::move(plaintext), session->permission);
      } else {
        server->call(type, session, next_payload, true);
      }
    });

    // This thread handles latency-sensitive control messages
    platf::adjust_thread_priority(platf::thread_priority_e::critical);

    // Check for both the full shutdown event and the shutdown event for this
    // broadcast to ensure we can inform connected clients of our graceful
    // termination when we shut down.
    auto shutdown_event = mail::man->event<bool>(mail::shutdown);
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
    while (!shutdown_event->peek() && !broadcast_shutdown_event->peek()) {
      bool has_session_awaiting_peer = false;

      {
        auto lg = server->_sessions.lock();

        auto now = std::chrono::steady_clock::now();

        KITTY_WHILE_LOOP(auto pos = std::begin(*server->_sessions), pos != std::end(*server->_sessions), {
          // Don't perform additional session processing if we're shutting down
          if (shutdown_event->peek() || broadcast_shutdown_event->peek()) {
            break;
          }

          auto session = *pos;

          if (now > session->pingTimeout) {
            auto address = session->control.peer ? platf::from_sockaddr((sockaddr *) &session->control.peer->address.address) : session->control.expected_peer_address;
            BOOST_LOG(info) << address << ": Ping Timeout"sv;
            session::stop(*session);
          }

          if (session->state.load(std::memory_order_acquire) == session::state_e::STOPPING) {
            pos = server->_sessions->erase(pos);

            if (session->control.peer) {
              {
                auto ptslg = server->_peer_to_session.lock();
                server->_peer_to_session->erase(session->control.peer);
              }

              enet_peer_disconnect_now(session->control.peer, 0);
            }

            session->controlEnd.raise(true);
            continue;
          }

          // Remember if we have a session that's waiting for a peer to connect to the
          // control stream. This ensures the clients are properly notified even when
          // the app terminates before they finish connecting.
          if (!session->control.peer) {
            has_session_awaiting_peer = true;
          } else {
            auto &feedback_queue = session->control.feedback_queue;
            while (feedback_queue->peek()) {
              auto feedback_msg = feedback_queue->pop();

              send_feedback_msg(session, *feedback_msg);
            }

            auto &hdr_queue = session->control.hdr_queue;
            while (session->control.peer && hdr_queue->peek()) {
              auto hdr_info = hdr_queue->pop();

              send_hdr_mode(session, std::move(hdr_info));
            }
          }

          ++pos;
        })
      }

      // Don't break until any pending sessions either expire or connect
      if (proc::proc.running() == 0 && !has_session_awaiting_peer) {
        BOOST_LOG(info) << "Process terminated"sv;
        break;
      }

      server->iterate(150ms);
    }

    // Let all remaining connections know the server is shutting down
    // reason: graceful termination
    std::uint32_t reason = 0x80030023;

    control_terminate_t plaintext;
    plaintext.header.type = packetTypes[IDX_TERMINATION];
    plaintext.header.payloadLength = sizeof(plaintext.ec);
    plaintext.ec = util::endian::big<uint32_t>(reason);

    std::array<std::uint8_t, sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
      encrypted_payload;

    auto lg = server->_sessions.lock();
    for (auto pos = std::begin(*server->_sessions); pos != std::end(*server->_sessions); ++pos) {
      auto session = *pos;

      // We may not have gotten far enough to have an ENet connection yet
      if (session->control.peer) {
        auto payload = encode_control(session, util::view(plaintext), encrypted_payload);

        if (server->send(payload, session->control.peer)) {
          TUPLE_2D(port, addr, platf::from_sockaddr_ex((sockaddr *) &session->control.peer->address.address));
          BOOST_LOG(warning) << "Couldn't send termination code to ["sv << addr << ':' << port << ']';
        }
      }

      session->shutdown_event->raise(true);
      session->controlEnd.raise(true);
    }

    server->flush();
  }

  void recvThread(broadcast_ctx_t &ctx) {
    std::map<av_session_id_t, message_queue_t> peer_to_video_session;
    std::map<av_session_id_t, message_queue_t> peer_to_audio_session;

    auto &video_sock = ctx.video_sock;
    auto &audio_sock = ctx.audio_sock;

    auto &message_queue_queue = ctx.message_queue_queue;
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);

    auto &io = ctx.io_context;

    udp::endpoint peer;

    std::array<char, 2048> buf[2];
    std::function<void(const boost::system::error_code, size_t)> recv_func[2];

    auto populate_peer_to_session = [&]() {
      while (message_queue_queue->peek()) {
        auto message_queue_opt = message_queue_queue->pop();
        TUPLE_3D_REF(socket_type, session_id, message_queue, *message_queue_opt);

        switch (socket_type) {
          case socket_e::video:
            if (message_queue) {
              peer_to_video_session.emplace(session_id, message_queue);
            } else {
              peer_to_video_session.erase(session_id);
            }
            break;
          case socket_e::audio:
            if (message_queue) {
              peer_to_audio_session.emplace(session_id, message_queue);
            } else {
              peer_to_audio_session.erase(session_id);
            }
            break;
        }
      }
    };

    auto recv_func_init = [&](udp::socket &sock, int buf_elem, std::map<av_session_id_t, message_queue_t> &peer_to_session) {
      recv_func[buf_elem] = [&, buf_elem](const boost::system::error_code &ec, size_t bytes) {
        auto fg = util::fail_guard([&]() {
          sock.async_receive_from(asio::buffer(buf[buf_elem]), peer, 0, recv_func[buf_elem]);
        });

        auto type_str = buf_elem ? "AUDIO"sv : "VIDEO"sv;
        BOOST_LOG(verbose) << "Recv: "sv << peer.address().to_string() << ':' << peer.port() << " :: " << type_str;

        populate_peer_to_session();

        // No data, yet no error
        if (ec == boost::system::errc::connection_refused || ec == boost::system::errc::connection_reset) {
          return;
        }

        if (ec || !bytes) {
          BOOST_LOG(error) << "Couldn't receive data from udp socket: "sv << ec.message();
          return;
        }

        if (buf_elem == 0 && bytes >= 6 && std::memcmp(buf[buf_elem].data(), "FTNK", 4) == 0) {
          // FrogtaleTV patch: retransmit request from a patched client
          nack::handle(peer, buf[buf_elem].data() + 4, bytes - 4);
          return;
        }

        if (buf_elem == 0 && bytes >= 8 && std::memcmp(buf[buf_elem].data(), "FTDL", 4) == 0) {
          // FrogtaleTV patch: queueing delay report from a patched client
          nack::handle_delay(peer, buf[buf_elem].data() + 4, bytes - 4);
          return;
        }

        if (bytes == 4) {
          // For legacy PING packets, find the matching session by address.
          auto it = peer_to_session.find(peer.address());
          if (it != std::end(peer_to_session)) {
            BOOST_LOG(debug) << "RAISE: "sv << peer.address().to_string() << ':' << peer.port() << " :: " << type_str;
            it->second->raise(peer, std::string {buf[buf_elem].data(), bytes});
          }
        } else if (bytes >= sizeof(SS_PING)) {
          auto ping = (PSS_PING) buf[buf_elem].data();

          // For new PING packets that include a client identifier, search by payload.
          auto it = peer_to_session.find(std::string {ping->payload, sizeof(ping->payload)});
          if (it != std::end(peer_to_session)) {
            BOOST_LOG(debug) << "RAISE: "sv << peer.address().to_string() << ':' << peer.port() << " :: " << type_str;
            it->second->raise(peer, std::string {buf[buf_elem].data(), bytes});
          }
        }
      };
    };

    recv_func_init(video_sock, 0, peer_to_video_session);
    recv_func_init(audio_sock, 1, peer_to_audio_session);

    video_sock.async_receive_from(asio::buffer(buf[0]), peer, 0, recv_func[0]);
    audio_sock.async_receive_from(asio::buffer(buf[1]), peer, 0, recv_func[1]);

    while (!broadcast_shutdown_event->peek()) {
      io.run();
    }
  }

  void videoBroadcastThread(udp::socket &sock) {
    auto shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
    auto packets = mail::man->queue<video::packet_t>(mail::video_packets);
    auto video_epoch = std::chrono::steady_clock::now();

    // Video traffic is sent on this thread
    platf::adjust_thread_priority(platf::thread_priority_e::high);

    logging::min_max_avg_periodic_logger<double> frame_processing_latency_logger(debug, "Frame processing latency", "ms");

    logging::time_delta_periodic_logger frame_send_batch_latency_logger(debug, "Network: each send_batch() latency");
    logging::time_delta_periodic_logger frame_fec_latency_logger(debug, "Network: each FEC block latency");
    logging::time_delta_periodic_logger frame_network_latency_logger(debug, "Network: frame's overall network latency");

    crypto::aes_t iv(12);

    auto timer = platf::create_high_precision_timer();
    if (!timer || !*timer) {
      BOOST_LOG(error) << "Failed to create timer, aborting video broadcast thread";
      return;
    }

    auto ratecontrol_next_frame_start = std::chrono::steady_clock::now();

    while (auto packet = packets->pop()) {
      if (shutdown_event->peek()) {
        break;
      }

      frame_network_latency_logger.first_point_now();

      auto session = (session_t *) packet->channel_data;
      auto lowseq = session->video.lowseq;

      std::string_view payload {(char *) packet->data(), packet->data_size()};
      std::vector<uint8_t> payload_with_replacements;

      // Apply replacements on the packet payload before performing any other operations.
      // We need to know the final frame size to calculate the last packet size, and we
      // must avoid matching replacements against the frame header or any other non-video
      // part of the payload.
      if (packet->is_idr() && packet->replacements) {
        for (auto &replacement : *packet->replacements) {
          auto frame_old = replacement.old;
          auto frame_new = replacement._new;

          payload_with_replacements = replace(payload, frame_old, frame_new);
          payload = {(char *) payload_with_replacements.data(), payload_with_replacements.size()};
        }
      }

      video_short_frame_header_t frame_header = {};
      frame_header.headerType = 0x01;  // Short header type
      frame_header.frameType = packet->is_idr()                     ? 2 :
                               packet->after_ref_frame_invalidation ? 5 :
                                                                      1;
      frame_header.lastPayloadLen = (payload.size() + sizeof(frame_header)) % (session->config.packetsize - sizeof(NV_VIDEO_PACKET));
      if (frame_header.lastPayloadLen == 0) {
        frame_header.lastPayloadLen = session->config.packetsize - sizeof(NV_VIDEO_PACKET);
      }

      if (packet->frame_timestamp) {
        auto duration_to_latency = [](const std::chrono::steady_clock::duration &duration) {
          const auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
          return (uint16_t) std::clamp<decltype(duration_us)>((duration_us + 50) / 100, 0, std::numeric_limits<uint16_t>::max());
        };

        uint16_t latency = duration_to_latency(std::chrono::steady_clock::now() - *packet->frame_timestamp);
        frame_header.frame_processing_latency = latency;
        frame_processing_latency_logger.collect_and_log(latency / 10.);
      } else {
        frame_header.frame_processing_latency = 0;
      }

      auto fecPercentage = config::stream.fec_percentage;
      if (auto fec_history = nack::find(session->video.peer)) {
        std::lock_guard lg {fec_history->mutex};
        fecPercentage = std::max(fecPercentage, fec_history->fec_boost);
      }

      // Insert space for packet headers
      auto blocksize = session->config.packetsize + MAX_RTP_HEADER_SIZE;
      auto payload_blocksize = blocksize - sizeof(video_packet_raw_t);
      auto payload_new = concat_and_insert(sizeof(video_packet_raw_t), payload_blocksize, std::string_view {(char *) &frame_header, sizeof(frame_header)}, payload);

      payload = std::string_view {(char *) payload_new.data(), payload_new.size()};

      // There are 2 bits for FEC block count for a maximum of 4 FEC blocks
      constexpr auto MAX_FEC_BLOCKS = 4;

      // The max number of data shards per block is found by solving this system of equations for D:
      // D = 255 - P
      // P = D * F
      // which results in the solution:
      // D = 255 / (1 + F)
      // multiplied by 100 since F is the percentage as an integer:
      // D = (255 * 100) / (100 + F)
      auto max_data_shards_per_fec_block = (DATA_SHARDS_MAX * 100) / (100 + fecPercentage);

      // Compute the number of FEC blocks needed for this frame using the block size and max shards
      auto max_data_per_fec_block = max_data_shards_per_fec_block * blocksize;
      auto fec_blocks_needed = (payload.size() + (max_data_per_fec_block - 1)) / max_data_per_fec_block;

      // If the number of FEC blocks needed exceeds the protocol limit, turn off FEC for this frame.
      // For normal FEC percentages, this should only happen for enormous frames (over 800 packets at 20%).
      if (fec_blocks_needed > MAX_FEC_BLOCKS) {
        BOOST_LOG(warning) << "Skipping FEC for abnormally large encoded frame (needed "sv << fec_blocks_needed << " FEC blocks)"sv;
        fecPercentage = 0;
        fec_blocks_needed = MAX_FEC_BLOCKS;
      }

      std::array<std::string_view, MAX_FEC_BLOCKS> fec_blocks;
      decltype(fec_blocks)::iterator
        fec_blocks_begin = std::begin(fec_blocks),
        fec_blocks_end = std::begin(fec_blocks) + fec_blocks_needed;

      BOOST_LOG(verbose) << "Generating "sv << fec_blocks_needed << " FEC blocks"sv;

      // Align individual FEC blocks to blocksize
      auto unaligned_size = payload.size() / fec_blocks_needed;
      auto aligned_size = ((unaligned_size + (blocksize - 1)) / blocksize) * blocksize;

      // If we exceed the 10-bit FEC packet index (which means our frame exceeded 4096 packets),
      // the frame will be unrecoverable. Log an error for this case.
      if (aligned_size / blocksize >= 1024) {
        BOOST_LOG(error) << "Encoder produced a frame too large to send! Is the encoder broken? (needed "sv << (aligned_size / blocksize) << " packets)"sv;
      }

      // Split the data into aligned FEC blocks
      for (int x = 0; x < fec_blocks_needed; ++x) {
        if (x == fec_blocks_needed - 1) {
          // The last block must extend to the end of the payload
          fec_blocks[x] = payload.substr(x * aligned_size);
        } else {
          // Earlier blocks just extend to the next block offset
          fec_blocks[x] = payload.substr(x * aligned_size, aligned_size);
        }
      }

      try {
        // Use around 80% of 1Gbps          1Gbps            percent    ms     packet      byte
        size_t ratecontrol_packets_in_1ms = std::giga::num * 80 / 100 / 1000 / blocksize / 8;

        // Send less than 64K in a single batch.
        // On Windows, batches above 64K seem to bypass SO_SNDBUF regardless of its size,
        // appear in "Other I/O" and begin waiting for interrupts.
        // This gives inconsistent performance so we'd rather avoid it.
        size_t send_batch_size = 64 * 1024 / blocksize;
        // Also don't exceed 64 packets, which can happen when Moonlight requests
        // unusually small packet size.
        // Generic Segmentation Offload on Linux can't do more than 64.
        send_batch_size = std::min<size_t>(64, send_batch_size);

        // Don't ignore the last ratecontrol group of the previous frame
        auto ratecontrol_frame_start = std::max(ratecontrol_next_frame_start, std::chrono::steady_clock::now());

        size_t ratecontrol_frame_packets_sent = 0;
        size_t ratecontrol_group_packets_sent = 0;

        auto blockIndex = 0;
        std::for_each(fec_blocks_begin, fec_blocks_end, [&](std::string_view &current_payload) {
          auto packets = (current_payload.size() + (blocksize - 1)) / blocksize;

          for (int x = 0; x < packets; ++x) {
            auto *inspect = (video_packet_raw_t *) &current_payload[x * blocksize];

            inspect->packet.frameIndex = packet->frame_index();
            inspect->packet.streamPacketIndex = ((uint32_t) lowseq + x) << 8;

            // Match multiFecFlags with Moonlight
            inspect->packet.multiFecFlags = 0x10;
            inspect->packet.multiFecBlocks = (blockIndex << 4) | ((fec_blocks_needed - 1) << 6);

            inspect->packet.flags = FLAG_CONTAINS_PIC_DATA;
            if (x == 0) {
              inspect->packet.flags |= FLAG_SOF;
            }
            if (x == packets - 1) {
              inspect->packet.flags |= FLAG_EOF;
            }
          }

          frame_fec_latency_logger.first_point_now();
          // If video encryption is enabled, we allocate space for the encryption header before each shard
          auto shards = fec::encode(current_payload, blocksize, fecPercentage, session->config.minRequiredFecPackets, session->video.cipher ? sizeof(video_packet_enc_prefix_t) : 0);
          frame_fec_latency_logger.second_point_now_and_log();

          // FrogtaleTV patch: GeForce Now paces each frame in a few groups at most 1 ms apart
          // (packetPacing.numGroups 5, maxDelayUs 1000) instead of one burst at line rate, which
          // overflows queues on a constrained or just-recovered satellite link.
          if (config::stream.frogtale_pacing_groups > 0) {
            auto groups = (size_t) config::stream.frogtale_pacing_groups;
            auto group_size = std::max<size_t>(1, (shards.size() + groups - 1) / groups);
            ratecontrol_packets_in_1ms = group_size;
            send_batch_size = std::min(send_batch_size, group_size);
          }

          auto peer_address = session->video.peer.address();

          // FrogtaleTV patch: keep what we send so a patched client can NACK it
          auto nack_history = nack::get_or_create(session->video.peer);
          {
            std::lock_guard lg {nack_history->mutex};
            nack_history->native_socket = (uintptr_t) sock.native_handle();
            nack_history->address = peer_address;
            nack_history->port = session->video.peer.port();
            nack_history->local_address = session->localAddress;
            nack_history->bitrate_events = session->video.frogtale_bitrate_events;
            if (!nack_history->base_kbps) {
              nack_history->base_kbps = nack_history->current_kbps = session->config.monitor.bitrate;
            }
          }

          auto batch_info = platf::batched_send_info_t {
            shards.headers.begin(),
            shards.prefixsize,
            shards.payload_buffers,
            shards.blocksize,
            0,
            0,
            (uintptr_t) sock.native_handle(),
            peer_address,
            session->video.peer.port(),
            session->localAddress,
          };

          size_t next_shard_to_send = 0;

          // RTP video timestamps use a 90 KHz clock and the frame_timestamp from when the frame was captured
          // When a timestamp isn't available (duplicate frames), the timestamp from rate control is used instead.
          bool frame_is_dupe = false;
          if (!packet->frame_timestamp) {
            packet->frame_timestamp = ratecontrol_next_frame_start;
            frame_is_dupe = true;
          }
          using rtp_tick = std::chrono::duration<uint32_t, std::ratio<1, 90000>>;
          uint32_t timestamp = std::chrono::round<rtp_tick>(*packet->frame_timestamp - video_epoch).count();

          // set FEC info now that we know for sure what our percentage will be for this frame
          for (auto x = 0; x < shards.size(); ++x) {
            auto *inspect = (video_packet_raw_t *) shards.data(x);

            inspect->packet.fecInfo =
              (x << 12 |
               shards.data_shards << 22 |
               shards.percentage << 4);

            inspect->rtp.header = 0x80 | FLAG_EXTENSION;
            inspect->rtp.sequenceNumber = util::endian::big<uint16_t>(lowseq + x);
            inspect->rtp.timestamp = util::endian::big<uint32_t>(timestamp);

            inspect->packet.multiFecBlocks = (blockIndex << 4) | ((fec_blocks_needed - 1) << 6);
            inspect->packet.frameIndex = packet->frame_index();

            // Encrypt this shard if video encryption is enabled
            if (session->video.cipher) {
              // We use the deterministic IV construction algorithm specified in NIST SP 800-38D
              // Section 8.2.1. The sequence number is our "invocation" field and the 'V' in the
              // high bytes is the "fixed" field. Because each client provides their own unique
              // key, our values in the fixed field need only uniquely identify each independent
              // use of the client's key with AES-GCM in our code.
              //
              // The IV counter is 64 bits long which allows for 2^64 encrypted video packets
              // to be sent to each client before the IV repeats.
              std::copy_n((uint8_t *) &session->video.gcm_iv_counter, sizeof(session->video.gcm_iv_counter), std::begin(iv));
              iv[11] = 'V';  // Video stream
              session->video.gcm_iv_counter++;

              // Encrypt the target buffer in place
              auto *prefix = (video_packet_enc_prefix_t *) shards.prefix(x);
              prefix->frameNumber = packet->frame_index();
              std::copy(std::begin(iv), std::end(iv), prefix->iv);
              session->video.cipher->encrypt(std::string_view {(char *) inspect, (size_t) blocksize}, prefix->tag, (uint8_t *) inspect, &iv);
            }

            nack::store(*nack_history, (uint16_t) (lowseq + x), shards.prefix(x), shards.prefixsize, shards.data(x), shards.blocksize);

            if (x - next_shard_to_send + 1 >= send_batch_size ||
                x + 1 == shards.size()) {
              // Do pacing within the frame.
              // Also trigger pacing before the first send_batch() of the frame
              // to account for the last send_batch() of the previous frame.
              if (ratecontrol_group_packets_sent >= ratecontrol_packets_in_1ms ||
                  ratecontrol_frame_packets_sent == 0) {
                auto due = ratecontrol_frame_start +
                           std::chrono::duration_cast<std::chrono::nanoseconds>(1ms) *
                             ratecontrol_frame_packets_sent / ratecontrol_packets_in_1ms;

                auto now = std::chrono::steady_clock::now();
                if (now < due) {
                  timer->sleep_for(due - now);
                }

                ratecontrol_group_packets_sent = 0;
              }

              size_t current_batch_size = x - next_shard_to_send + 1;
              batch_info.block_offset = next_shard_to_send;
              batch_info.block_count = current_batch_size;

              frame_send_batch_latency_logger.first_point_now();
              // Use a batched send if it's supported on this platform
              if (!platf::send_batch(batch_info)) {
                // Batched send is not available, so send each packet individually
                BOOST_LOG(verbose) << "Falling back to unbatched send"sv;
                for (auto y = 0; y < current_batch_size; y++) {
                  auto send_info = platf::send_info_t {
                    shards.prefix(next_shard_to_send + y),
                    shards.prefixsize,
                    shards.data(next_shard_to_send + y),
                    shards.blocksize,
                    (uintptr_t) sock.native_handle(),
                    peer_address,
                    session->video.peer.port(),
                    session->localAddress,
                  };

                  platf::send(send_info);
                }
              }
              frame_send_batch_latency_logger.second_point_now_and_log();

              ratecontrol_group_packets_sent += current_batch_size;
              ratecontrol_frame_packets_sent += current_batch_size;
              next_shard_to_send = x + 1;
            }
          }

          // remember this in case the next frame comes immediately
          ratecontrol_next_frame_start = ratecontrol_frame_start +
                                         std::chrono::duration_cast<std::chrono::nanoseconds>(1ms) *
                                           ratecontrol_frame_packets_sent / ratecontrol_packets_in_1ms;

          frame_network_latency_logger.second_point_now_and_log();

          BOOST_LOG(verbose) << "Sent Frame seq ["sv << packet->frame_index() << "] pts ["sv << timestamp
                             << "] shards ["sv << shards.size() << "/"sv << shards.percentage << "%]"sv
                             << (frame_is_dupe ? " Dupe" : "")
                             << (packet->is_idr() ? " Key" : "")
                             << (packet->after_ref_frame_invalidation ? " RFI" : "");

          ++blockIndex;
          lowseq += shards.size();
        });

        session->video.lowseq = lowseq;
      } catch (const std::exception &e) {
        BOOST_LOG(error) << "Broadcast video failed "sv << e.what();
        std::this_thread::sleep_for(100ms);
      }
    }

    shutdown_event->raise(true);
  }

  void audioBroadcastThread(udp::socket &sock) {
    auto shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);
    auto packets = mail::man->queue<audio::packet_t>(mail::audio_packets);

    audio_packet_t audio_packet;
    fec::rs_t rs {reed_solomon_new(RTPA_DATA_SHARDS, RTPA_FEC_SHARDS)};
    crypto::aes_t iv(16);

    // For unknown reasons, the RS parity matrix computed by our RS implementation
    // doesn't match the one Nvidia uses for audio data. I'm not exactly sure why,
    // but we can simply replace it with the matrix generated by OpenFEC which
    // works correctly. This is possible because the data and FEC shard count is
    // constant and known in advance.
    const unsigned char parity[] = {0x77, 0x40, 0x38, 0x0e, 0xc7, 0xa7, 0x0d, 0x6c};
    memcpy(rs.get()->p, parity, sizeof(parity));

    audio_packet.rtp.header = 0x80;
    audio_packet.rtp.packetType = 97;
    audio_packet.rtp.ssrc = 0;

    // Audio traffic is sent on this thread
    platf::adjust_thread_priority(platf::thread_priority_e::high);

    while (auto packet = packets->pop()) {
      if (shutdown_event->peek()) {
        break;
      }

      TUPLE_2D_REF(channel_data, packet_data, *packet);
      auto session = (session_t *) channel_data;

      auto sequenceNumber = session->audio.sequenceNumber;
      auto timestamp = session->audio.timestamp;

      *(std::uint32_t *) iv.data() = util::endian::big<std::uint32_t>(session->audio.avRiKeyId + sequenceNumber);

      auto &shards_p = session->audio.shards_p;

      auto bytes = encode_audio(session->config.encryptionFlagsEnabled & SS_ENC_AUDIO, packet_data, shards_p[sequenceNumber % RTPA_DATA_SHARDS], iv, session->audio.cipher);
      if (bytes < 0) {
        BOOST_LOG(error) << "Couldn't encode audio packet"sv;
        break;
      }

      BOOST_LOG(verbose) << "Audio [seq "sv << sequenceNumber << ", pts "sv << timestamp << "] ::  send..."sv;

      audio_packet.rtp.sequenceNumber = util::endian::big(sequenceNumber);
      audio_packet.rtp.timestamp = util::endian::big(timestamp);

      session->audio.sequenceNumber++;
      session->audio.timestamp += session->config.audio.packetDuration;

      auto peer_address = session->audio.peer.address();
      try {
        auto send_info = platf::send_info_t {
          (const char *) &audio_packet,
          sizeof(audio_packet),
          (const char *) shards_p[sequenceNumber % RTPA_DATA_SHARDS],
          (size_t) bytes,
          (uintptr_t) sock.native_handle(),
          peer_address,
          session->audio.peer.port(),
          session->localAddress,
        };
        platf::send(send_info);

        auto &fec_packet = session->audio.fec_packet;
        // initialize the FEC header at the beginning of the FEC block
        if (sequenceNumber % RTPA_DATA_SHARDS == 0) {
          fec_packet.fecHeader.baseSequenceNumber = util::endian::big(sequenceNumber);
          fec_packet.fecHeader.baseTimestamp = util::endian::big(timestamp);
        }

        // generate parity shards at the end of the FEC block
        if ((sequenceNumber + 1) % RTPA_DATA_SHARDS == 0) {
          reed_solomon_encode(rs.get(), shards_p.begin(), RTPA_TOTAL_SHARDS, bytes);

          for (auto x = 0; x < RTPA_FEC_SHARDS; ++x) {
            fec_packet.rtp.sequenceNumber = util::endian::big<std::uint16_t>(sequenceNumber + x + 1);
            fec_packet.fecHeader.fecShardIndex = x;

            auto send_info = platf::send_info_t {
              (const char *) &fec_packet,
              sizeof(fec_packet),
              (const char *) shards_p[RTPA_DATA_SHARDS + x],
              (size_t) bytes,
              (uintptr_t) sock.native_handle(),
              peer_address,
              session->audio.peer.port(),
              session->localAddress,
            };
            platf::send(send_info);
            BOOST_LOG(verbose) << "Audio FEC ["sv << (sequenceNumber & ~(RTPA_DATA_SHARDS - 1)) << ' ' << x << "] ::  send..."sv;
          }
        }
      } catch (const std::exception &e) {
        BOOST_LOG(error) << "Broadcast audio failed "sv << e.what();
        std::this_thread::sleep_for(100ms);
      }
    }

    shutdown_event->raise(true);
  }

  int start_broadcast(broadcast_ctx_t &ctx) {
    auto address_family = net::af_from_enum_string(config::sunshine.address_family);
    auto protocol = address_family == net::IPV4 ? udp::v4() : udp::v6();
    auto control_port = net::map_port(CONTROL_PORT);
    auto video_port = net::map_port(VIDEO_STREAM_PORT);
    auto audio_port = net::map_port(AUDIO_STREAM_PORT);

    if (ctx.control_server.bind(address_family, control_port)) {
      BOOST_LOG(error) << "Couldn't bind Control server to port ["sv << control_port << "], likely another process already bound to the port"sv;

      return -1;
    }

    boost::system::error_code ec;
    ctx.video_sock.open(protocol, ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't open socket for Video server: "sv << ec.message();

      return -1;
    }

    // Set video socket send buffer size (SO_SENDBUF) to 1MB
    try {
      ctx.video_sock.set_option(boost::asio::socket_base::send_buffer_size(1024 * 1024));
    } catch (...) {
      BOOST_LOG(error) << "Failed to set video socket send buffer size (SO_SENDBUF)";
    }

    ctx.video_sock.bind(udp::endpoint(protocol, video_port), ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't bind Video server to port ["sv << video_port << "]: "sv << ec.message();

      return -1;
    }

    ctx.audio_sock.open(protocol, ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't open socket for Audio server: "sv << ec.message();

      return -1;
    }

    ctx.audio_sock.bind(udp::endpoint(protocol, audio_port), ec);
    if (ec) {
      BOOST_LOG(fatal) << "Couldn't bind Audio server to port ["sv << audio_port << "]: "sv << ec.message();

      return -1;
    }

    ctx.message_queue_queue = std::make_shared<message_queue_queue_t::element_type>(30);

    ctx.video_thread = std::thread {videoBroadcastThread, std::ref(ctx.video_sock)};
    ctx.audio_thread = std::thread {audioBroadcastThread, std::ref(ctx.audio_sock)};
    ctx.control_thread = std::thread {controlBroadcastThread, &ctx.control_server};

    ctx.recv_thread = std::thread {recvThread, std::ref(ctx)};

    return 0;
  }

  void end_broadcast(broadcast_ctx_t &ctx) {
    auto broadcast_shutdown_event = mail::man->event<bool>(mail::broadcast_shutdown);

    broadcast_shutdown_event->raise(true);

    auto video_packets = mail::man->queue<video::packet_t>(mail::video_packets);
    auto audio_packets = mail::man->queue<audio::packet_t>(mail::audio_packets);

    // Minimize delay stopping video/audio threads
    video_packets->stop();
    audio_packets->stop();

    ctx.message_queue_queue->stop();
    ctx.io_context.stop();

    ctx.video_sock.close();
    ctx.audio_sock.close();

    video_packets.reset();
    audio_packets.reset();

    BOOST_LOG(debug) << "Waiting for main listening thread to end..."sv;
    ctx.recv_thread.join();
    BOOST_LOG(debug) << "Waiting for main video thread to end..."sv;
    ctx.video_thread.join();
    BOOST_LOG(debug) << "Waiting for main audio thread to end..."sv;
    ctx.audio_thread.join();
    BOOST_LOG(debug) << "Waiting for main control thread to end..."sv;
    ctx.control_thread.join();
    BOOST_LOG(debug) << "All broadcasting threads ended"sv;

    broadcast_shutdown_event->reset();
  }

  int recv_ping(session_t *session, decltype(broadcast)::ptr_t ref, socket_e type, std::string_view expected_payload, udp::endpoint &peer, std::chrono::milliseconds timeout) {
    auto messages = std::make_shared<message_queue_t::element_type>(30);
    av_session_id_t session_id = std::string {expected_payload};

    // Only allow matches on the peer address for legacy clients
    if (!(session->config.mlFeatureFlags & ML_FF_SESSION_ID_V1)) {
      ref->message_queue_queue->raise(type, peer.address(), messages);
    }
    ref->message_queue_queue->raise(type, session_id, messages);

    auto fg = util::fail_guard([&]() {
      messages->stop();

      // remove message queue from session
      if (!(session->config.mlFeatureFlags & ML_FF_SESSION_ID_V1)) {
        ref->message_queue_queue->raise(type, peer.address(), nullptr);
      }
      ref->message_queue_queue->raise(type, session_id, nullptr);
    });

    auto start_time = std::chrono::steady_clock::now();
    auto current_time = start_time;

    while (current_time - start_time < config::stream.ping_timeout) {
      auto delta_time = current_time - start_time;

      auto msg_opt = messages->pop(config::stream.ping_timeout - delta_time);
      if (!msg_opt) {
        break;
      }

      TUPLE_2D_REF(recv_peer, msg, *msg_opt);
      if (msg.find(expected_payload) != std::string::npos) {
        // Match the new PING payload format
        BOOST_LOG(debug) << "Received ping [v2] from "sv << recv_peer.address() << ':' << recv_peer.port() << " ["sv << util::hex_vec(msg) << ']';
      } else if (!(session->config.mlFeatureFlags & ML_FF_SESSION_ID_V1) && msg == "PING"sv) {
        // Match the legacy fixed PING payload only if the new type is not supported
        BOOST_LOG(debug) << "Received ping [v1] from "sv << recv_peer.address() << ':' << recv_peer.port() << " ["sv << util::hex_vec(msg) << ']';
      } else {
        BOOST_LOG(debug) << "Received non-ping from "sv << recv_peer.address() << ':' << recv_peer.port() << " ["sv << util::hex_vec(msg) << ']';
        current_time = std::chrono::steady_clock::now();
        continue;
      }

      // Update connection details.
      peer = recv_peer;
      return 0;
    }

    BOOST_LOG(error) << "Initial Ping Timeout"sv;
    return -1;
  }

  void videoThread(session_t *session) {
    auto fg = util::fail_guard([&]() {
      session::stop(*session);
    });

    while_starting_do_nothing(session->state);

    auto ref = broadcast.ref();
    auto error = recv_ping(session, ref, socket_e::video, session->video.ping_payload, session->video.peer, config::stream.ping_timeout);
    if (error < 0) {
      return;
    }

    // Enable local prioritization and QoS tagging on video traffic if requested by the client
    auto address = session->video.peer.address();
    session->video.qos = platf::enable_socket_qos(ref->video_sock.native_handle(), address, session->video.peer.port(), platf::qos_data_type_e::video, session->config.videoQosType != 0);

    BOOST_LOG(debug) << "Start capturing Video"sv;
    video::capture(session->mail, session->config.monitor, session);
  }

  void audioThread(session_t *session) {
    auto fg = util::fail_guard([&]() {
      session::stop(*session);
    });

    while_starting_do_nothing(session->state);

    auto ref = broadcast.ref();
    auto error = recv_ping(session, ref, socket_e::audio, session->audio.ping_payload, session->audio.peer, config::stream.ping_timeout);
    if (error < 0) {
      return;
    }

    // Enable local prioritization and QoS tagging on audio traffic if requested by the client
    auto address = session->audio.peer.address();
    session->audio.qos = platf::enable_socket_qos(ref->audio_sock.native_handle(), address, session->audio.peer.port(), platf::qos_data_type_e::audio, session->config.audioQosType != 0);

    BOOST_LOG(debug) << "Start capturing Audio"sv;
    audio::capture(session->mail, session->config.audio, session);
  }

  namespace session {
    std::atomic_uint running_sessions;

    state_e state(session_t &session) {
      return session.state.load(std::memory_order_relaxed);
    }

    inline bool send(session_t& session, const std::string_view &payload) {
      return session.broadcast_ref->control_server.send(payload, session.control.peer);
    }

    std::string uuid(const session_t& session) {
      return session.device_uuid;
    }

    bool uuid_match(const session_t &session, const std::string_view& uuid) {
      return session.device_uuid == uuid;
    }

    bool update_device_info(session_t& session, const std::string& name, const crypto::PERM& newPerm) {
      session.permission = newPerm;
      if (!(newPerm & crypto::PERM::_allow_view)) {
        BOOST_LOG(debug) << "Session: View permission revoked for [" << session.device_name << "], disconnecting...";
        graceful_stop(session);
        return true;
      }

      BOOST_LOG(debug) << "Session: Permission updated for [" << session.device_name << "]";

      if (session.device_name != name) {
        BOOST_LOG(debug) << "Session: Device name changed from [" << session.device_name << "] to [" << name << "]";
        session.device_name = name;
      }

      return false;
    }

    void stop(session_t &session) {
      while_starting_do_nothing(session.state);
      auto expected = state_e::RUNNING;
      auto already_stopping = !session.state.compare_exchange_strong(expected, state_e::STOPPING);
      if (already_stopping) {
        return;
      }

      session.shutdown_event->raise(true);
    }

    void graceful_stop(session_t& session) {
      while_starting_do_nothing(session.state);
      auto expected = state_e::RUNNING;
      auto already_stopping = !session.state.compare_exchange_strong(expected, state_e::STOPPING);
      if (already_stopping) {
        return;
      }

      // reason: graceful termination
      std::uint32_t reason = 0x80030023;

      control_terminate_t plaintext;
      plaintext.header.type = packetTypes[IDX_TERMINATION];
      plaintext.header.payloadLength = sizeof(plaintext.ec);
      plaintext.ec = util::endian::big<uint32_t>(reason);

      // We may not have gotten far enough to have an ENet connection yet
      if (session.control.peer) {
        std::array<std::uint8_t,
          sizeof(control_encrypted_t) + crypto::cipher::round_to_pkcs7_padded(sizeof(plaintext)) + crypto::cipher::tag_size>
          encrypted_payload;
        auto payload = stream::encode_control(&session, util::view(plaintext), encrypted_payload);

        if (send(session, payload)) {
          TUPLE_2D(port, addr, platf::from_sockaddr_ex((sockaddr *) &session.control.peer->address.address));
          BOOST_LOG(warning) << "Couldn't send termination code to ["sv << addr << ':' << port << ']';
        }
      }

      session.shutdown_event->raise(true);
      session.controlEnd.raise(true);
    }

    void join(session_t &session) {
      // Current Nvidia drivers have a bug where NVENC can deadlock the encoder thread with hardware-accelerated
      // GPU scheduling enabled. If this happens, we will terminate ourselves and the service can restart.
      // The alternative is that Sunshine can never start another session until it's manually restarted.
      auto task = []() {
        BOOST_LOG(fatal) << "Hang detected! Session failed to terminate in 10 seconds."sv;
        logging::log_flush();
        lifetime::debug_trap();
      };
      auto force_kill = task_pool.pushDelayed(task, 10s).task_id;
      auto fg = util::fail_guard([&force_kill]() {
        // Cancel the kill task if we manage to return from this function
        task_pool.cancel(force_kill);
      });

      BOOST_LOG(debug) << "Waiting for video to end..."sv;
      session.videoThread.join();
      BOOST_LOG(debug) << "Waiting for audio to end..."sv;
      session.audioThread.join();
      BOOST_LOG(debug) << "Waiting for control to end..."sv;
      session.controlEnd.view();
      // Reset input on session stop to avoid stuck repeated keys
      BOOST_LOG(debug) << "Resetting Input..."sv;
      input::reset(session.input);

      if (!session.undo_cmds.empty()) {
        auto exec_thread = std::thread([cmd_list = session.undo_cmds]{
          for (auto &cmd : cmd_list) {
            std::error_code ec;
            auto env = proc::proc.get_env();
            boost::filesystem::path working_dir = proc::find_working_directory(cmd.cmd, env);
            auto child = platf::run_command(cmd.elevated, true, cmd.cmd, working_dir, env, nullptr, ec, nullptr);
            BOOST_LOG(info) << "Spawning client undo command ["sv << cmd.cmd << "] in ["sv << working_dir << ']';
            if (ec) {
              BOOST_LOG(warning) << "Couldn't spawn ["sv << cmd.cmd << "]: System: "sv << ec.message();
            } else {
              child.detach();
            }
          }
        });

        exec_thread.detach();
      }

      // If this is the last session, invoke the platform callbacks
      if (--running_sessions == 0) {
        bool revert_display_config {config::video.dd.config_revert_on_disconnect};
        if (proc::proc.running()) {
          proc::proc.pause();
        } else {
          // We have no app running and also no clients anymore.
          revert_display_config = true;
        }

        if (revert_display_config) {
          display_device::revert_configuration();
        }

        platf::streaming_will_stop();
      }

      BOOST_LOG(debug) << "Session ended"sv;
    }

    int start(session_t &session, const std::string &addr_string) {
      session.input = input::alloc(session.mail);

      session.broadcast_ref = broadcast.ref();
      if (!session.broadcast_ref) {
        return -1;
      }

      session.control.expected_peer_address = addr_string;
      BOOST_LOG(debug) << "Expecting incoming session connections from "sv << addr_string;

      // Insert this session into the session list
      {
        auto lg = session.broadcast_ref->control_server._sessions.lock();
        session.broadcast_ref->control_server._sessions->push_back(&session);
      }

      auto addr = boost::asio::ip::make_address(addr_string);
      session.video.peer.address(addr);
      session.video.peer.port(0);

      session.audio.peer.address(addr);
      session.audio.peer.port(0);

      session.pingTimeout = std::chrono::steady_clock::now() + config::stream.ping_timeout;

      session.audioThread = std::thread {audioThread, &session};
      session.videoThread = std::thread {videoThread, &session};

      session.state.store(state_e::RUNNING, std::memory_order_relaxed);

      // If this is the first session, invoke the platform callbacks
      if (++running_sessions == 1) {
        platf::streaming_will_start();
        proc::proc.resume();
      }

      if (!session.do_cmds.empty()) {
        auto exec_thread = std::thread([cmd_list = session.do_cmds]{
          for (auto &cmd : cmd_list) {
            std::error_code ec;
            auto env = proc::proc.get_env();
            boost::filesystem::path working_dir = proc::find_working_directory(cmd.cmd, env);
            auto child = platf::run_command(cmd.elevated, true, cmd.cmd, working_dir, env, nullptr, ec, nullptr);
            BOOST_LOG(info) << "Spawning client do command ["sv << cmd.cmd << "] in ["sv << working_dir << ']';
            if (ec) {
              BOOST_LOG(warning) << "Couldn't spawn ["sv << cmd.cmd << "]: System: "sv << ec.message();
            } else {
              child.detach();
            }
          }
        });

        exec_thread.detach();
      }

      return 0;
    }

    std::shared_ptr<session_t> alloc(config_t &config, rtsp_stream::launch_session_t &launch_session) {
      auto session = std::make_shared<session_t>();

      auto mail = std::make_shared<safe::mail_raw_t>();

      session->shutdown_event = mail->event<bool>(mail::shutdown);
      session->launch_session_id = launch_session.id;
      session->device_name = launch_session.device_name;
      session->device_uuid = launch_session.unique_id;
      session->permission = launch_session.perm;

      session->do_cmds = std::move(launch_session.client_do_cmds);
      session->undo_cmds = std::move(launch_session.client_undo_cmds);

      session->config = config;

      session->control.connect_data = launch_session.control_connect_data;
      session->control.feedback_queue = mail->queue<platf::gamepad_feedback_msg_t>(mail::gamepad_feedback);
      session->control.hdr_queue = mail->event<video::hdr_info_t>(mail::hdr);
      session->control.legacy_input_enc_iv = launch_session.iv;
      session->control.cipher = crypto::cipher::gcm_t {
        launch_session.gcm_key,
        false
      };

      session->video.idr_events = mail->event<bool>(mail::idr);
      session->video.invalidate_ref_frames_events = mail->event<std::pair<int64_t, int64_t>>(mail::invalidate_ref_frames);
      session->video.frogtale_bitrate_events = mail->event<int>(mail::frogtale_bitrate);
      session->video.lowseq = 0;
      session->video.ping_payload = launch_session.av_ping_payload;
      if (config.encryptionFlagsEnabled & SS_ENC_VIDEO) {
        BOOST_LOG(info) << "Video encryption enabled"sv;
        session->video.cipher = crypto::cipher::gcm_t {
          launch_session.gcm_key,
          false
        };
        session->video.gcm_iv_counter = 0;
      }

      constexpr auto max_block_size = crypto::cipher::round_to_pkcs7_padded(2048);

      util::buffer_t<char> shards {RTPA_TOTAL_SHARDS * max_block_size};
      util::buffer_t<uint8_t *> shards_p {RTPA_TOTAL_SHARDS};

      for (auto x = 0; x < RTPA_TOTAL_SHARDS; ++x) {
        shards_p[x] = (uint8_t *) &shards[x * max_block_size];
      }

      // Audio FEC spans multiple audio packets,
      // therefore its session specific
      session->audio.shards = std::move(shards);
      session->audio.shards_p = std::move(shards_p);

      session->audio.fec_packet.rtp.header = 0x80;
      session->audio.fec_packet.rtp.packetType = 127;
      session->audio.fec_packet.rtp.timestamp = 0;
      session->audio.fec_packet.rtp.ssrc = 0;

      session->audio.fec_packet.fecHeader.payloadType = 97;
      session->audio.fec_packet.fecHeader.ssrc = 0;

      session->audio.cipher = crypto::cipher::cbc_t {
        launch_session.gcm_key,
        true
      };

      session->audio.ping_payload = launch_session.av_ping_payload;
      session->audio.avRiKeyId = util::endian::big(*(std::uint32_t *) launch_session.iv.data());
      session->audio.sequenceNumber = 0;
      session->audio.timestamp = 0;

      session->control.peer = nullptr;
      session->state.store(state_e::STOPPED, std::memory_order_relaxed);

      session->mail = std::move(mail);

      return session;
    }
  }  // namespace session
}  // namespace stream
