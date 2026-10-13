# FrogtaleTV Starlink build of Apollo

This is Apollo v0.4.6 plus server-side recovery for lossy satellite links. Use it with the Moonlight fork
[aesse94/moonlight-qt](https://github.com/aesse94/moonlight-qt) (branch `frogtale-starlink`; see its
`FROGTALE.md` for the whole picture). Stock Moonlight clients never send the request below, so they see
no change in behaviour.

## Changes (`src/stream.cpp`, namespace `nack`)
- **Resend history:** the last 4096 video packets per client endpoint, kept exactly as sent (after
  encryption).
- **`FTNK` handling:** a datagram on the video socket, `"FTNK"`, `uint16 count`, then `count × (uint16 first,
  uint16 length)`, little endian. The listed RTP sequence numbers are resent from the history.
- **Handoff copies:** once a client has sent an FTNK, every video packet sent from 0.5 s before to 1 s
  after :12/:27/:42/:57 past the minute (UTC, Starlink's reconfiguration schedule) is sent twice more,
  30 ms and 60 ms later. A copy then lands right after a 15–80 ms stall, instead of the client waiting
  a round trip for a NACK. The cost is about 20% extra video bandwidth, all inside those windows. This
  relies on an accurate host clock: Windows' default sync interval is several hours, so a shorter
  `SpecialPollInterval` is recommended.
- **Build fixes for current MSYS2 (GCC 16, mingw-w64 v12+):** a `boost/endian/conversion.hpp`
  include, and the synthetic pointer API declared only for older headers.

## Build (MSYS2 UCRT64)
```
cmake -B build -G Ninja -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_DOCS=OFF -DBUILD_TESTS=OFF \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5
ninja -C build sunshine
```
`build/sunshine.exe` is statically linked. It replaces `sunshine.exe` in an existing Apollo 0.4.6
install; keep the original so you can switch back.

Apollo is GPL-3.0, and so is everything here.
