# espnow-sniff

Decode unencrypted [ESP-NOW](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp_now.html)
traffic off the air with an ordinary WiFi adapter, and print the payloads.

ESP-NOW rides inside an 802.11 vendor specific action frame. `tcpdump` and Wireshark both stop
at `Action: Vendor Act#24` — there is no ESP-NOW dissector upstream — so this decodes the frame
itself: radiotap, then the 802.11 header, then the action body and its vendor elements.

```
14:23:01.482913 6      -47   1.0M   1827     2  remote-01           gateway-a     10  "R1 46 0 3"
```

## What you need

* **Monitor mode**, not promiscuous mode. Promiscuous mode is an Ethernet concept (and, confusingly,
  the name of the ESP32's own sniffer API). On Linux only monitor mode (RFMON) hands you raw 802.11
  management frames with a radiotap header.
* An adapter whose driver actually supports it — `ath9k_htc` (AR9271), `rt2800usb` and friends.
  Check with `iw phy phyN info` and look for `* monitor`. Many built-in chips, the Raspberry Pi's
  `brcmfmac` among them, cannot do it at all.
* `gawk`, `tcpdump`, `iw`, and root. No `tshark` or python needed — the pcap stream is decoded
  inside gawk, so this runs on a stripped-down box.
* The traffic must be **unencrypted**. ESP-NOW peers added with `encrypt = true` have a
  CCMP-encrypted body, and you will see the frames but not the payload.
* The transmitter must not be using **`WIFI_PROTOCOL_LR`**. Espressif's long-range PHY is
  proprietary and no conventional adapter can demodulate it.

## Usage

```sh
espnow-sniff -c 6
```

```
  -c CHAN    channel to listen on (0 = hop 1..13 to find traffic)
  -i IFACE   base wifi interface to take the phy from               [auto]
  -m MONIF   name of the monitor interface to create                [mon0]
  -n FILE    MAC -> name table                                      [$HOME/.espnow-names]
  -r FILE    decode an existing pcap instead of capturing live
  -w FILE    also write the raw capture to FILE (pcap, radiotap)
  -t SECS    stop after SECS seconds
  -C COUNT   stop after COUNT frames
  -a         show every vendor action frame, not just ESP-NOW
  -x         hex dump the payload as well as the ASCII rendering
  -q         no per frame lines, print the summary only
  -F         deliver CRC failed frames too (fcsfail), and count them
  -k         keep the monitor interface on exit
```

The monitor interface is created on entry and removed on exit, restoring the base interface.
Nothing is left behind if you interrupt it.

Do not guess the channel. An ESP-NOW device transmits on whichever channel it was configured
for, which need not be the one its AP uses. `-c 0` sweeps 1..13 to find traffic, at the cost of
missing frames while parked elsewhere.

## Naming devices

Bare MAC addresses make a capture hard to read. Point `-n` at a table of
`aa:bb:cc:dd:ee:ff  label` lines — `#` starts a comment, only at the beginning of a line:

```
# MAC                label
02:00:00:00:00:01    remote-01
02:00:00:00:00:02    gateway-a
```

Labels are clipped to the column width. The file is not shipped here, and `.espnow-names` is
gitignored, because it is a map of real hardware addresses.

## Reading the output

`RTY` is the 802.11 **Retry** bit, set by the transmitter on any frame it is resending because
the previous attempt was not acknowledged. Retries reuse the sequence number, so a single send
can legitimately appear as thirty-odd lines. The summary counts them properly:

```
  FROM                TO                   SENDS  RETRIES  RETRY/SEND
  remote-01           gateway-d               34     1077        31.7
  remote-01           gateway-a               33       84         2.5
```

`SENDS` is distinct sequence numbers, so **retries per send** is the link quality figure — near
0 is clean, and around 32 means the transmitter hit the hardware retry limit and gave up. Raw
retry percentages mislead badly here: a link that works fine can sit at 90%.

Two things to keep in mind:

* **Sequence numbers are reused.** A device sending to several peers emits one sequence number
  per peer and starts over on the next wake, so `(source, seq)` is not unique across a capture.
  Split bursts on a large time gap before grouping on it.
* **Monitor capture is lossy**, in a way the endpoints are not — it is a third party overhearing.
  Expect to miss a fraction of frames, rising sharply as the transmitter's signal weakens. A
  retry whose original is absent means you missed the original, not that the sender retried
  instantly. `-F` reports how many frames arrived with a bad CRC, which is usually very few:
  missed frames mostly are not demodulated at all.

## espnow-inject

A companion transmitter, for checking the whole decode path without waiting for real traffic.
It builds a synthetic ESP-NOW action frame and writes it to an `AF_PACKET` socket on a monitor
interface.

```sh
gcc -Wall -O2 -o espnow-inject espnow-inject.c
```

```sh
espnow-sniff -c 6 -t 20 -k &
sleep 5
espnow-inject -i mon0 -c 5
```

The defaults are deliberately inert: both MAC addresses are locally administered (`02:...`) so
they belong to no real device, and the payload is not a valid command for anything. It warns if
you aim it at a globally administered address, because that device may act on the frame.

Injecting and sniffing on one radio does **not** prove the receive path — a half duplex radio
cannot hear itself, so what comes back is mac80211's TX feedback. You can tell: those frames
carry no RSSI (the column shows `?`) and each appears twice. It still exercises the decoder
against a real driver-produced radiotap header, which is a different layout from the receive one.

## Several sniffers at once

One receiver misses a few percent of frames, and which few depends on where it sits.
Several cheap sniffers spread around and reporting to one machine cover far more
between them. `espnow-collect` is the listener:

```sh
espnow-collect -d /var/lib/espnow &
```

Each sniffer connects and is appended to its own `espnow-<ip>.pcap`. Appending across
reconnects is safe, because a sniffer re-emits the pcap global header every time it
connects and the decoder skips headers repeated mid-stream. Any one file decodes on
its own, live if you want it:

```sh
tail -c +1 -f /var/lib/espnow/espnow-10.0.0.5.pcap | espnow-sniff -r /dev/stdin
```

`espnow-merge` collapses them into one view:

```
--- 330 transmissions from 3 collector(s), 3248 frames after merge ---

  COLLECTOR                  SEEN OF TOTAL
  10.0.0.5                    312    94.5%
  10.0.0.6                    301    91.2%

  SEEN BY N COLLECTORS      COUNT    SHARE
  1                            44    13.3%
  2                           286    86.7%
```

Frames are grouped by `(source, sequence, frame id)`, the frame id being the 4 byte
value ESP-NOW carries after the OUI. That value stays the same across the retries of
one transmission and changes between transmissions, so it identifies a transmission
**without the collectors needing agreeing clocks** — which matters, because retries
are about a millisecond apart and byte-identical, finer than any clock protocol
resolves over a LAN. The frame count reported is the **maximum** across collectors,
not the sum: a collector that missed some retries must not drag the number down.

Duplicates are merged rather than discarded, so each transmission keeps every
collector's RSSI. The same frame seen from several points is a coverage map and a
rough fix on where the transmitter was.

### One percentage per collector will mislead you

That summary is only honest while traffic is spread evenly over the collectors, and it
usually is not. A single chatty transmitter parked next to one sniffer can be most of the
traffic in the capture, and then the overall figures say little more than how far each
collector sits from *that one device*. A collector can read 31% and contribute nothing
unique, and still be the only thing in the building that hears its own room properly.

So `-s` breaks it down per source:

```
  PER SOURCE - share of transmissions heard, by device and collector

  SOURCE                  TOTAL          10.0.0.5          10.0.0.6          10.0.0.7
  remote-1                 5584    0.0%    1 -92dBm   97.8% 5462 -64dBm   98.1% 5477 -56dBm
  gateway-a                1367   89.5% 1223 -74dBm   96.9% 1325 -23dBm   71.0%  970 -67dBm
  sensor-1                    2  100.0%    2 -43dBm  100.0%    2 -88dBm  100.0%    2 -83dBm

  each cell: share of TOTAL heard, transmissions, best RSSI seen
```

`10.0.0.5` looks useless on `remote-1`, which happens to be two thirds of the whole
capture — and it is the best receiver in the mesh for `sensor-1`, 40 dB ahead of the
others. Judge a collector on the devices it is there to hear, not on the total.

Periodic sensors make a far better test population than one driven remote, because they
are already spread out the way the mesh is. They are also slow, so give it hours.

## Notes

`subtype action` is not a libpcap keyword — it is a syntax error, not an empty filter. The
working filter is a raw offset match, and libpcap does resolve `wlan[]` past the variable length
radiotap header correctly:

```
wlan[0] == 0xd0 and wlan[24:4] == 0x7f18fe34
```

That is the action frame subtype, then the vendor specific category `0x7f` followed by
Espressif's OUI `18:fe:34`.

## License

Released into the public domain under [The Unlicense](LICENSE). Do whatever you like with it.
