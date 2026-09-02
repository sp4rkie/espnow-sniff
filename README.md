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

## Notes

`subtype action` is not a libpcap keyword — it is a syntax error, not an empty filter. The
working filter is a raw offset match, and libpcap does resolve `wlan[]` past the variable length
radiotap header correctly:

```
wlan[0] == 0xd0 and wlan[24:4] == 0x7f18fe34
```

That is the action frame subtype, then the vendor specific category `0x7f` followed by
Espressif's OUI `18:fe:34`.
