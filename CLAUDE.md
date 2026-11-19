# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

This is the Wireshark 4.4 personal plugin directory on Windows, not a git repo. The only source files are two Lua scripts:

- `omci.lua`: the OMCI (ITU-T G.984.4 / G.988) dissector, originally written by Technicolor and modified locally.
- `BinDecHex.lua`: a helper library for hex, binary and decimal string conversion. It registers itself as a global via `_G[...] = BinDecHex`, which is why `omci.lua` can call `BinDecHex.Hex2Bin(...)` after a bare `require "BinDecHex"`.

`4.4/` contains the stock compiled plugins (`codecs/`, `epan/`, `wiretap/` DLLs) that ship with Wireshark. Leave them alone.

The parent directory `C:\Program Files\Wireshark\` holds other copies of the dissector: `omci.lua`, `omci_extend.lua`, `omci_kenny_Time.lua` and `omci_ori_backup.lua`, plus an older `BinDecHex.lua`. They are separate variants. If two copies get loaded at the same time, they both register `Proto("omci")` and conflict, so check which file is actually being loaded before you edit.

## Running and testing

There is no build step. Wireshark loads the `.lua` files at startup.

- In the GUI, apply changes with **Analyze → Reload Lua Plugins** (Ctrl+Shift+L).
- To test from the command line, use the bundled tshark. Lua errors are printed to stderr:
  ```
  & "C:\Program Files\Wireshark\tshark.exe" -r capture.pcap -V -Y omci
  & "C:\Program Files\Wireshark\tshark.exe" -r capture.pcap -T fields -e frame.number -e _ws.col.Info
  ```
- To confirm the plugin loaded, run `tshark -G plugins`, or check Help → About → Plugins in the GUI.
- `C:\Program Files\Wireshark\plugins\` can only be written with admin rights, so all development happens in this folder (`Documents\wireshark_omci_plugin`). When a change is finished, an admin copies `omci.lua` / `BinDecHex.lua` into `plugins\`.
- To test this folder's copy without installing it, point tshark at it with `WIRESHARK_PLUGIN_DIR`. That replaces the global plugin dir, so the installed `omci.lua` is not loaded alongside it:
  ```
  WIRESHARK_PLUGIN_DIR="$HOME/Documents/wireshark_omci_plugin" "/c/Program Files/Wireshark/tshark.exe" -r test/t.pcap -V -O omci
  ```
- `test/` holds hand-built captures. Each `*.txt` is a hex dump (Ethernet + Ethertype 0x88B5 + OMCI); turn it into a pcap with `text2pcap.exe -q x.txt x.pcap`.

## Dissector architecture (`omci.lua`)

- **Registration:** the dissector binds to Ethertype `0x88B5` through `DissectorTable.get("ethertype")`, at the end of the file. The input is an Ethernet frame carrying a copy of OMCI traffic (G.988 Appendix III style).
- **Timestamp hack:** the capture tool encodes the date and time in the MAC addresses. The destination MAC is `YY:YY:MM:DD:hh:mm` and the source MAC is `ss:ms:ms:us:us`, in decimal digits. The dissector parses both, accepting `_` or `:` as separators, and appends the result to the Info column. If you change the column format, keep this parsing.
- **Lookup tables**, in file order:
  - `msgtype`: maps message type number to name. It is indexed by `bitfield(3,5)` of the MT byte, and the AR/AK bits are read separately.
  - `msg_result`: maps result codes to names.
  - `test_message_name`: maps test IDs to names.
  - `omci_def`: the main ME table, keyed by ME class ID. Each entry has `me_class_name` plus an array of `{attname, length, setbycreate}` in attribute order. Array index `i` corresponds to attribute-mask bit `i-1`, counting from the MSB.
  - Metatables (for example `mt2`): return a "Reserved …" or `***TBD***` name for any class ID missing from `omci_def`, so a lookup never yields nil.
  - `ext_vlan_op_tbl`: the bit layout of the Extended VLAN Tagging Operation table entry, attribute 6 of ME 171.
- **`omciproto.dissector`:** a single large function that branches on message type, AR and AK. The branches cover Get, Set, Create, MIB Upload Next, Get All Alarms Next, Test, and so on.
  - **Baseline vs. extended format:** if device ID is `0x0b`, the message is extended OMCI. Its content length comes from a 2-byte field and the trailer is a CRC32. Otherwise the content is a fixed 32 bytes followed by CPCS-UU/CPI, length and CRC.
  - Every branch walks `omci_def[class]` against the attribute mask and uses each attribute's `length` to advance the offset.
- **Global state:** `result_code` is a global that the response branches set. The Info column uses it to add an `[ERROR]` prefix.
- **Special cases:**
  - ME 171 (Extended VLAN Tagging): attribute 6 is decoded bit by bit with `ext_vlan_op_tbl`.
  - ME 263 (ANI-G): has its own Test-result handling.

## Adding or fixing an ME

Most changes are edits to `omci_def`. To add an ME class, add `[classId] = { me_class_name = "...", {attname=..., length=..., setbycreate=...}, ... }`. List the attributes in G.988 order and use their exact byte lengths. A wrong `length` misaligns every attribute after it in Get responses, Set requests and MIB uploads. The `att-omci-reference` skill has the attribute sizes from G.988 and AT&T.
