> **Ghidra-Rare fork.** This branch adds tested fixes, release builds for the three newest Ghidra
> releases and test suites; see [GHIDRA-RARE.md](GHIDRA-RARE.md) for the test results and
> remaining gaps, and [CREDITS.md](CREDITS.md) for the original authors and every change.
> Prebuilt zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this fork's
> [Releases page](https://github.com/aleph-void/ghidra-alpha/releases). The original README
> follows; only the parts that are no longer correct were changed (marked *Ghidra-Rare*).

# Alpha processor description for Ghidra

This implements the Digital (DEC) Alpha family of processors for
[Ghidra](https://ghidra-sre.org)

# Requirements

- Ghidra (*Ghidra-Rare:* this branch targets 12.1.4 and is built and tested on 12.1.3, 12.1.4
  and 12.2)
- Knowledge on how to use Ghidra

# Installation

*Ghidra-Rare:* the module now has a Java part (ELF relocations, analyzers), which a symlinked
checkout only gets after building `lib/Alpha.jar`. Install it one of these ways:

- **Release zip:** download the zip for your Ghidra version from the
  [Releases page](https://github.com/aleph-void/ghidra-alpha/releases), then in Ghidra use
  *File > Install Extensions*, add the zip, and restart Ghidra.
- **From source:** `GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC gradle buildExtension`,
  then install the zip from `dist/` the same way.
- **Symlink (development):** the original instructions below still work if you also run
  `test/build-jar.sh` (with `GHIDRA_INSTALL_DIR` set) to compile `lib/Alpha.jar`.

`ghidra-alpha` must be added to your Ghidra installation. Find the
`Ghidra/Processors` directory and create a symlink from there to your
`git` checkout.

## Example

Assuming that Ghidra is installed below `/usr/lib64/ghidra`, run the
following:

~~~
git clone https://github.com/kkaempf/ghidra-alpha.git
sudo ln -s `pwd`/ghidra-alpha /usr/lib64/ghidra/Ghidra/Processors/Alpha
~~~

Then start Ghidra. ~~You now have three Alpha processors (21064, 21164,
21264) to choose from.~~

*Ghidra-Rare:* you now have 15 languages to choose from: five CPU generations (21064, 21164,
21264, 21364, 21464), each with the Unix (Tru64/Linux), OpenVMS and Windows NT register names,
calling convention and CALL_PAL functions. User code decodes the same in all of them; the CPU
selects the PALcode instruction formats. ELF files load as `21264:LE:64:unix` and Windows NT PE
files as `21264:LE:64:nt` automatically. OpenVMS images have no Ghidra loader; import them raw
with a `:vms` language (see GHIDRA-RARE.md).

# Tests

*Ghidra-Rare:* `tests/runtest` needs the `sleigh-lift` tool. `test/upstream-tests.sh` runs the
same `tests/*.hex` files and expected disassembly with Ghidra instead. The full test suite is
`test/run-tests.sh`; see GHIDRA-RARE.md.

# Known limitations

*Ghidra-Rare:* the upstream repository lists none and has no open issues. The limitations found
by testing, which ones are fixed and which remain (with the reason), are listed in
GHIDRA-RARE.md.
