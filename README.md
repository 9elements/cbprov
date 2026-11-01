# cbprov

Offline provisioning for finished coreboot images, in pure Go: no rebuild, no cbfstool.

- **VPD:** set the `RO_VPD` keys coreboot turns into SMBIOS (serial numbers, UUID, product, SKU).
- **Options:** change CFR options stored as EFI variables in `SMMSTORE`.
- **Payload:** replace a CBFS payload; the CBFS metadata hash is updated on CBFS-verified images.
- **Show:** print everything provisionable, with defaults; `--json` everywhere.

Status: early development, not yet released.

## Install

```
go install github.com/9elements/cbprov/cmd/cbprov@latest
```

## Usage

Writes never modify the input unless `--in-place` is given; otherwise pass `-o OUT`.
Bytes outside the region a command owns are checked to be unchanged before anything is written.

```
cbprov show coreboot.rom
cbprov vpd set coreboot.rom serial_number=SN123 system_uuid=00112233-4455-6677-8899-aabbccddeeff -o out.rom
cbprov vpd keys
cbprov option list coreboot.rom
cbprov option set coreboot.rom power_on_after_fail=Enable -o out.rom
cbprov option reset coreboot.rom --all --in-place
cbprov payload replace coreboot.rom --file linux.elf -o out.rom
cbprov apply coreboot.rom -f provision.yaml -o out.rom
```

Provisioning file:

```yaml
vpd:
  serial_number: SN123
  system_uuid: 00112233-4455-6677-8899-aabbccddeeff
schema: cfr.bin            # optional, embedded into CBFS first
options:
  power_on_after_fail: Enable
payload:
  fallback/payload: linux.elf
```

## Option schema (CFR)

coreboot builds its CFR option list at runtime, so the image does not contain it.
Without a schema cbprov works in raw mode (names and numbers only). To get names,
choices and defaults, capture the CFR once per board build and embed it:

```
cbprov schema extract --from-cbtable cbtable.bin -o cfr.bin   # coreboot table dump from a running board
cbprov schema embed coreboot.rom cfr.bin --in-place          # stored as CBFS cfr.bin
```

## Requirements on the coreboot build

| Feature | Kconfig |
| --- | --- |
| VPD | `CONFIG_VPD`, plus `SMBIOS_SERIAL_FROM_VPD`, `SMBIOS_UUID_FROM_VPD`, `SMBIOS_SYSTEM_DATA_FROM_VPD` |
| Options | `CONFIG_SMMSTORE`, `DRIVERS_EFI_VARIABLE_STORE`, `USE_UEFI_VARIABLE_STORE`, `DRIVERS_OPTION_CFR` |
| Board info in `show` | `CONFIG_INCLUDE_CONFIG_FILE` (default) |

Images with vboot RW slots are refused for payload changes: re-signing is not implemented.

## Development

```
make test        # unit tests
make fixtures    # build coreboot test images in the coreboot-sdk container
make e2e         # boot the fixtures in QEMU and check provisioning end to end
```

## License

BSD-3-Clause.
