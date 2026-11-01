#!/usr/bin/env bash
# Build the coreboot test fixtures for cbprov's e2e tests.
#
#   test/fixtures/build.sh [name...]     (default: all configs/*.defconfig)
#
# Output: $CBPROV_CACHE/fixtures/<name>/{coreboot.rom,config,build.log,payload.elf}
#         $CBPROV_CACHE/fixtures/tools/{cbfstool,smmstoretool}
#
# Environment:
#   CBPROV_CACHE        cache dir (default: <repo>/.cache)
#   COREBOOT_URL        coreboot git URL (default: review.coreboot.org)
#   COREBOOT_REFERENCE  local coreboot clone to borrow objects from (optional)
#   SDK_IMAGE           coreboot-sdk image
#   CONTAINER_ENGINE    docker | podman | none (none: already inside the SDK)
#   JOBS                make -j (default: nproc)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
cache=${CBPROV_CACHE:-$root/.cache}
mkdir -p "$cache"
cache=$(cd "$cache" && pwd)
cb=$cache/coreboot
out=$cache/fixtures
rev=$(<"$here/COREBOOT_REV")
url=${COREBOOT_URL:-https://review.coreboot.org/coreboot.git}
image=${SDK_IMAGE:-coreboot/coreboot-sdk:2026-07-06_c165edb4ce}
jobs=${JOBS:-$(nproc)}

if [[ -z ${CONTAINER_ENGINE:-} ]]; then
	if command -v docker >/dev/null; then CONTAINER_ENGINE=docker
	elif command -v podman >/dev/null; then CONTAINER_ENGINE=podman
	else echo "need docker or podman (or CONTAINER_ENGINE=none)" >&2; exit 1
	fi
fi

if (($# == 0)); then
	set -- $(cd "$here/configs" && ls *.defconfig | sed 's/\.defconfig$//')
fi
for n in "$@"; do
	[[ -f $here/configs/$n.defconfig ]] || { echo "unknown fixture $n" >&2; exit 1; }
done

log() { printf '==> %s\n' "$*" >&2; }

checkout() {
	if [[ ! -d $cb/.git ]]; then
		log "cloning coreboot"
		git init -q "$cb"
		git -C "$cb" remote add origin "$url"
		if [[ -n ${COREBOOT_REFERENCE:-} ]]; then
			echo "$(cd "$COREBOOT_REFERENCE" && git rev-parse --git-common-dir | xargs realpath)/objects" \
				>"$cb/.git/objects/info/alternates"
		fi
	fi
	if ! git -C "$cb" cat-file -e "$rev^{commit}" 2>/dev/null; then
		log "fetching coreboot $rev"
		git -C "$cb" fetch -q --depth 1 origin "$rev" ||
			git -C "$cb" fetch -q origin
	fi
	git -C "$cb" checkout -q -f --detach "$rev"
	# Build dirs survive so incremental rebuilds stay fast.
	git -C "$cb" clean -fdq -e '/build-*'

	local subs=(3rdparty/vboot)
	[[ " $* " == *" aarch64 "* ]] && subs+=(3rdparty/arm-trusted-firmware)
	log "submodules: ${subs[*]}"
	git -C "$cb" submodule update -q --init --depth 1 "${subs[@]}" 2>/dev/null ||
		git -C "$cb" submodule update -q --init "${subs[@]}"

	local p
	for p in "$here"/patches/*.patch; do
		[[ -e $p ]] || continue
		log "applying $(basename "$p")"
		git -C "$cb" apply --index "$p"
	done
}

payloads() {
	mkdir -p "$out/payloads"
	local a
	for a in x86 arm64; do
		(cd "$root" && go run ./test/payload -arch "$a" -msg CBPROV-PAYLOAD-A -o "$out/payloads/$a-a.elf")
	done
}

# Runs inside the SDK container with $cb as working directory.
inner='
set -euo pipefail
out=$1 jobs=$2; shift 2
fail=()

echo "==> host tools" >&2
mkdir -p "$out/tools"
# Static, so they run on hosts with an older glibc than the SDK.
if ! { make -C util/cbfstool clean && make -C util/cbfstool cbfstool TOOLLDFLAGS=-static -j"$jobs" &&
       make -C util/smmstoretool clean && make -C util/smmstoretool LDFLAGS=-static -j"$jobs"; } \
		>"$out/tools/build.log" 2>&1; then
	tail -n 30 "$out/tools/build.log" >&2
	exit 1
fi
cp util/cbfstool/cbfstool util/smmstoretool/smmstoretool "$out/tools/"

for n in "$@"; do
	echo "==> building $n" >&2
	obj=build-$n
	dst=$out/$n
	mkdir -p "$obj" "$dst"
	rm -f "$dst/coreboot.rom" "$obj/.config"
	cp "$out/.defconfigs/$n" "$obj/defconfig"
	if ! { make obj="$obj" DOTCONFIG="$obj/.config" KBUILD_DEFCONFIG="$obj/defconfig" defconfig &&
	       make obj="$obj" DOTCONFIG="$obj/.config" -j"$jobs"; } >"$dst/build.log" 2>&1; then
		tail -n 30 "$dst/build.log" >&2
		fail+=("$n"); continue
	fi
	# Kconfig silently drops symbols whose dependencies are unmet.
	missing=$(grep "^CONFIG_" "$obj/defconfig" | grep -vxF -f "$obj/.config" || true)
	if [[ -n $missing ]]; then
		printf "%s: not in resulting .config:\n%s\n" "$n" "$missing" >&2
		fail+=("$n"); continue
	fi
	cp "$obj/coreboot.rom" "$dst/coreboot.rom"
	cp "$obj/.config" "$dst/config"
done
if ((${#fail[@]})); then echo "FAILED: ${fail[*]}" >&2; exit 1; fi
'

run_inner() {
	case $CONTAINER_ENGINE in
	none)
		(cd "$cb" && bash -c "$inner" inner "$@") ;;
	docker|podman)
		local user=(--user "$(id -u):$(id -g)")
		[[ $CONTAINER_ENGINE == podman ]] && user=(--userns=keep-id)
		"$CONTAINER_ENGINE" run --rm "${user[@]}" -e HOME=/tmp \
			-v "$cache:$cache:z" -w "$cb" "$image" bash -c "$inner" inner "$@" ;;
	*)
		echo "bad CONTAINER_ENGINE $CONTAINER_ENGINE" >&2; exit 1 ;;
	esac
}

checkout "$@"
payloads
mkdir -p "$out/.defconfigs"
for n in "$@"; do
	cfg=$here/configs/$n.defconfig
	arch=$(sed -n 's/^# payload-arch: //p' "$cfg")
	mkdir -p "$out/$n"
	cp "$out/payloads/$arch-a.elf" "$out/$n/payload.elf"
	# The non-x86 default FMAP has no RO_VPD, so such fixtures bring a layout.
	[[ -f $here/configs/$n.fmd ]] && cp "$here/configs/$n.fmd" "$out/$n/layout.fmd"
	sed -e "s|@PAYLOAD@|$out/$n/payload.elf|" -e "s|@FMD@|$out/$n/layout.fmd|" "$cfg" >"$out/.defconfigs/$n"
done
run_inner "$out" "$jobs" "$@"
git -C "$cb" rev-parse HEAD >"$out/COREBOOT_REV"
log "fixtures in $out: $*"
