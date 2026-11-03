"""Isolated static-analysis harness. Never loads the dylib into the host process."""
import json
import struct
import lief
import unicorn as U
from unicorn.arm64_const import *


class Harness:
    def __init__(self, path, verbose=False):
        self.binary = lief.MachO.parse(str(path)).at(0)
        self.uc = U.Uc(U.UC_ARCH_ARM64, U.UC_MODE_ARM)
        self.imports = {}
        self.import_addrs = {}
        self.verbose = verbose
        self.events = []
        self.overrides = {}
        self.objects = {}
        self.heap = 0x300000000
        self.uc.mem_map(self.heap, 0x100000)
        self.uc.mem_map(0x400000000, 0x100000)
        self.uc.mem_map(0x500000000, 0x10000)
        for seg in self.binary.segments:
            if seg.virtual_size:
                self.uc.mem_map(seg.virtual_address, (seg.virtual_size + 0xfff) & ~0xfff)
                if seg.file_size:
                    self.uc.mem_write(seg.virtual_address, bytes(seg.content))
        for reloc in self.binary.relocations:
            if hasattr(reloc, 'target'):
                self.putptr(reloc.address, reloc.target)
        for binding in self.binary.dyld_chained_fixups.bindings:
            name = binding.symbol.name
            if name not in self.import_addrs:
                a = 0x500000000 + len(self.import_addrs) * 8
                self.import_addrs[name] = a
                self.imports[a] = name
            self.putptr(binding.address, self.import_addrs[name] + binding.addend)
        self.uc.hook_add(U.UC_HOOK_CODE, self.hook)
        self.defaults = self.obj({'class': 'NSUserDefaults'})
        self.prefs = {}
        self.last_pc = 0

    def reg(self, n):
        return self.uc.reg_read(UC_ARM64_REG_X0 + n)

    def setreg(self, n, v):
        self.uc.reg_write(UC_ARM64_REG_X0 + n, v & 0xffffffffffffffff)

    def ptr(self, a):
        return struct.unpack('<Q', self.uc.mem_read(a, 8))[0]

    def putptr(self, a, v):
        self.uc.mem_write(a, struct.pack('<Q', v & 0xffffffffffffffff))

    def cstr(self, a):
        try:
            data = bytes(self.uc.mem_read(a, 160)).split(b'\0')[0]
            return data.decode('utf8')
        except Exception:
            return f'<{a:#x}>'

    def describe(self, a):
        if a in self.objects:
            return self.objects[a]
        if a in self.imports:
            return self.imports[a]
        if a == 0:
            return None
        try:
            isa = self.ptr(a)
            if self.imports.get(isa, '') == '___CFConstantStringClassReference':
                return self.cstr(self.ptr(a + 16))
        except Exception:
            pass
        return f'<{a:#x}>'

    def obj(self, value):
        a = self.heap
        self.heap += 0x100
        self.objects[a] = value
        return a

    def emit(self, *event):
        self.events.append(event)
        if self.verbose:
            print(*event)

    def hook(self, uc, pc, size, user):
        self.last_pc = pc
        if pc in self.overrides:
            self.setreg(0, self.overrides[pc])
            uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))
            return
        if pc not in self.imports:
            instruction = struct.unpack('<I', uc.mem_read(pc, 4))[0]
            if instruction & 0xffe0001f == 0xd4000001:
                # Only emulate Darwin PT_DENY_ATTACH; no host syscall is executed.
                number = uc.reg_read(UC_ARM64_REG_X16)
                direct = number == 26 and self.reg(0) == 31
                indirect = number == 0 and self.reg(0) == 26 and self.reg(1) == 31
                if direct or indirect:
                    self.setreg(0, 0)
                    uc.reg_write(UC_ARM64_REG_PC, pc + 4)
            return
        name = self.imports[pc]
        result = 0
        if name.startswith('_objc_retain') or name == '_objc_autoreleaseReturnValue':
            result = self.reg(0)
        elif name in ('_objc_release', '_objc_destroyWeak'):
            pass
        elif name in ('_objc_storeStrong', '_objc_storeWeak'):
            self.putptr(self.reg(0), self.reg(1))
        elif name == '_objc_msgSend':
            receiver = self.describe(self.reg(0))
            sel = self.cstr(self.reg(1))
            self.emit('objc', receiver, sel, self.describe(self.reg(2)))
            if sel == 'sectionWithIdentifier:':
                result = self.obj({'class': 'DVNSection', 'cells': [], 'identifier': self.describe(self.reg(2))})
            elif sel == 'standardUserDefaults':
                result = self.defaults
            elif sel == 'objectForKey:':
                key = self.describe(self.reg(2))
                result = self.prefs.get(key, 0) if isinstance(key, str) else 0
            elif sel == 'boolForKey:':
                key = self.describe(self.reg(2))
                result = int(bool(self.prefs.get(key, 0))) if isinstance(key, str) else 0
            elif sel == 'integerForKey:':
                key = self.describe(self.reg(2))
                result = int(self.prefs.get(key, 0)) if isinstance(key, str) else 0
            elif sel in ('init', 'copy', 'mutableCopy'):
                result = self.reg(0)
            elif sel == 'alloc':
                result = self.obj({'class': receiver})
            elif sel == 'stringWithUTF8String:':
                result = self.obj(self.cstr(self.reg(2)))
            elif sel == 'boolValue':
                result = int(bool(self.objects.get(self.reg(0))))
            elif sel == 'isEqualToString:':
                result = int(receiver == self.describe(self.reg(2)))
        elif name in ('_NSClassFromString', '_objc_getClass'):
            key = self.describe(self.reg(0)) if name == '_NSClassFromString' else self.cstr(self.reg(0))
            self.emit('class', key)
            result = self.obj({'class': key})
        elif name in ('_sel_registerName', '_NSSelectorFromString'):
            if name == '_sel_registerName':
                result = self.reg(0)
            else:
                value = self.describe(self.reg(0))
                result = self.heap
                self.heap += 0x100
                self.uc.mem_write(result, str(value).encode() + b'\0')
        elif name == '_dispatch_once':
            predicate, block = self.reg(0), self.reg(1)
            if self.ptr(predicate) != 0xffffffffffffffff:
                self.putptr(predicate, -1)
                self.setreg(0, block)
                uc.reg_write(UC_ARM64_REG_PC, self.ptr(block + 16))
                return
        elif name in ('_objc_sync_enter', '_objc_sync_exit'):
            pass
        else:
            self.emit('external', name)
        self.setreg(0, result)
        uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))

    def call(self, address, args=()):
        for i, arg in enumerate(args):
            self.setreg(i, arg)
        self.uc.reg_write(UC_ARM64_REG_SP, 0x400080000)
        self.uc.reg_write(UC_ARM64_REG_LR, 0x50000fff0)
        self.uc.reg_write(UC_ARM64_REG_FP, 0)
        try:
            self.uc.emu_start(address, 0x50000fff0, count=100000)
        except U.UcError as exc:
            raise RuntimeError(f'Emulation failed at {self.last_pc:#x}: {exc}') from exc
        if self.uc.reg_read(UC_ARM64_REG_PC) != 0x50000fff0:
            raise RuntimeError('Emulation did not return within its instruction budget')
        return self.reg(0)

