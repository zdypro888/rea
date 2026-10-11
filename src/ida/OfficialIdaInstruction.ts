/** Fixed read-only IDAPython query; caller data is encoded by officialIdaQuery. */
export const officialIdaInstruction = `ea = int(args['address'], 16)
f = ida_funcs.get_func(ea)
flags = ida_bytes.get_full_flags(ea)
limits = ['Operand memory addressing and per-instruction execution mode are unavailable.', 'References describe the IDA database, not observed runtime destinations.']
result = {'address': hex(ea), 'status': 'undecodable', 'procedure': ida_name.get_name(f.start_ea) if f else None, 'architecture': ida_ida.inf_get_procname() or 'unknown', 'mode': 'unavailable', 'bytes': None, 'length': None, 'mnemonic': None, 'raw_disassembly': None, 'operands': [], 'flow': {'kind': 'unavailable', 'conditional': False, 'computed': False, 'direct_destinations': []}, 'references': [], 'limitations': limits}
if not ida_bytes.is_mapped(ea):
    result['status'] = 'outside-memory'
elif ida_bytes.is_tail(flags):
    result['status'] = 'not-instruction-boundary'
elif ida_bytes.is_data(flags):
    result['status'] = 'data'
elif ida_bytes.is_code(flags):
    insn = ida_ua.insn_t()
    size = ida_ua.decode_insn(insn, ea)
    if size > 0:
        data = ida_bytes.get_bytes(ea, size)
        result.update(status='decoded', length=size, bytes=data.hex() if data is not None else None, mnemonic=ida_ua.print_insn_mnem(ea), raw_disassembly=ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or ''))
        for op in insn.ops:
            if op.type == ida_ua.o_void:
                break
            raw = ida_lines.tag_remove(ida_ua.print_operand(ea, op.n) or '')
            width = ida_ua.get_dtype_size(op.dtype)
            component = {'kind': 'unknown', 'text': raw, 'value': None, 'bit_width': width * 8 if width > 0 else None}
            if op.type == ida_ua.o_reg and width > 0:
                component.update(kind='register', value=ida_idp.get_reg_name(op.reg, width))
            elif op.type == ida_ua.o_imm:
                component.update(kind='immediate', value=hex(op.value))
            elif op.type in (ida_ua.o_near, ida_ua.o_far, ida_ua.o_mem):
                component.update(kind='address', value=hex(op.addr))
            result['operands'].append({'index': op.n, 'raw': raw, 'provider_type': op.type, 'components': [component], 'memory_addressing': 'unavailable'})
        call = bool(ida_idp.is_call_insn(insn))
        ret = bool(ida_idp.is_ret_insn(insn))
        indirect_jump = bool(ida_idp.is_indirect_jump_insn(insn))
        computed = indirect_jump or (call and not any(op.type in (ida_ua.o_near, ida_ua.o_far) for op in insn.ops))
        refs = list(idautils.XrefsFrom(ea))
        jump = indirect_jump or any(x.type in (ida_xref.fl_JN, ida_xref.fl_JF) for x in refs)
        falls = any(x.type == ida_xref.fl_F for x in refs)
        destinations = []
        for x in refs:
            is_call = x.type in (ida_xref.fl_CN, ida_xref.fl_CF)
            is_jump = x.type in (ida_xref.fl_JN, ida_xref.fl_JF)
            if is_call or is_jump:
                destinations.append(hex(x.to))
            result['references'].append({'target_address': hex(x.to), 'source_address': hex(x.frm), 'type': str(x.type), 'call': is_call, 'jump': is_jump, 'indirect': computed if is_call or is_jump else False, 'computed': computed if is_call or is_jump else False, 'operand_index': -1, 'data': not x.iscode, 'read': x.type == ida_xref.dr_R, 'write': x.type == ida_xref.dr_W, 'provenance': 'IDA XrefsFrom'})
        feature = insn.get_canon_feature()
        kind = 'call' if call else 'return' if ret else 'jump' if jump else 'terminal' if feature & ida_idp.CF_STOP else 'fallthrough'
        result['flow'] = {'kind': kind, 'conditional': jump and falls, 'computed': computed, 'direct_destinations': [] if computed else destinations, 'classification_evidence': [{'source': 'IDA processor instruction predicates and XrefsFrom', 'value': str(feature)}]}
return result`;
