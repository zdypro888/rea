import { AnalysisProtocolError } from "../domain/analysisErrorCore.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { officialIdaInstruction } from "./OfficialIdaInstruction.js";

const queryBodies: Readonly<Record<string, string>> = {
  inspect_instruction: officialIdaInstruction,
  server_health: "return health()",
  analysis_advance: `steps = 0
deadline = time.monotonic() + args['budget_ms'] / 1000
if not ida_ida.inf_is_auto_enabled():
    raise RuntimeError('IDA automatic analysis is disabled')
while not ida_auto.auto_is_ok() and time.monotonic() < deadline:
    if ida_kernwin.user_cancelled() or not ida_auto.auto_make_step(0, ida_idaapi.BADADDR):
        break
    steps += 1
return {'steps': steps, 'health': health()}`,
  list_funcs: `q = args['queries']
offset, count = q['offset'], q['count']
entries = list(itertools.islice(idautils.Functions(), offset, offset + count + 1))
end = offset + count
return [{'data': [describe(ida_funcs.get_func(ea)) for ea in entries[:count]], 'next_offset': end if len(entries) > count else None}]`,
  lookup_funcs: `q = args['queries'][0]
ea = int(q, 16) if q.lower().startswith('0x') else ida_name.get_name_ea(ida_idaapi.BADADDR, q)
f = ida_funcs.get_func(ea)
return [{'query': q, 'fn': describe(f), 'error': None if f else 'Function not found'}]`,
  decompile: `ea = int(args['addr'], 16)
f = ida_funcs.get_func(ea)
if not f or f.start_ea != ea:
    raise RuntimeError('Decompile target is not a canonical function entry')
if not ida_hexrays.init_hexrays_plugin():
    raise RuntimeError('Hex-Rays decompiler is unavailable')
cfunc = ida_hexrays.decompile(ea)
if cfunc is None:
    raise RuntimeError('Hex-Rays decompilation failed')
lines = []
for line in cfunc.get_pseudocode():
    text = ida_lines.tag_remove(line.line)
    head, item, tail = ida_hexrays.ctree_item_t(), ida_hexrays.ctree_item_t(), ida_hexrays.ctree_item_t()
    if cfunc.get_line_item(line.line, 0, False, head, item, tail):
        location = (item.dstr() or '').split(': ')
        if len(location) == 2:
            try:
                text += ' /*' + hex(int(location[0], 16)) + '*/'
            except ValueError:
                pass
    lines.append(text)
offset, count = args['offset'], args['max_lines']
end = offset + count
code = '\\n'.join(lines[offset:end])
return {'addr': hex(ea), 'code': code, 'total_lines': len(lines), 'line_count': len(lines[offset:end]), 'cursor': {'next': end} if end < len(lines) else {'done': True}}`,
  disasm: `f = ida_funcs.get_func(int(args['addr'], 16))
if not f:
    raise RuntimeError('Function not found')
items = [ea for ea in idautils.FuncItems(f.start_ea) if ida_bytes.is_code(ida_bytes.get_full_flags(ea))]
offset, count = args['offset'], args['max_instructions']
end = offset + count
return {'asm': {'name': ida_name.get_name(f.start_ea), 'start_ea': hex(f.start_ea), 'lines': [{'addr': hex(ea), 'instruction': ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or '')} for ea in items[offset:end]]}, 'cursor': {'next': end} if end < len(items) else {'done': True}}`,
  find_regex: `if args['pattern'] != '(?s).*':
    raise RuntimeError('This adapter only enumerates strings; REA owns matching')
offset, count = args['offset'], args['limit']
items = list(itertools.islice(idautils.Strings(), offset, offset + count + 1))
end = offset + count
return {'matches': [{'addr': hex(s.ea), 'string': str(s)} for s in items[:count]], 'cursor': {'next': end} if len(items) > count else {'done': True}}`,
  xrefs_to: `ea = int(args['addrs'][0], 16)
items = list(idautils.XrefsTo(ea))
limit = args['limit']
return [{'xrefs': [{'addr': hex(x.frm), 'type': 'code' if x.iscode else 'data', 'fn': describe(ida_funcs.get_func(x.frm))} for x in items[:limit]], 'more': len(items) > limit}]`,
  callees: `f = ida_funcs.get_func(int(args['addrs'][0], 16))
if not f:
    raise RuntimeError('Function not found')
targets = {}
for ea in idautils.FuncItems(f.start_ea):
    for x in idautils.XrefsFrom(ea):
        if x.type not in (ida_xref.fl_CN, ida_xref.fl_CF):
            continue
        callee = ida_funcs.get_func(x.to)
        entry = callee.start_ea if callee else x.to
        targets[entry] = {'addr': hex(entry), 'name': ida_name.get_name(entry) or hex(entry), 'type': 'internal' if callee else 'external'}
items = list(targets.values())
limit = args['limit']
return [{'callees': items[:limit], 'more': len(items) > limit}]`,
};

/** Caller data is JSON, never interpolated as executable Python. No arbitrary code API. */
export const officialIdaQuery = (
  name: string,
  args: Readonly<Record<string, JsonValue>>,
): string => {
  const body = queryBodies[name];
  if (body === undefined)
    throw new AnalysisProtocolError(
      `Unsupported official IDA read-only query: ${name}`,
    );
  return `import json, time, os, itertools
import idaapi, ida_idaapi, ida_ida, ida_auto, ida_kernwin, ida_nalt, ida_loader
import ida_funcs, ida_name, ida_hexrays, ida_lines, ida_bytes, ida_xref, idautils
import ida_ua, ida_idp
def _rea_query():
    args = json.loads(${JSON.stringify(JSON.stringify(args))})
    def describe(f):
        return {'addr': hex(f.start_ea), 'name': ida_name.get_name(f.start_ea) or hex(f.start_ea), 'size': hex(f.end_ea - f.start_ea)} if f else None
    def health():
        return {'status': 'ok', 'input_path': os.path.realpath(ida_nalt.get_input_file_path()), 'idb_path': ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 'imagebase': hex(ida_nalt.get_imagebase()), 'module': ida_nalt.get_root_filename(), 'auto_analysis_ready': bool(ida_auto.auto_is_ok()), 'ida_version': idaapi.get_kernel_version()}
${body
  .split("\n")
  .map((line) => `    ${line}`)
  .join("\n")}
_rea_query()`;
};
