"""
Super Pseudo - IDA Pro Plugin
Recursively inlines function calls in decompiled pseudocode
"""

import ida_hexrays
import ida_kernwin
import ida_funcs
import ida_lines
import idc
from ida_hexrays import *
from blacklist import blacklist_contains

try:
    from . import config
except ImportError:
    class config:
        DEFAULT_DEPTH = 3
        MAX_DEPTH = 10
        ASK_DEPTH_EVERY_TIME = True
        PRESERVE_SYNTAX_HIGHLIGHTING = True


class FunctionInliner(ctree_visitor_t):
    def __init__(self, visited_funcs, depth, max_depth):
        ctree_visitor_t.__init__(self, CV_FAST)
        self.calls = []
        self.visited_funcs = visited_funcs
        self.depth = depth
        self.max_depth = max_depth

    def visit_expr(self, expr):
        if expr.op == cot_call:
            if expr.x.op == cot_obj:
                func_ea = expr.x.obj_ea
                if func_ea not in self.visited_funcs and self.depth < self.max_depth:
                    self.calls.append((func_ea, expr))
        return 0


class InlineInfo:
    def __init__(self, ea, name, cfunc):
        self.ea = ea
        self.name = name
        self.cfunc = cfunc
        self.args = []
        self.params = []


class SuperPseudoGenerator:
    def __init__(self, max_depth=3):
        self.max_depth = max_depth
        self.inline_count = 0

    def get_func_name(self, ea):
        name = idc.get_func_name(ea)
        if not name:
            name = f"sub_{ea:X}"
        return name

    def decompile_function(self, ea):
        try:
            cfunc = ida_hexrays.decompile(ea)
            return cfunc
        except ida_hexrays.DecompilationFailure:
            return None

    def get_expr_string(self, expr):
        printer = qstring()
        expr.print1(printer, None)
        return str(printer)

    def extract_function_body(self, cfunc):
        sv = cfunc.get_pseudocode()
        lines = []

        for i in range(len(sv)):
            line = ida_lines.tag_remove(sv[i].line)
            lines.append(line)

        if len(lines) > 2:
            body_lines = []
            for i in range(1, len(lines) - 1):
                line = lines[i].rstrip()
                if line.startswith('  '):
                    line = line[2:]
                body_lines.append(line)
            return body_lines
        return []

    def get_function_params(self, cfunc):
        params = []
        func_type = cfunc.type
        if func_type:
            for i in range(func_type.get_nargs()):
                arg_name = cfunc.lvars[i].name if i < len(cfunc.lvars) else f"arg{i}"
                params.append(arg_name)
        return params

    def get_function_pseudocode(self, ea, visited_funcs=None, depth=0, inline_simple=True, preserve_tags=True):
        if visited_funcs is None:
            visited_funcs = set()

        if ea in visited_funcs or depth >= self.max_depth:
            return None

        visited_funcs.add(ea)

        cfunc = self.decompile_function(ea)
        if not cfunc:
            visited_funcs.remove(ea)
            return None

        sv = cfunc.get_pseudocode()
        lines = []
        for i in range(len(sv)):
            if preserve_tags:
                line = sv[i].line
            else:
                line = ida_lines.tag_remove(sv[i].line)
            lines.append(line)

        visitor = FunctionInliner(visited_funcs, depth, self.max_depth)
        visitor.apply_to(cfunc.body, None)

        inlined_functions = {}
        for func_ea, call_expr in visitor.calls:
            func_name = self.get_func_name(func_ea)

            if depth == 0:
                print(f"[Super Pseudo] Found call to {func_name} at 0x{func_ea:X}")

            inlined_code = self.get_function_pseudocode(func_ea, visited_funcs.copy(), depth + 1, inline_simple, preserve_tags)
            if inlined_code:
                inlined_functions[func_ea] = {
                    'name': func_name,
                    'code': inlined_code,
                    'ea': func_ea,
                    'expr': call_expr
                }
                if depth == 0:
                    print(f"[Super Pseudo] Successfully inlined {func_name} ({len(inlined_code)} lines)")
            else:
                if depth == 0:
                    print(f"[Super Pseudo] Could not inline {func_name}")

        visited_funcs.remove(ea)

        if inlined_functions:
            result = []
            if depth == 0:
                result.append("// ========== SUPER PSEUDO ==========")
                result.append(f"// Inlining depth: {self.max_depth}")
                result.append(f"// Functions inlined: {len(inlined_functions)}")
                result.append("")

            inlined_on_line = set()

            for line in lines:
                result.append(line)
                line_plain = ida_lines.tag_remove(line) if preserve_tags else line

                for func_ea, inline_info in inlined_functions.items():
                    func_name = inline_info['name']
                    should_inline = False

                    if func_name + "(" in line_plain:
                        should_inline = True
                    elif func_name in line_plain and '=' in line_plain:
                        should_inline = True
                    else:
                        base_name = func_name.split('.')[-1].split('_')[-1]
                        if len(base_name) > 3 and base_name in line_plain:
                            should_inline = True
                    if (blacklist_contains(func_name)):
                        should_inline = False
                    if should_inline and func_ea not in inlined_on_line:
                        inlined_on_line.add(func_ea)
                        self.inline_count += 1

                        result.append("")
                        result.append(f"  // ========== BEGIN INLINED: {func_name} (depth {depth + 1}) ==========")

                        if isinstance(inline_info['code'], list):
                            for inline_line in inline_info['code']:
                                stripped = ida_lines.tag_remove(inline_line).strip() if preserve_tags else inline_line.strip()
                                if stripped:
                                    result.append("  " + inline_line)
                        else:
                            for inline_line in inline_info['code'].split('\n'):
                                if inline_line.strip():
                                    result.append("  " + inline_line)

                        result.append(f"  // ========== END INLINED: {func_name} ==========")
                        result.append("")

                inlined_on_line.clear()

            if depth == 0:
                result.append("")
                result.append(f"// Total inline operations: {self.inline_count}")
                result.append("// ========== END SUPER PSEUDO ==========")

            return result
        else:
            return lines


class SuperPseudoActionHandler(ida_kernwin.action_handler_t):
    last_depth = config.DEFAULT_DEPTH

    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)

        if not func:
            ida_kernwin.warning("Please position the cursor in a function")
            return 0

        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.warning("Hex-Rays decompiler is not available")
            return 0

        if config.ASK_DEPTH_EVERY_TIME:
            depth = ida_kernwin.ask_long(
                SuperPseudoActionHandler.last_depth,
                f"Enter maximum inlining depth (1-{config.MAX_DEPTH}):"
            )

            if depth is None:
                return 0

            if depth < 1:
                depth = 1
            elif depth > config.MAX_DEPTH:
                ida_kernwin.warning(f"Maximum depth is {config.MAX_DEPTH}. Using {config.MAX_DEPTH}.")
                depth = config.MAX_DEPTH

            SuperPseudoActionHandler.last_depth = depth
        else:
            depth = config.DEFAULT_DEPTH

        func_name = idc.get_func_name(func.start_ea)
        print(f"[Super Pseudo] Generating super pseudocode for {func_name} (depth: {depth})...")
        generator = SuperPseudoGenerator(max_depth=depth)
        pseudocode_lines = generator.get_function_pseudocode(func.start_ea, preserve_tags=config.PRESERVE_SYNTAX_HIGHLIGHTING)

        if not pseudocode_lines:
            ida_kernwin.warning("Failed to generate super pseudocode")
            return 0

        self.show_pseudocode(func_name, pseudocode_lines, depth)
        print(f"[Super Pseudo] Done! {generator.inline_count} function(s) inlined.")

        return 1

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

    def show_pseudocode(self, func_name, pseudocode_lines, depth):
        title = f"Super Pseudo: {func_name} [depth={depth}]"

        widget = ida_kernwin.find_widget(title)
        if widget:
            ida_kernwin.close_widget(widget, 0)

        viewer = ida_kernwin.simplecustviewer_t()
        if viewer.Create(title):
            for line in pseudocode_lines:
                viewer.AddLine(line)
            viewer.Show()