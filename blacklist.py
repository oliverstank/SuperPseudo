import ida_kernwin
import ida_funcs
import ida_hexrays
import ida_bytes
import idc
import json
import os

BLACKLIST_PATH = "sp_blacklist.json"

def get_blacklist():
    if os.path.exists(BLACKLIST_PATH):
        with open(BLACKLIST_PATH, "r", encoding="utf-8") as f:
            try: 
                json
                return json.load(f)
            except json.JSONDecodeError:
                with open(BLACKLIST_PATH, "w", encoding="utf-8") as fw:
                    json.dump([], fw, indent=4, ensure_ascii=False)
                return []
    else:
        with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
            json.dump([], f, indent=4, ensure_ascii=False)
        return []

def blacklist_contains(func):
    blacklist = get_blacklist()
    return func in blacklist

def update_blacklist(func):
    blacklist = get_blacklist()
    if func in blacklist:
        blacklist.remove(func)
    else:
        blacklist.append(func)
    
    with open(BLACKLIST_PATH, "w", encoding="utf-8") as f:
        json.dump(blacklist, f, indent=4, ensure_ascii=False)

def get_call():
    if not ida_hexrays.init_hexrays_plugin():
        return

    vu = ida_hexrays.get_widget_vdui(ida_kernwin.get_current_viewer())
    if not vu or not vu.cfunc:
        return
    
    # not a citem
    if not vu.item.is_citem():
        return

    ni = ida_hexrays.citem_to_specific_type(vu.item.it)

    if isinstance(ni, ida_hexrays.cexpr_t):
        ea = ni.obj_ea

        # cot_call only marks the opening bracket character, otherwise it is cot_obj
        if ni.op == ida_hexrays.cot_call:
            callee = ida_hexrays.citem_to_specific_type(ni.x)
            if callee.op == ida_hexrays.cot_obj:
                return idc.get_func_name(callee.obj_ea)

        # check if the cot_obj is a function itself
        elif ni.op == ida_hexrays.cot_obj and ida_funcs.get_func(ea) is not None:
            return idc.get_func_name(ea)

        else:
            return
    else:
        # sometimes cinsn_t is selected instead of cexpr_t
        return

class ToggleActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        call = get_call()
        if call is not None:
            update_blacklist(call)
            print("Super Pseudo: Exclusion list updated to:", get_blacklist())


    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS