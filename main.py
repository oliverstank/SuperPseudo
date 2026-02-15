"""
Super Pseudo - Main Entry Point
IDA Pro Plugin for recursive function inlining
"""

import ida_idaapi
import ida_kernwin
import ida_hexrays

# Import the plugin implementation
from super_pseudo import SuperPseudoActionHandler, SuperPseudoGenerator
from blacklist import ToggleActionHandler

class PseudocodePopupHooks(ida_kernwin.UI_Hooks):
    """Hooks to add our action to the pseudocode context menu"""

    def __init__(self):
        ida_kernwin.UI_Hooks.__init__(self)

    def finish_populating_widget_popup(self, widget, popup, ctx):
        """Called when a popup menu is about to be shown"""
        # Check if this is a pseudocode widget
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # Attach our action to the popup menu
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                'superpseudo:inline',
                'Super Pseudo/',
                ida_kernwin.SETMENU_APP
            )
            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                'superpseudo:toggle',
                'Super Pseudo/',
                ida_kernwin.SETMENU_APP
            )
        return 0


class SuperPseudoPlugin(ida_idaapi.plugin_t):
    """
    Plugin loader class for IDA Pro
    """
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Recursively inline function calls in pseudocode"
    help = "Super Pseudo - Inline all function calls recursively"
    wanted_name = "Super Pseudo"

    def __init__(self):
        ida_idaapi.plugin_t.__init__(self)
        self.hooks = None
        self.action_name = 'superpseudo:inline'

    def init(self):
        """Initialize the plugin"""
        # Check if decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            print("[Super Pseudo] Hex-Rays decompiler is not available")
            return ida_idaapi.PLUGIN_SKIP

        # Register action
        action_desc = ida_kernwin.action_desc_t(
            self.action_name,
            'Super Pseudo: Inline Functions',
            SuperPseudoActionHandler(),
            'Ctrl-Shift-I',
            'Recursively inline function calls in pseudocode',
            -1
        )

        toggle_action_desc = ida_kernwin.action_desc_t(
            "superpseudo:toggle",
            'Super Pseudo: Toggle Inline Block',
            ToggleActionHandler(),
            'Ctrl-Shift-J',
            'Select whether the function should be inlined or not',
            -1
        )

        commands = [action_desc, toggle_action_desc]

        for command in commands:
            if not ida_kernwin.register_action(command):
                print("[Super Pseudo] Failed to register command")
                return ida_idaapi.PLUGIN_SKIP

        # Install UI hooks to add menu item to pseudocode popup
        if self.hooks is None:
            self.hooks = PseudocodePopupHooks()
            self.hooks.hook()

        print("=" * 60)
        print("Super Pseudo plugin loaded successfully!")
        print("Usage:")
        print("  - Press Ctrl-Shift-I in pseudocode view")
        print("  - Right-click in pseudocode -> Super Pseudo: Inline Functions")
        print("=" * 60)

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        """Run the plugin (when hotkey is pressed outside of action)"""
        # When the hotkey is pressed, IDA will invoke the action directly
        pass

    def term(self):
        """Cleanup when plugin is unloaded"""
        print("[Super Pseudo] Unloading plugin...")

        # Unhook UI hooks
        if self.hooks is not None:
            self.hooks.unhook()
            self.hooks = None

        # Unregister action
        ida_kernwin.unregister_action(self.action_name)


def PLUGIN_ENTRY():
    """Plugin entry point called by IDA"""
    return SuperPseudoPlugin()
