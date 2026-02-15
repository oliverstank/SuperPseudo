# Super Pseudo - IDA Pro Plugin

Recursively inlines function calls in decompiled pseudocode for deeper code analysis.

## Overview

Super Pseudo is an IDA Pro plugin that leverages the Hex-Rays decompiler to recursively inline all function calls within pseudocode. This provides a comprehensive view of code execution by expanding nested function calls to a configurable depth.

## Features

- **Recursive Inlining**: Automatically inlines all function calls found in decompiled pseudocode
- **Cycle Detection**: Prevents infinite recursion by tracking visited functions
- **Configurable Depth**: Control inlining depth (default: 3 levels)
- **AST-Based Analysis**: Uses Hex-Rays ctree visitor for accurate function call detection
- **Adjustable Inlining Range**: Prevent inlining selected functions (e.g. standard library calls like `fwrite()`)
  
![gif](./gif.gif)

## Requirements

- IDA Pro 9.0 or later
- Hex-Rays Decompiler
- Python 3.x (bundled with IDA)

## Installation

Place the directory into the `plugins/` directory of your IDA path

## Usage

### Method 1: Keyboard Shortcut
1. Open a function in the Hex-Rays decompiler view
2. Press **Ctrl-Shift-I** or **right click > super psuedo**
3. A new window will open showing the inlined pseudocode

### Method 2: Context Menu
1. Right-click in the pseudocode view
2. Navigate to **Super Pseudo** → **Inline Functions**
3. View the results in the new window

## How It Works

1. **AST Traversal**: The plugin uses `ctree_visitor_t` to traverse the decompiler's abstract syntax tree (AST)
2. **Call Detection**: Identifies all `cot_call` expression nodes (function calls)
3. **Recursive Decompilation**: Each called function is decompiled and processed recursively
4. **Cycle Prevention**: Maintains a set of visited functions to prevent infinite loops
5. **Output Generation**: Combines original code with inlined function bodies in comment blocks

## Output Format

The generated output includes:

```c
// ========== SUPER PSEUDO ==========
// Inlining depth: 3
// Functions inlined: 2

void target_function() {
  int result = helper_function(5);

  // ========== BEGIN INLINED: helper_function (depth 1) ==========
  // int helper_function(int x) {
  //   return x * 2 + utility_func(x);
  //
  //   // ========== BEGIN INLINED: utility_func (depth 2) ==========
  //   // int utility_func(int y) {
  //   //   return y + 1;
  //   // }
  //   // ========== END INLINED: utility_func ==========
  // }
  // ========== END INLINED: helper_function ==========

  return result;
}

// Total inline operations: 2
// ========== END SUPER PSEUDO ==========
```

## Configuration

The plugin can be configured by editing `config.py`:

```python
# Default inlining depth (can be overridden at runtime)
DEFAULT_DEPTH = 3

# Maximum allowed depth (to prevent performance issues)
MAX_DEPTH = 10

# Whether to ask for depth every time (True) or use default (False)
ASK_DEPTH_EVERY_TIME = True

# Whether to preserve syntax highlighting in output
PRESERVE_SYNTAX_HIGHLIGHTING = True
```

### Configuration Options

**DEFAULT_DEPTH** (default: 3)
- The default inlining depth used when `ASK_DEPTH_EVERY_TIME` is False
- Can be any value between 1 and `MAX_DEPTH`

**MAX_DEPTH** (default: 10)
- Maximum inlining depth allowed
- Higher values may cause performance issues with complex code

**ASK_DEPTH_EVERY_TIME** (default: True)
- When True: Plugin prompts for depth each time you use it
- When False: Plugin uses `DEFAULT_DEPTH` automatically
- The dialog remembers your last input as the default for next time

**PRESERVE_SYNTAX_HIGHLIGHTING** (default: True)
- When True: Output preserves IDA's color-coded syntax highlighting
- When False: Output is plain text

### Blacklist configuration
You can exclude the function from inlining by selecting it (placing the cursor before the opening bracket)
and pressing `Ctrl+Shift+J` or choosing *"Super Pseudo > Toggle Inline Block"* from the context menu. You can also manually manage the blacklist by modyfying the JSON structure of `./sp_blacklist.json`, where `.` is the directory with your currently decompiled file.

### Quick Start Configurations

**For interactive use** (ask every time):
```python
ASK_DEPTH_EVERY_TIME = True
DEFAULT_DEPTH = 3  # Starting default
```

**For automated analysis** (no prompts):
```python
ASK_DEPTH_EVERY_TIME = False
DEFAULT_DEPTH = 5  # Always use depth 5
```

## Credits

Built using the IDA Pro Hex-Rays Decompiler API.

