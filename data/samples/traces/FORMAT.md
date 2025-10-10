# VMDragonSlayer Trace Format Specification

## Version 1.0

### File Structure

```
# Header comments (optional)
---
<trace lines>
---
```

### Line Formats

**Instruction Line:**
```
i: <address> | <size> | <bytes> | <disasm> | <registers>
```

**Memory Access:**
```
m: <R|W> | <address> | <size> | <value>
```

**Control Flow:**
```
c: <type> | <source> | <target>
```

**Handler Marker:**
```
h: <id> | <address> | <type>
```

### Examples

See sample_*.trace files in this directory.
