/*
 * VMProtect version-specific detection rules
 * ==========================================
 * Matches handler prologues and dispatcher patterns for
 * VMProtect 3.0, 3.1, 3.5, and 3.8+ versions.
 *
 * B81: Initial rule set — contributed by pattern analysis.
 */

rule VMP_30_Handler_Prologue {
    meta:
        description = "VMProtect 3.0.x handler prologue (pushad + large immediate)"
        protector = "VMProtect"
        version = "3.0.x"
        confidence = 85
    strings:
        $prologue = { 60 [0-8] B8 ?? ?? ?? ?? }
    condition:
        $prologue
}

rule VMP_31_Handler_Prologue {
    meta:
        description = "VMProtect 3.1.x handler prologue (push reg + xor key + jmp)"
        protector = "VMProtect"
        version = "3.1.x"
        confidence = 85
    strings:
        $push_xor = { 5? 81 (F0|F1|F2|F3|F4|F5|F6|F7) ?? ?? ?? ?? (E9|EB) }
    condition:
        $push_xor
}

rule VMP_35_Handler_Prologue {
    meta:
        description = "VMProtect 3.5.x handler prologue (push + LEA context switch)"
        protector = "VMProtect"
        version = "3.5.x"
        confidence = 80
    strings:
        $push_lea = { 5? 48 (8D|89) ?? [0-8] }
    condition:
        $push_lea
}

rule VMP_38_Extended_Dispatch {
    meta:
        description = "VMProtect 3.8.x extended 64-bit dispatch (MOV + indirect)"
        protector = "VMProtect"
        version = "3.8.x"
        confidence = 75
    strings:
        $dispatch = { 4? 8B ?? 48 [1-8] FF }
    condition:
        $dispatch
}

rule VMP_Dispatcher_Loop {
    meta:
        description = "VMProtect generic dispatcher loop (movzx + dispatch jump)"
        protector = "VMProtect"
        version = "generic"
        confidence = 70
    strings:
        $movzx_jmp = { 0F B6 ?? [0-16] FF (24|64) }
    condition:
        $movzx_jmp
}
