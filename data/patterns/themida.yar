/*
 * Themida / Code Virtualizer detection rules
 * ===========================================
 * Matches VM entry points and handler patterns for
 * Themida 2.x and 3.x / Code Virtualizer.
 *
 * B81: Initial rule set.
 */

rule Themida_2x_Entry {
    meta:
        description = "Themida 2.x VM entry (pushfd + pushad + call $+5 + pop)"
        protector = "Themida"
        version = "2.x"
        confidence = 80
    strings:
        $entry = { 9C 60 E8 00 00 00 00 5? }
    condition:
        $entry
}

rule Themida_3x_Entry {
    meta:
        description = "Themida 3.x VM entry (call + add/sub esp)"
        protector = "Themida"
        version = "3.x"
        confidence = 80
    strings:
        $call_fixup = { E8 ?? ?? ?? ?? (83|81) C4 }
    condition:
        $call_fixup
}

rule CodeVirtualizer_Handler {
    meta:
        description = "Code Virtualizer generic handler dispatch"
        protector = "CodeVirtualizer"
        version = "generic"
        confidence = 70
    strings:
        $cv_fetch = { 8B ?? [0-4] 0F B6 ?? [0-16] FF }
    condition:
        $cv_fetch
}
