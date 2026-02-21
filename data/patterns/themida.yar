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

rule Themida_2x_VM_Init {
    meta:
        description = "Themida 2.x VM context initialisation (pushad + mov ebp,esp)"
        protector = "Themida"
        version = "2.x"
        confidence = 75
    strings:
        $init = { 60 8B EC [0-8] 83 EC }
    condition:
        $init
}

rule Themida_3x_Dolphin {
    meta:
        description = "Themida 3.x Dolphin VM variant (LEA + XOR init)"
        protector = "Themida"
        version = "3.x"
        confidence = 75
    strings:
        $dolphin = { 48 8D ?? ?? ?? ?? ?? 48 33 ?? E8 }
    condition:
        $dolphin
}

rule Themida_3x_Tiger {
    meta:
        description = "Themida 3.x Tiger VM variant (SUB RSP + MOV chain)"
        protector = "Themida"
        version = "3.x"
        confidence = 70
    strings:
        $tiger = { 48 83 EC ?? 48 89 ?? ?? 48 89 ?? ?? 48 89 }
    condition:
        $tiger
}

rule CodeVirtualizer_2x_Dispatch {
    meta:
        description = "Code Virtualizer 2.x dispatch loop (LODSB + XLAT pattern)"
        protector = "CodeVirtualizer"
        version = "2.x"
        confidence = 70
    strings:
        $lodsb_xlat = { AC D7 [0-8] FF }
    condition:
        $lodsb_xlat
}

rule CodeVirtualizer_3x_Dispatch {
    meta:
        description = "Code Virtualizer 3.x dispatch with handler table"
        protector = "CodeVirtualizer"
        version = "3.x"
        confidence = 70
    strings:
        $cv3_dispatch = { 0F B6 ?? 48 8B ?? ?? ?? ?? ?? FF }
    condition:
        $cv3_dispatch
}
