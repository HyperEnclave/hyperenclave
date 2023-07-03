ENTRY(arch_entry)

BASE_ADDRESS = 0xffffff0000000000;

SECTIONS
{
	. = BASE_ADDRESS;

	.header		: {
		__header_start = .;
		KEEP(*(.header))
	}

	. = ALIGN(4K);
	.bss		: { *(.bss .bss.*) *(COMMON) }

	. = ALIGN(16);
	.text		: { *(.text .text.*) }

	. = ALIGN(16);
	.rodata		: { *(.rodata .rodata.*) }

	. = ALIGN(16);
	.data		: { *(.data .data.*) }

	. = ALIGN(4K);
	.got		: { *(.got .got.*) }

	. = ALIGN(4K);
	__core_end = .;

	__entry_offset = arch_entry - BASE_ADDRESS;
	__core_size = __core_end - BASE_ADDRESS;

	/DISCARD/ : { *(.comment) *(.gnu*) *(.note*) *(.eh_frame*) }
}
