# Relocation test object for Alpha_ElfRelocationHandler (test/reloc-check.sh).
# Covers the gp-relative relocations of relocatable objects (GPDISP, LITERAL, LITUSE,
# GPREL16, GPRELHIGH/GPRELLOW, GPREL32, BRSGP) and the plain data/branch ones.
	.set noreorder
	.set noat
	.text
	.globl _start
	.ent _start
_start:
	ldah $29, 0($27)	!gpdisp!1
	lda $29, 0($29)		!gpdisp!1
	.prologue 1
	ldq $1, extvar($29)	!literal!2
	ldl $2, 0($1)		!lituse_base!2
	ldq $3, localvar($29)	!literal!3
	ldq $4, 0($3)		!lituse_base!3
	ldq $27, extfunc($29)	!literal!4
	jsr $26, ($27), extfunc	!lituse_jsr!4
	ldah $29, 0($26)	!gpdisp!5
	lda $29, 0($29)		!gpdisp!5
	lda $5, smallvar($29)	!gprel
	ldl $6, smallvar+4($29)	!gprel
	ldah $7, bigvar($29)	!gprelhigh
	lda $7, bigvar($7)	!gprellow
	ldah $8, bigvar+16($29)	!gprelhigh
	ldq $8, bigvar+16($8)	!gprellow
	bsr $26, helper		!samegp
	br $31, 1f
1:	jsr $26, ($27), helper
	ret $31, ($26), 1
	.end _start

	.globl helper
	.ent helper
helper:
	ldah $29, 0($27)	!gpdisp!6
	lda $29, 0($29)		!gpdisp!6
	.prologue 1
	ldq $1, localvar($29)	!literal!7
	ldq $2, extvar($29)	!literal!8
	ret $31, ($26), 1
	.end helper

	.data
	.align 3
localvar:
	.quad 0x1122334455667788
	.quad helper
	.quad extvar
	.long localvar
	.gprel32 smallvar
	.gprel32 bigvar
	.long 0
	.quad localvar - .

	.section .sdata,"aw"
	.align 3
smallvar:
	.quad 7
	.quad 8

	.section .bss
	.align 3
bigvar:
	.space 0x30000
