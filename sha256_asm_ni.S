.section	.rodata.cst256.K256, "aM", @progbits, 256
.align 64
K256:
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2

.section	.rodata.cst16.PSHUFFLE_BYTE_FLIP_MASK, "aM", @progbits, 16
.align 16
PSHUFFLE_BYTE_FLIP_MASK:
	.octa 0x0c0d0e0f08090a0b0405060700010203

.text
.global sha256_ni_transform
.type sha256_ni_transform, @function

sha256_ni_transform:

shl		$6, %rdx		/*  convert to bytes */
jz		.Ldone_hash
add		%rsi, %rdx		/* pointer to end of data */

/*
 * load initial hash values
 * Need to reorder these appropriately
 * DCBA, HGFE -> ABEF, CDGH
 */
movdqu		0*16(%rdi), %xmm1
movdqu		1*16(%rdi), %xmm2

pshufd		$0xB1, %xmm1, %xmm1	/* CDAB */
pshufd		$0x1B, %xmm2, %xmm2	/* EFGH */
movdqa		%xmm1, %xmm5
palignr		$8, %xmm2, %xmm1	/* ABEF */
pblendw		$0xF0, %xmm5, %xmm2	/* CDGH */

movdqa		PSHUFFLE_BYTE_FLIP_MASK(%rip), %xmm0
lea		K256(%rip), %rax

.Lloop0:
/* Save hash values for addition after rounds */
movdqa		%xmm1, %xmm9
movdqa		%xmm2, %xmm10

/* Rounds 0-3 */
movdqu		0*16(%rsi), %xmm3
pshufb		%xmm0, %xmm3
movdqa		%xmm3, %xmm4
paddd		0*16(%rax), %xmm3
sha256rnds2	%xmm1, %xmm2
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1

/* Rounds 4-7 */
movdqu		1*16(%rsi), %xmm3
pshufb		%xmm0, %xmm3
movdqa		%xmm3, %xmm4
paddd		1*16(%rax), %xmm3
sha256rnds2	%xmm1, %xmm2
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm4, %xmm3

/* Rounds 8-11 */
movdqu		2*16(%rsi), %xmm3
pshufb		%xmm0, %xmm3
movdqa		%xmm3, %xmm4
paddd		2*16(%rax), %xmm3
sha256rnds2	%xmm1, %xmm2
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm4, %xmm3

/* Rounds 12-15 */
movdqu		3*16(%rsi), %xmm3
pshufb		%xmm0, %xmm3
movdqa		%xmm3, %xmm4
paddd		3*16(%rax), %xmm3
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm3, %xmm6
palignr		$4, %xmm4, %xmm6
paddd		%xmm6, %xmm4
sha256msg2	%xmm3, %xmm4
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm6

/* Rounds 16-19 */
movdqa		%xmm4, %xmm3
paddd		4*16(%rax), %xmm4
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm4, %xmm6
palignr		$4, %xmm3, %xmm6
paddd		%xmm6, %xmm5
sha256msg2	%xmm4, %xmm5
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm4

/* Rounds 20-23 */
movdqa		%xmm5, %xmm3
paddd		5*16(%rax), %xmm5
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm5, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm6
sha256msg2	%xmm5, %xmm6
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm5

/* Rounds 24-27 */
movdqa		%xmm6, %xmm3
paddd		6*16(%rax), %xmm6
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm6, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm5
sha256msg2	%xmm6, %xmm5
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm6

/* Rounds 28-31 */
movdqa		%xmm5, %xmm3
paddd		7*16(%rax), %xmm5
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm5, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm6
sha256msg2	%xmm5, %xmm6
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm5

/* Rounds 32-35 */
movdqa		%xmm6, %xmm3
paddd		8*16(%rax), %xmm6
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm6, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm5
sha256msg2	%xmm6, %xmm5
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm6

/* Rounds 36-39 */
movdqa		%xmm5, %xmm3
paddd		9*16(%rax), %xmm5
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm5, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm6
sha256msg2	%xmm5, %xmm6
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm5

/* Rounds 40-43 */
movdqa		%xmm6, %xmm3
paddd		10*16(%rax), %xmm6
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm6, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm5
sha256msg2	%xmm6, %xmm5
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm6

/* Rounds 44-47 */
movdqa		%xmm5, %xmm3
paddd		11*16(%rax), %xmm5
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm5, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm6
sha256msg2	%xmm5, %xmm6
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm5

/* Rounds 48-51 */
movdqa		%xmm6, %xmm3
paddd		12*16(%rax), %xmm6
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm6, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm5
sha256msg2	%xmm6, %xmm5
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm6

/* Rounds 52-55 */
movdqa		%xmm5, %xmm3
paddd		13*16(%rax), %xmm5
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm5, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm6
sha256msg2	%xmm5, %xmm6
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1
sha256msg1	%xmm3, %xmm5

/* Rounds 56-59 */
movdqa		%xmm6, %xmm3
paddd	14*16(%rax), %xmm6
sha256rnds2	%xmm1, %xmm2
movdqa		%xmm6, %xmm4
palignr		$4, %xmm3, %xmm4
paddd		%xmm4, %xmm5
sha256msg2	%xmm6, %xmm5
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1

/* Rounds 60-63 */
movdqa		%xmm5, %xmm3
paddd		15*16(%rax), %xmm5
sha256rnds2	%xmm1, %xmm2
pshufd		$0x0E, %xmm3, %xmm3
sha256rnds2	%xmm2, %xmm1

/* Add current hash values with previously saved */
paddd		%xmm7, %xmm1
paddd		%xmm8, %xmm2

/* Increment data pointer and loop if more to process */
add		$64, %rsi
cmp		%rdx, %rsi
jne		.Lloop0

/* Write hash values back in the correct order */
pshufd		$0x1B, %xmm1, %xmm1
pshufd		$0xB1, %xmm2, %xmm2
movdqa		%xmm1, %xmm7
movdqa		%xmm2, %xmm8
palignr		$8, %xmm7, %xmm8

movdqu		%xmm1, 0*16(%rdi)
movdqu		%xmm2, 1*16(%rdi)

.Ldone_hash:

RET
