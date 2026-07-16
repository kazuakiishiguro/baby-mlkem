#!/usr/bin/env perl
use strict;
use warnings;

my @rho = (
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
);

sub phys {
    my ($power, $x, $y) = @_;
    for (1 .. $power) {
        $y = ($x + 2 * $y) % 5;
    }
    return $x + 5 * $y;
}

sub xr { return '%xmm' . $_[0]; }
sub ins { print "    $_[0]\n"; }

sub chi_imm {
    my ($dest_role, $src1_role, $src2_role) = @_;
    my $imm = 0;
    for my $index (0 .. 7) {
        my @role;
        $role[$dest_role] = ($index >> 2) & 1;
        $role[$src1_role] = ($index >> 1) & 1;
        $role[$src2_role] = $index & 1;
        my $out = $role[0] ^ ((1 ^ $role[1]) & $role[2]);
        $imm |= $out << $index;
    }
    return $imm;
}

sub build_plane {
    my ($i, $y, $temp_base) = @_;
    my $shift = (2 * $y) % 5;
    my @orders = (
        [0, 1, 2, 3, 4],
        [0, 1, 3, 2, 4],
        [0, 1, 4, 3, 2],
        [0, 1, 2, 4, 3],
        [0, 1, 2, 3, 4],
    );
    my @order = @{$orders[$shift]};
    my %position;
    $position{$order[$_]} = $_ for 0 .. 4;
    my %location;
    for my $b (0 .. 4) {
        my $source_x = ($b - $shift + 5) % 5;
        $location{$b} = phys($i + 1, $source_x, $y);
    }

    my @rotations;
    for my $x (0 .. 4) {
        my $p = phys($i + 1, $x, $y);
        my $logical_y = ($x + 2 * $y) % 5;
        my $rot = $rho[$x][$logical_y];
        push @rotations, sprintf("vprolq \$%d, %s, %s", $rot, xr($p), xr($p))
            if $rot;
    }

    my @chi;
    my $next_temp = $temp_base;
    for my $step (0 .. 4) {
        my $x = $order[$step];
        my $dest = phys($i + 1, $x, $y);
        my $old_b = ($x + $shift) % 5;
        my @users = ($old_b, ($old_b + 4) % 5, ($old_b + 3) % 5);
        my $last_use = 0;
        for my $user (@users) {
            $last_use = $position{$user}
                if $position{$user} > $last_use;
        }
        if ($step < $last_use) {
            push @chi, sprintf("vmovdqa64 %s, %s",
                               xr($dest), xr($next_temp));
            $location{$old_b} = $next_temp++;
        }

        my @needed = ($x, ($x + 1) % 5, ($x + 2) % 5);
        my $dest_role = -1;
        for my $role (0 .. 2) {
            $dest_role = $role if $needed[$role] == $old_b;
        }
        if ($dest_role < 0) {
            push @chi, sprintf("vmovdqa64 %s, %s",
                               xr($location{$needed[0]}), xr($dest));
            $dest_role = 0;
        }
        my @source_roles = grep { $_ != $dest_role } 0 .. 2;
        my ($src1_role, $src2_role) = @source_roles;
        my $imm = chi_imm($dest_role, $src1_role, $src2_role);
        push @chi, sprintf("vpternlogq \$0x%02X, %s, %s, %s", $imm,
                           xr($location{$needed[$src2_role]}),
                           xr($location{$needed[$src1_role]}), xr($dest));
        delete $location{$old_b}
            if exists($location{$old_b}) && $location{$old_b} == $dest;
    }
    die "Chi temporary range exceeds xmm30\n" if $next_temp > 31;
    return (\@rotations, \@chi, $shift, $next_temp);
}

sub emit_plane_pair {
    my ($i, $y0, $y1, $temp0, $temp1) = @_;
    my ($rot0, $chi0, $shift0, $end0) =
        build_plane($i, $y0, $temp0);
    my ($rot1, $chi1, $shift1, $end1) =
        build_plane($i, $y1, $temp1);
    die "Overlapping Chi temporary ranges\n"
        unless $end0 <= $temp1 || $end1 <= $temp0;
    print "\n    # Output planes y=$y0 (B shift=$shift0) and "
        . "y=$y1 (B shift=$shift1), interleaved.\n";
    ins($_) for @{$rot0}, @{$rot1};
    my $count = @{$chi0} > @{$chi1} ? @{$chi0} : @{$chi1};
    for my $step (0 .. $count - 1) {
        ins($chi0->[$step]) if $step < @{$chi0};
        ins($chi1->[$step]) if $step < @{$chi1};
    }
}

sub emit_single_plane {
    my ($i, $y, $temp_base) = @_;
    my ($rotations, $chi, $shift) = build_plane($i, $y, $temp_base);
    print "\n    # Output plane y=$y, B shift=$shift.\n";
    ins($_) for @{$rotations}, @{$chi};
}

sub emit_sha3_256_output_plane {
    my ($i) = @_;
    my @p = map { phys($i + 1, $_, 0) } 0 .. 4;
    print "\n    # Output plane y=0, lanes x=0..3 only.\n";
    for my $x (0 .. 4) {
        my $logical_y = $x;
        my $rot = $rho[$x][$logical_y];
        ins(sprintf("vprolq \$%d, %s, %s", $rot, xr($p[$x]), xr($p[$x])))
            if $rot;
    }
    ins(sprintf("vmovdqa64 %s, %%xmm25", xr($p[0])));
    for my $x (0 .. 3) {
        my $src1 = $p[($x + 1) % 5];
        my $src2 = ($x == 3) ? 25 : $p[($x + 2) % 5];
        ins(sprintf("vpternlogq \$0xD2, %s, %s, %s",
                    xr($src2), xr($src1), xr($p[$x])));
    }
}

sub emit_final_output_round {
    my ($i) = @_;
    print "\n    # Final round mapping N^$i -> N^" . ($i + 1)
        . "; only SHA3-256 output plane y=0 is live.\n";
    for my $x (0 .. 4) {
        my @p = map { phys($i, $x, $_) } 0 .. 4;
        ins(sprintf("vmovdqa64 %7s, %s", xr($p[0]), xr(25 + $x)));
        ins(sprintf("vpternlogq \$0x96, %7s, %7s, %s",
                    xr($p[2]), xr($p[1]), xr(25 + $x)));
        ins(sprintf("vpternlogq \$0x96, %7s, %7s, %s",
                    xr($p[4]), xr($p[3]), xr(25 + $x)));
    }
    for my $x (0 .. 4) {
        my $prev = 25 + (($x + 4) % 5);
        my $next = 25 + (($x + 1) % 5);
        my $p = phys($i + 1, $x, 0);
        ins(sprintf("vprolq \$1, %s, %%xmm30", xr($next)));
        ins(sprintf("vpternlogq \$0x96, %%xmm30, %s, %s",
                    xr($prev), xr($p)));
    }

    # Four SHA3-256 output lanes need all five Chi inputs in plane y=0.
    emit_sha3_256_output_plane($i);
    ins(sprintf("vmovq %d(%%r14), %%xmm31", 8 * $i));
    ins("vpxorq %xmm31, %xmm0, %xmm0");
}

sub emit_round {
    my ($i) = @_;
    print "\n    # Round mapping N^$i -> N^" . ($i + 1) . ".\n";
    for my $x (0 .. 4) {
        my @p = map { phys($i, $x, $_) } 0 .. 4;
        ins(sprintf("vmovdqa64 %7s, %s", xr($p[0]), xr(25 + $x)));
        ins(sprintf("vpternlogq \$0x96, %7s, %7s, %s",
                    xr($p[2]), xr($p[1]), xr(25 + $x)));
        ins(sprintf("vpternlogq \$0x96, %7s, %7s, %s",
                    xr($p[4]), xr($p[3]), xr(25 + $x)));
    }
    for my $x (0 .. 4) {
        my $prev = 25 + (($x + 4) % 5);
        my $next = 25 + (($x + 1) % 5);
        ins(sprintf("vprolq \$1, %s, %%xmm30", xr($next)));
        for my $y (0 .. 4) {
            my $p = phys($i, $x, $y);
            ins(sprintf("vpternlogq \$0x96, %%xmm30, %s, %s",
                        xr($prev), xr($p)));
        }
    }

    # Preserve each plane overwrite order while overlapping independent chains.
    emit_plane_pair($i, 0, 1, 25, 27);
    emit_plane_pair($i, 2, 3, 25, 28);
    emit_single_plane($i, 4, 25);
    ins(sprintf("vmovq %d(%%r14), %%xmm31", 8 * $i));
    ins("vpxorq %xmm31, %xmm0, %xmm0");
}

print <<'ASM';
# BEGIN GENERATED BY scripts/gen_keccak_inplace4.pl
# Fixed-shape H(pk) core using Keccak Team Algorithm 4.
# N(x,y)=(x,x+2y) mod 5 has order four, so each group returns the state to
# canonical order without the compact core's per-round 25-register reorder.
# xmm0-xmm24 hold lanes and xmm25-xmm31 are temporary registers.
.type .Lmlkem_keccakf1600_avx512vl_inplace4_permute,@function
.balign 32
.Lmlkem_keccakf1600_avx512vl_inplace4_permute:
    movl $6, %r13d
    leaq .Lmlkem_sha3_256_rc(%rip), %r14
.balign 32
.Lmlkem_keccakf1600_avx512vl_inplace4_group:
ASM

emit_round($_) for 0 .. 2;

print <<'ASM';
#if defined(__clang__)
    # r10d selects the last group of fixed SHA3-256's final permutation.
    testl %r10d, %r10d
    jz .Lmlkem_keccakf1600_avx512vl_inplace4_full_round3
    cmpl $1, %r13d
    je .Lmlkem_keccakf1600_avx512vl_inplace4_final32_round3
.Lmlkem_keccakf1600_avx512vl_inplace4_full_round3:
#endif
ASM

emit_round(3);

print <<'ASM';
    addq $32, %r14
    decl %r13d
    jnz .Lmlkem_keccakf1600_avx512vl_inplace4_group
    ret
.size .Lmlkem_keccakf1600_avx512vl_inplace4_permute,.-.Lmlkem_keccakf1600_avx512vl_inplace4_permute

#if defined(__clang__)
.section .mlkem_sha3_final32,"ax",@progbits
.balign 32
.type .Lmlkem_keccakf1600_avx512vl_inplace4_final32_round3,@function
.Lmlkem_keccakf1600_avx512vl_inplace4_final32_round3:
ASM

emit_final_output_round(3);

print <<'ASM';
    ret
.size .Lmlkem_keccakf1600_avx512vl_inplace4_final32_round3,.-.Lmlkem_keccakf1600_avx512vl_inplace4_final32_round3
.text
#endif
# END GENERATED BY scripts/gen_keccak_inplace4.pl

ASM
