# ML-KEM-768 をスクラッチから作る教材

このディレクトリは `docs/implementation-book.md` の実行可能な教材である。Git の履歴や過去のコミットは使わない。短い多項式プログラムから始め、FIPS 203 と byte 単位で一致する読みやすいスカラー ML-KEM-768 を、自分の作業ディレクトリで一章ずつ組み立てる。

最初の例を動かす。

    make -C tutorial/00-scratch test

初級編の章別テストと完成版をすべて動かす。

    make -C tutorial test

期待する最後の行は次のとおりである。

    scalar ML-KEM-768: ALL TESTS PASSED

教材用実装と、このリポジトリの最適化済み製品実装が完全に一致することも確認できる。

    make -C tutorial oracle

構成:

- `00-scratch/`: 紙で追える `N=8` の negacyclic 多項式環。
- `scalar-mlkem/`: FIPS の式を通常の `% q` で書いた初級編の完成解答。
- `scalar-mlkem/tests/`: Keccak、encoding、NTT、sampling、K-PKE の章別合格テスト。

`scalar-mlkem` は学習用であり、実運用用ではない。K-PKE は ML-KEM の内部部品としてだけ扱う。また、再現可能な deterministic API はテスト専用であり、実運用の KeyGen/Encaps は承認された乱数生成器から内部で乱数を取得しなければならない。
