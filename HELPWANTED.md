# 「求人募集中」

angrは巨大なプロジェクトで，保守するのは大変です．
コミュニティに貢献し，願わくばフィードバックを得たいという思いから，私たちはここに，遠大なTODOリストを掲載します．
幅広い難易度の，すべてのスキルレベルに応じた課題が（きっと）あるはずです．


## ドキュメンテーション

There are many parts of angr that suffer from little or no documentation. We desperately need community help in this area.

### API

私たちはつねにドキュメンテーションに遅れを取っています．
私たちは現状のドキュメントに何が欠けているか把握するため，githubでissueをトラッキングしています：

1. [angr](https://github.com/angr/angr/issues/145)
2. [simuvex](https://github.com/angr/simuvex/issues/28)
3. [claripy](https://github.com/angr/claripy/issues/17)
4. [cle](https://github.com/angr/cle/issues/29)
5. [pyvex](https://github.com/angr/pyvex/issues/34)


### GitBook

本書にはいくらか核心部分の抜けがあります．
具体的には，下記の要素に改善の余地があります：

1. あちこちに残されたTODOを完遂する．
2. 実例のページを理にかなったやり方で整理する．いまのところ実例のほとんどは極めて冗長で，大部分をシンプルな表にまとめられれば，ページ数をいくらか削減できるかもしれない．


### angr学習コース

angr初学者に向けた「コース」なるものの開発は，必ずや有益な取り組みとなることでしょう．
これは，[こちら](https://github.com/angr/angr-doc/pull/74)の方向性に沿って実現されつつありますが，さらなる拡張が見込まれます．

回を重ねるごとに難易度が上昇し，段階的にangrの機能を学べるようなハンズオンが理想です．

## Research re-implementation

Unfortunately, not everyone bases their research on angr ;-).
Until that's remedied, we'll need to periodically implement related work, on top of angr, to make it reusable within the scope of the framework.
This section lists some of this related work that's ripe for reimplementation in angr.

### Redundant State Detection for Dynamic Symbolic Execution

Bugrara, et al. describe a method to identify and trim redundant states, increasing the speed of symbolic execution by up to 50 times and coverage by 4%.
This would be great to have in angr, as an ExplorationTechnique.
The paper is here: http://nsl.cs.columbia.edu/projects/minestrone/papers/atc13-bugrara.pdf

### In-Vivo Multi-Path Analysis of Software Systems

Rather than developing symbolic summaries for every system call, we can use a technique proposed by [S2E](http://dslab.epfl.ch/pubs/s2e.pdf) for concretizing necessary data and dispatching them to the OS itself.
This would make angr applicable to a *much* larger set of binaries than it can currently analyze.

While this would be most useful for system calls, once it is implemented, it could be trivially applied to any location of code (i.e., library functions).
By carefully choosing which library functions are handled like this, we can greatly increase angr's scalability.

## 開発
We have several projects in mind that primarily require development effort.

### angr-management

angrのGUIである[angr-management](https://github.com/angr/angr-management)には*多大な*伸びしろがあります．

Here is a non-exhaustive list of what is currently missing in angr-management:

- A navigator toolbar showing content in a program’s memory space, just like IDA Pro’s navigator toolbar.
- A text-based disassembly view of the program.
- Better view showing details in program states during path exploration, including modifiable register view, memory view, file descriptor view, etc.
- A GUI for cross referencing.

angrの機能を適切に可視化する手法はきっと有用です！

### IDA Plugins

Much of angr's functionality could be exposed via IDA.
For example, angr's data dependence graph could be exposed in IDA through annotations, or obfuscated values can be resolved using symbolic execution.

### アーキテクチャサポートの追加

新しいアーキテクチャに対応すれば，angrはより有用なものとなるでしょう．それには，下記の作業を伴います：

1. アーキテクチャの情報を[archinfo](https://github.com/angr/archinfo)に追加する．
2. IR変換処理を`angr.Block`に追加する．
3. IRパーサを`simuvex`に追加する（おそらくは`simuvex.SimRun`のさらなるサブクラスとして）．
4. SimProcedures対応のために（システムコールを含む）呼び出し規約を`simuvex.SimCC`に追加する．
5. 初期化処理対応のために`angr.SimOS`を追加・改変する．
6. バイナリをロードするCLEバックエンドを作成する．バイナリがELFフォーマットであれば，CLE ELFバックエンドを拡張すればよい．

手順2および3は，アーキテクチャのネイティブコードからVEXへの変換器を書いて済ませることもできます．PyVEX構造体を出力するだけなら，Pythonで事足ります．


___新しいアーキテクチャのアイデア___

- PIC, AVR, その他組み込みアーキテクチャ
- SPARC（libVEXのSPARCサポートを[準備中](https://bitbucket.org/iraisr/valgrind-solaris)です）

___新しいIRのアイデア___

- LLVM IR（に対応できれば，angrをバイナリ解析プラットフォームからプログラム解析プラットフォームへと拡張し，さまざまな機能を追加できるようになります！）
- SOOT（そうするためにはメモリモデルの拡張が必要となりますが，angrがJavaコードを分析できない理由はありません）


### 環境サポート

私たちは，オペレーティングシステム（すなわち，そのシステムコールによる影響）とライブラリ関数の環境をモデル化するため，「機能の概要」というコンセプトを採用しています．
この拡張は，angrのユーティリティを発展させる大きな助けとなるでしょう．
機能の概要については[こちら](https://github.com/angr/simuvex/tree/master/simuvex/procedures)を参照のこと．

機能の概要の具体的なサブセットはシステムコールを単位としています．
SimProduresのライブラリ関数（これがなくともangrは実際の関数を実行可能です）もさることながら，私たちは未実装のシステムコールを回避する策を少ししか持ち合わせていません．
システムコールの実装次第で，angrの扱えるバイナリの幅が広がります！

## Design Problems

There are some outstanding design challenges regarding the integration of additional functionalities into angr.

### type annotation and type information usage

angr has fledgling support for types, in the sense that it can parse them out of header files.
However, those types are not well exposed to do anything useful with.
Improving this support would make it possible to, for example, annotate certain memory regions with certain type information and interact with them intelligently.

Consider, for example, interacting with a linked list like this: `print state.memory[state.regs.rax:].next.next.value`.

## Research Challenges

Historically, angr has progressed in the course of research into novel areas of program analysis.
Here, we list several self-contained research projects that can be tackled.

### semantic function identification/diffing

Current function diffing techniques (TODO: some examples) have drawbacks.
For the CGC, we created a semantic-based binary identification engine (https://github.com/angr/identifier) that can identify functions based on testcases.
There are two areas of improvement, each of which is its own research project:

1. Currently, the testcases used by this component are human-generated. However, symbolic execution can be used to automatically generate testcases that can be used to recognize instances of a given function in other binaries.
2. By creating testcases that achieve a "high-enough" code coverage of a given function, we can detect changes in functionality by applying the set of testcases to another implementation of the same function and analyzing changes in code coverage. This can then be used as a sematic function diff.

### applying AFL's path selection criteria to symbolic execution

AFL does an excellent job in identifying "unique" paths during fuzzing by tracking the control flow transitions taken by every path.
This same metric can be applied to symbolic exploration, and would probably do a depressingly good job, considering how simpl

## Overarching Research Directions

There are areas of program analysis that are not well explored.
We list general directions of research here, but readers should keep in mind that these directions likely describe potential undertakings of entire PhD dissertations.

### process interactions

Almost all work in the field of binary analysis deals with single binaries, but this is often unrealistic in the real world.
For example, the type of input that can be passed to a CGI program depend on pre-processing by a web server.
Currently, there is no way to support the analysis of multiple concurrent processes in angr, and many open questions in the field (i.e., how to model concurrent actions).

### intra-process concurrency

Similar to the modeling of interactions between processes, little work has been done in understanding the interaction of concurrent threads in the same process.
Currently, angr has no way to reason about this, and it is unclear from the theoretical perspective how to approach this.

A subset of this problem is the analysis of signal handlers (or hardware interrupts).
Each signal handler can be modeled as a thread that can be executed at any time that a signal can be triggered.
Understanding when it is meaningful to analyze these handlers is an open problem.
One system that does reason about the effect of interrupts is [FIE](http://pages.cs.wisc.edu/~davidson/fie/).

### path explosion

Many approaches (such as [Veritesting](https://users.ece.cmu.edu/~dbrumley/pdf/Avgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf)) attempt to mitigate the path explosion problem in symbolic execution.
However, despite these efforts, path explosion is still *the* main problem preventing symbolic execution from being mainstream.

angr provides an excellent base to implement new techniques to control path explosion.
Most approaches can be easily implemented as [Exploration Techniques](http://angr.io/api-doc/angr.html#angr.exploration_techniques.ExplorationTechnique) and quickly evaluated (for example, on the [CGC dataset](https://github.com/CyberGrandChallenge/samples).