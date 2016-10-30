トップレベルインターフェイス
====================

そういうわけで，angrのプロジェクトをロードできたぞ．さあどうしよう？

このドキュメントでは，`angr.Project`のインスタンスから参照できる全属性を解説します．

## 基本的なプロパティ
```python
>>> import angr, monkeyhex, claripy
>>> b = angr.Project('/bin/true')

>>> b.arch
<Arch AMD64 (LE)>
>>> b.entry
0x401410
>>> b.filename
'/bin/true'
>>> b.loader
<Loaded true, maps [0x400000:0x4004000]>
```

- *arch*はどのアーキテクチャ向けにプログラムがコンパイルされたかを示す，`archinfo.Arch`オブジェクトのインスタンスです．[たくさんの楽しい情報](https://github.com/angr/archinfo/blob/master/archinfo/arch_amd64.py)が詰まっています！　注意を払うべき共通の要素は`arch.bit`, `arch.bytes`（これは[メイン`Arch`クラス](https://github.com/angr/archinfo/blob/master/archinfo/arch.py)の`@property`宣言です），`arch.name`, そして`arch.memory_endness`です．
- *entry*はバイナリのエントリポイントです！
- *filename*はファイルの絶対パス名です．うわーすげーかっこいい．
- *loader*は各プロジェクトにおける[cle.Loader](https://github.com/angr/cle/blob/master/cle/loader.py)のインスタンスです．使用法の詳細は[こちら](./loading.md)．

## AnalysesとSurveyors
```python
>>> b.analyses
<angr.analysis.Analyses object at 0x7f5220d6a890>
>>> b.surveyors
<angr.surveyor.Surveyors object at 0x7f52191b9dd0>

>>> filter(lambda x: '_' not in x, dir(b.analyses))
['BackwardSlice',
 'BinDiff',
 'BoyScout',
 'BufferOverflowDetection',
 'CDG',
 'CFG',
 'DDG',
 'GirlScout',
 'SleakMeta',
 'Sleakslice',
 'VFG',
 'Veritesting',
 'XSleak']
>>> filter(lambda x: '_' not in x, dir(b.surveyors))
['Caller', 'Escaper', 'Executor', 'Explorer', 'Slicecutor', 'started']
```

`analyses`と`surveyors`はどちらもそれぞれAnalysesとSurveyorsのコンテナオブジェクトです．

Analysesはカスタマイズ可能な分析ルーチンで，プログラムからなんらかの情報を抽出できます．
最も一般的なのは，制御フローグラフを構成する`CFG`と，値セットの解析を実行する`VFG`です．
それらの使用法と，独自のAnalysesを作成する方法は[こちら](./analyses.md)に文書化されています．

Surveyorsはある共通の目的に向けてシンボリック実行を実施するための基本ツールです．
最も一般的なのは，あるアドレスを回避しつつあるアドレスに辿り着くための`Explorer`です．
Surveyorsについては[こちら](./surveyors.md)を呼んでください．
これはクールですが，しかし将来はPath Groups（下記）に置き換えられる予定です．

## Factory

`b.factory`は，`b.analyses`と`b.surveyors`と同様にクールな情報を持っているコンテナオブジェクトです．
これはJavaにおけるfactoryのようなものではありません．単にangrの重要なクラスの新しいインスタンスを生みだす全関数の元で，Projectごとに設定されます．

```python
>>> import claripy # あとで使うため

>>> block = b.factory.block(addr=b.entry)
>>> block = b.factory.block(addr=b.entry, insn_bytes='\xc3')
>>> block = b.factory.block(addr=b.entry, num_inst=1)

>>> state = b.factory.blank_state(addr=b.entry)
>>> state = b.factory.entry_state(args=['./program', claripy.BVS('arg1', 20*8)])
>>> state = b.factory.call_state(0x1000, "hello", "world")
>>> state = b.factory.full_init_state(args=['./program', claripy.BVS('arg1', 20*8)])

>>> path = b.factory.path()
>>> path = b.factory.path(state)

>>> group = b.factory.path_group()
>>> group = b.factory.path_group(path)
>>> group = b.factory.path_group([path, state])

>>> strlen_addr = b.loader.main_bin.plt['strlen']
>>> strlen = b.factory.callable(strlen_addr)
>>> assert claripy.is_true(strlen("hello") == 5)

>>> cc = b.factory.cc()
```

- *factory.block*はangrのリフターです．渡されたアドレスを起点としてバイナリを基本ブロックに区切り，ブロックのさまざまな表現を含むBlockオブジェクトを返します．詳細はのちほど示します．
- *factory.blank_state*は，渡された引数に応じて初期化したSimStateオブジェクトを返します．Statesの全貌は[こちら](states.md)で論じられています．
- *factory.entry_state*は，バイナリのエントリポイントに相当するプログラムの状態に初期化したSimStateを返します．
- *factory.call_state*は，渡されたアドレスの関数を引数とともに呼び出したかのように初期化したSimStateを返します．
- *factory.full_init_state*は`entry_state`に似ていますが，エントリポイントではなく，SimProcedureを示すプログラムカウンタのSimStateを返します．SimProcedureは動的ローダーの提供を目的としていて，エントリポイントにジャンプする前に各共有ライブラリを初期化します．
- *factory.path*はPathオブジェクトを返します．PathsはSimStatesまわりのちょっとしたラッパーで，stateを引数として`path`を呼び出すと，そのstateをラップしたpathを取得できます．単純な例を挙げると，`path`に渡されたキーワード引数は`entry_state`を経由し，結果としてラップ対象のstateが作成されます．その詳細は[こちら](paths.md)で論じられています．
- *factory.path_group*はpath groupを作成します！　Path groupsは未来をもたらします．これはpathsのかしこいリストで，pathやstate（pathにラップされます），あるいはpathsやstatesのリストを渡すことができます．その詳細は[こちら](pathgroups.md)で論じられています．
- *factory.callable*は_マジで_クールですよ．Callablesは任意のバイナリコードへのFFI（外部関数インターフェイス）で，その詳細は[こちら](structured_data.md)で論じられています．
- *factory.cc*は呼び出し規約 (calling convention) オブジェクトを初期化します．この初期化に際して，関数呼び出しの引数や，関数プロトタイプを設定できます．そして，どのように引数や戻り値，リターンアドレスがメモリにレイアウトされるかfactory.callableあるいはfactory.call_stateを通じて設定できます．その詳細は[こちら](structured_data.md)で論じられています．

### リフター

*factory.block*を介してリフターにアクセスできます．
このメソッドは，[こちら](http://angr.io/api-doc/angr.html#module-angr.lifter)にあるように，いくつかのオプション引数をとります！
つまるところ，`block()`はコードの基本ブロックへの汎用的なインターフェイスを提供するということです．
`.size`（バイト単位）のようにブロックからプロパティを取得できますが，おもしろいことをしたければ，基本ブロックのより具体的な表現形が必要になります．
`.vex`にアクセスして[PyVEX IRSB](http://angr.io/api-doc/pyvex.html#pyvex.block.IRSB)を取得するか，`.capstone`にアクセスして[Capstone block](http://www.capstone-engine.org/lang_python.html)を取得してください．

### ファイルシステムオプション

stateの初期化ルーチンには，ファイルシステムの利用方法に影響を与えるオプションを渡すことができます．これには，`fs`, `concrete_fs`, および`chroot`のオプションが含まれます．

`fs`オプションを使用すると，事前に設定されたSimFileオブジェクトに対して辞書またはファイル名を渡せるようになります．
このオプションによって，ファイルの内容についてサイズの制限を設けるといったことができるようになります．

`concrete_fs`オプションに`True`を設定すれば，angrはディスク上の実ファイルを重視するようになります．たとえば，シミュレーション中にプログラムが`banner.txt`を開こうとしたとしましょう．ここで`concrete_fs`が`False`（デフォルト）に設定されている場合，メモリを記号値として扱うようにSimFileが作成され，ファイルが存在するかのようにシミュレートが行われます．`concrete_fs`が`True`に設定されている場合，メモリを具体値として扱うようにSimFileが作成され，記号値だけでファイルを扱うことで生じるであろう状態爆発を抑制できます．
さらに`concrete_fs`モードでは，シミュレーション中に`banner.txt`が存在しないと場合はSimFileオブジェクトを作成せず，エラーコードを返します．
加えて，パスが'/dev/'から始まるファイルは`concrete_fs`が`True`に設定されていた場合開かれないことに注意してください．

`chroot`オプションでは，`concrete_fs`オプションを用いるときのルートを設定できます．解析対象のプログラムが絶対パスを用いてファイルを参照しようとする場合に便利なオプションです．たとえば，解析対象のプログラムが'etc/passwd'を開こうとするとき，chrootをカレントワーキングディレクトリに設定しておけば，'/etc/passwd'へのアクセス試行は'$CWD/etc/passwd'にリダイレクトされます．

```python
>>> import simuvex
>>> files = {'/dev/stdin': simuvex.storage.file.SimFile("/dev/stdin", "r", size=30)}
>>> s = b.factory.entry_state(fs=files, concrete_fs=True, chroot="angr-chroot/")
```

この例では，標準入力から30バイトまでの記号値を受け取ったとしてstateを作成します．そして，新しいルートディレクトリ`angr-chroot`内でファイルの参照を具体的に解決することになります．

残りの要素について書く前に，この初版で注意しておかなければならないこと：
`args`と`env`キーワード引数は`entry_state`および`full_init_state`で動作します．これらはそれぞれ，文字列または[claripy](./claripy.md) BVオブジェクトのリストまたは辞書で，いろいろな文字列の具体値と記号値を表現することができます．もっと知りたければソースコードを読んでください！

## フッキング

```python
>>> def set_rax(state):
...    state.regs.rax = 10

>>> b.hook(0x10000, set_rax, length=5)
>>> b.is_hooked(0x10000)
True
>>> b.unhook(0x10000)
>>> b.hook_symbol('strlen', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
```

フックはプログラムのあるべき動作を変化させる手法です．
特定のアドレスにフックを仕掛ければ，プログラムの実行がそこに到達するたびに，フック内のpythonコードを実行できます．
実行はフックされたアドレスから`length`バイトぶんスキップしたアドレスからレジュームされます．`length`引数を省略した場合，実行は0バイトぶんスキップされ，フックされたアドレスからレジュームされます．

基本的な関数に加えて，`SimProcedure`を用いてアドレスをフックすることもできます．これは，プログラムの実行をきめ細かく制御するためのより複雑なシステムです．`SimProcedure`はまったく同じ`hook`関数から利用できますが，simuvex.SimProcedureの（インスタンスではなく！）サブクラスを提供しています．

`is_hooked`と`unhook`メソッドはまあ自明でしょう．

`hook_symbol`はこれらと異なる目的を果たす別の関数です．アドレスではなくバイナリのインポート関数名を渡します．関数呼び出しにおいて解決されるコードへの内部 (GOT) ポインタは，第3引数で指定したSimProcedureまたはフック関数へのポインタに置き換えられます．同様に，通常の整数を渡し，その値のシンボルに置き換えることもできます．
