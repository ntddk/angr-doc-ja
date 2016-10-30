# バイナリのロード - CLEとangr Projects

angrのバイナリロードコンポーネントはCLEといいます．これはCLE Loads Everythingのバクロニムです．CLEはバイナリ（とそれが依存するライブラリ）を受け取り，angrの残りのコンポーネントが扱いやすいようにそれらを提示する担当です．

CLEの主な目標は，ロバストな方法，すなわち，実際の（たとえばELFバイナリの場合GNU LD）ローダと同じ方法でバイナリをロードすることです．それは，ストリップされたり自主的または無意識に壊されたバイナリ中の情報のいくつかはCLEによって無視されることを意味します．組み込みの世界ではよくあることです．

angrは，次々にバイナリの情報を*Project*クラスに含めます．Projectクラスは解析対象のバイナリを示すエンティティであり，angrの操作を通じて幾度となく参照されます．

バイナリをangrにロードするには（"/bin/true"ってことにしましょう）次のように入力します：

```python
>>> import angr

>>> b = angr.Project("/bin/true")
```

これで，*b*はangrなりのバイナリ（「メイン」バイナリ）の表現になりました．依存ライブラリも一緒です．残りのプラットフォームの知識がなくても，ここでいくつか基本的なことができます：

```python
# バイナリのエントリポイント
>>> print b.entry

# バイナリのメモリにおける最小アドレスと最大アドレス
>>> print b.loader.min_addr(), b.loader.max_addr()

# バイナリの絶対パス名
>>> print b.filename
```

CLEはLoaderクラスを介してバイナリの情報をエクスポーズしています．CLEローダ (cle.loader) は単一のメモリ空間にロード・マッピングされ，ロードされたCLEバイナリオブジェクト全体の集合体を表現します．各バイナリオブジェクトは，そのファイル形式を扱えるローダバックエンド（cle.Backendのサブクラス）によりロードされます．たとえば，cle.ELFはELFバイナリのロードに用いられます．

CLEへのインターフェイスは次の通り：

```python
# CLE Loaderオブジェクト
>>> print b.loader

# 解析対象のバイナリの一部としてロードされたオブジェクト（型はバックエンド依存）の辞書
>>> print b.loader.shared_objects

# ロード後のプロセスのメモリ空間．指定アドレスのバイトにアドレスをマップする
>>> print b.loader.memory[b.loader.min_addr()]

# メインバイナリのオブジェクト（型はバックエンド依存）
>>> print b.loader.main_bin

# 指定アドレスにマップされたオブジェクト
>>> print b.loader.addr_belongs_to_object(b.loader.max_addr())

# （メインバイナリ中の）シンボルのGOTスロットのアドレス取得
>>> print b.loader.find_symbol_got_entry('__libc_start_main')

```

個々のバイナリオブジェクトを直に参照することもできます：

```python
# プログラムが依存しているライブラリ名のリスト
# ELFバイナリ中のdynamicセクションのDT_NEEDEDフィールドを静的に読み込むことで取得している
>>> print b.loader.main_bin.deps

# メインバイナリ*だけ*のメモリ内容の辞書
>>> print b.loader.main_bin.memory

# ロードされたlibcのインポート関数の辞書 (name->ELFRelocation)
>>> b.loader.shared_objects['libc.so.6'].imports

# メインバイナリのインポート関数の辞書 (name->ELFRelocation)
# アドレスは通常0（下記のその他セクションを参照のこと）
>>> print b.loader.main_bin.imports
```

## 依存関係のロード

ローディングオプションで`auto_load_libs`を`False`に指定していなければ，CLEはデフォルトでメインバイナリのすべての依存関係をロードしようとします（たとえばlibc.so.6やld-linux.so2など）．
いずれかを見つけられない場合はライブラリのロード時に黙ってエラーを無視し，そのライブラリの依存関係を未解決のものとして扱います．お好みでこの振る舞いは変更できます．

## ローディングオプション

ローディングオプションはProjectに対して渡すことができます（続いてCLEに渡されます）．

CLEはパラメータの集合のような辞書を予期しています．解析対象バイナリではないライブラリに適用されなければならないパラメータは，lib_opsパラメータとして下記のように渡せます：

```python
load_options = {'main_opts':{options0}, 'lib_opts': {libname1:{options1}, path2:{options2}, ...}}

# 読みやすく書くと：
load_options = {}
load_options['main_opts'] = {k1:v1, k2:v2 ...}
load_options['lib_opts'] = {}
load_options['lib_opts'][path1] = {k1:v1, k2:v2, ...}
load_options['lib_opts'][path2] = {k1:v1, k2:v2, ...}
など．
```

### 有効なオプション

```python
>>> load_options = {}

# もう動的ライブラリはロードしたっけ？
>>> load_options['auto_load_libs'] = False

# 強制的にロードするライブラリのリスト
>>> load_options['force_load_libs'] = ['libleet.so']

# スキップする特定ライブラリ
>>> load_options['skip_libs'] = ['libc.so.6']

# メインバイナリをロードするときのオプション
>>> load_options['main_opts'] = {'backend': 'elf'}

# ライブラリ名をロード時にオブジェクトの辞書にマッピング
>>> load_options['lib_opts'] = {'libc.so.6': {'custom_base_addr': 0x13370000}}

# 共有ライブラリを追加で検索するパスのリスト
>>> load_options['custom_ld_path'] = ['/my/fav/libs']

# libc.so.6とlibc.so.0のように異なるバージョン番号だが同一とおぼしきライブラリの扱い
>>> load_options['ignore_import_version_numbers'] = False

# 共有メモリのリベースのためのアライメント
>>> load_options['rebase_granularity'] = 0x1000

# ライブラリが見つからないときに例外を送出（デフォルトでは無視）
>>> load_options['except_missing_libs'] = True
```

次のオプションはオブジェクトごとに適用され，CLEの自動検出を上書きします．
これらはどちらも'main_opts'または'lib_opts'を通じて適用できます．

```python
# バイナリをロードするベースアドレス
>>> load_options['main_opts'] = {'custom_base_addr':0x4000}

# オブジェクトのバックエンド指定（バックエンドについては後述）
>>> load_options['main_opts'] = {'backend': 'elf'}
```

一度に複数のオプションを設定した例：

```python
>>> load_options['main_opts'] = {'backend':'elf', 'custom_base_addr': 0x10000}
```

## バックエンド

CLEは現在，IDAを用いてバイナリをロードしたりフラットなアドレス空間にファイルをロードしたりするだけでなく，静的にELF, PE, CGC, そしてELFコアダンプファイルをロードするバックエンドを備えています．CLEはほとんどの場合自動的にバイナリの正しいバックエンドを検出するため，よほど変なことをしようとしていない限りバックエンドを指定する必要はありません．

バックエンドを指定する場合は，オプション辞書にそのキーを含めるとよいでしょう．自動的に検出されない特定のアーキテクチャを強制する必要があれば，`custom_arch`キーから指定できます．キーがアーキテクチャのリストと一致する必要はありません；angrはサポートしているアーキテクチャの中から類似する共通の識別子をもとに指定しようとしたアーキテクチャを特定してくれるでしょう．

```python
>>> load_options = {}
>>> load_options['main_opts'] = {'backend': 'elf', 'custom_arch': 'i386'}
>>> load_options['lib_opts'] = {'libc.so.6': {'backend': 'elf'}}
```

| バックエンドキー | 説明 | `custom_arch`を要求する？ |
| --- | --- | --- |
| elf | PyELFToolsをベースとしたELFファイルの静的ローダ | no |
| pe | PEFileをベースとしたPEファイルの静的ローダ | no |
| cgc | Cyber Grand Challengeのバイナリの静的ローダ | no |
| backedcgc | メモリとレジスタのバッカー (backer) を登録できるCGCバイナリの静的ローダ | no |
| elfcore | ELFコアダンプの静的ローダ | no |
| ida | IDAのインスタンスを起動してファイルをパースする | yes |
| blob | フラットなイメージとしてメモリにファイルをロードする | yes |

いまやあなたはバイナリをロードし，```b.loader.main_bin```を通じてバイナリの興味深い情報にアクセスできるようになりました．たとえば，共有ライブラリの依存関係，インポートされたライブラリ，メモリ，シンボルなどです．IPythonのタブ補完機能を駆使して，利用可能な関数やオプションを参照するとよいでしょう．

さあ[IRサポート](./ir.md)に目を通すときがきました．

## その他

### インポート関数

以下はELF固有の情報です．
ほとんどのアーキテクチャでは，インポート関数，すなわちバイナリ外部の（共有ライブラリの）シンボルは，ほとんどつねに未定義アドレス (0) に割り当てられます．MIPSのようないくつかのアーキテクチャでは（テキストセグメント内に存在する）関数のPLTスタブのアドレスが含まれます．
もし（データセグメント内に存在する）特定のシンボルに関するGOTエントリのアドレスを探しているなら，jmprelを見てみましょう．これは辞書です (symbol -> GOT addr):

PLT後かGOTエントリ後かはアーキテクチャ依存です．アーキテクチャ固有の情報はArchinfoリポジトリ内のクラスで定義されます．アーキテクチャに依存した関数の絶対アドレスの扱い方はこのクラス内のgot_section_name propertyで定義されています．

ELFのローディングとアーキテクチャ固有の情報のさらなる詳細は，[Executable and linkable format document](http://www.cs.northwestern.edu/~pdinda/icsclass/doc/elf.pdf)を参照のこと．同様にアーキテクチャごとのABIの補足も ([MIPS](http://math-atlas.sourceforge.net/devel/assembly/mipsabi32.pdf), [PPC64](http://math-atlas.sourceforge.net/devel/assembly/PPC-elf64abi-1.7.pdf), [AMD64](http://www.x86-64.org/documentation/abi.pdf))..

```python
>>> rel = b.loader.main_bin.jmprel
```

### シンボリック解析：関数のサマリ

デフォルトでは，Projectはライブラリ関数の外部参照を*SimProcedures*という[シンボリックサマリ (symbolic summaries)](./todo.md) に置き換えようとします（関数がstateに与える影響をまとめたものです）．

与えられた関数のサマリが存在しない場合：

- `auto_load_libs`が`True`であれば（これがデフォルトです）*実際の*ライブラリ関数が代わりに実行されます．これは関数によっては欲しい機能かもしれません．たとえば，libc関数のいくつかは極めて複雑で，解析は困難です．実行しようとすれば[path](./paths.md)の状態爆発が起こりえます．
- `auto_load_libs`が`False`であれば，外部参照は未解決とされ，Projectは汎用的な`ReturnUnconstrained`と呼ばれる「スタブ」SimProcedureを用います．これは名前通りの仕事をします：そうです，制約されていない (unconstrained) 値を返すのです．
- `use_sim_procedures`（これは`cle.Loader`ではなく`angr.Project`のパラメータです）が`False`の場合は（デフォルトでは`True`），`ReturnUnconstrained`以外のSimProduresは利用されません．
- SimProceduresへの置き換えから除外するシンボルを指定したければ，`angr.Project`から次のパラメータを設定します：`exclude_sim_procedures_list`と`exclude_sim_procedures_func`.
- アルゴリズムの実際のソースコードは`angr.Project._use_sim_procedures`です．
