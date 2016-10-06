# バグ報告

もしangrに解決できない問題があり，バグのような挙動を示したら，ぜひ私たちに知らせてください！

1. angr/binariesとangr/angrをフォークし，
2. 問題のバイナリを添えてangr/binariesにプルリクエストを送ってください．
3. 問題のバイナリを読み込む`angr/tests/broken_x.py`, `angr/tests/broken_y.py`, などを添えてangr/angrにプルリクエストを送ってください．

そのときは，楽にスクリプトをマージして実行できるよう，（コードをtest_なんとか関数として切り分けできるので）下記のテストケースの形式に従っていただきたいと思います．
例：

```python
def test_some_broken_feature():
    p = angr.Project("some_binary")
    result = p.analyses.SomethingThatDoesNotWork()
    assert result == "what it should *actually* be if it worked"

if __name__ == '__main__':
    test_some_broken_feature()
```

こうしていただければ，バグの再現とその修正の*著しい*迅速化が見込めます．
理想的な状況は，バグが修正されたとき，あなたのテストケースがパスする（すなわち，末尾のassertがAssertionErrorを引き起こさない）ことです．
そうなれば，`broken_x.py`は`test_x.py`にリネームされ，リポジトリにコードがプッシュされる度に私たちの内部CIが検証してくれるテストケースに追加されます．バグが修正されていることを保証するためです．

# angrの開発

コードベースをよい状態にしておくための，いくつかのガイドラインがあります！

## コーディングスタイル

クソッタレた状況を避け，合理的なコードを保つために，私たちは[PEP8コーディング規約](http://legacy.python.org/dev/peps/pep-0008/)に準拠しようとしています．もしあなたがVimを使っているなら，[python-mode](https://github.com/klen/python-mode)プラグインがあなたの必要とするすべてを担います．もちろん[手動で設定](https://wiki.python.org/moin/Vim)しても構いません．

angrの一部としてコードを書くとき最も重要なのは，以下の点を考慮することです：

- どこであろうと，getterやsetterではなく属性アクセス（`@property`デコレータを参照）を利用してください．Javaじゃあるまいし．iPythonなら属性のタブ補完も効きます．とはいえ，合理的たれ：属性アクセスは高速であるべきです．経験則的に，何らかの制約解決が必要なものを属性として扱うべきではありません．

- 私たちの用意した`.pylintrc`を利用してください．かなり寛容ではありますが，あなたのコードがpylintの要求する品質にそぐわなければ，CIサーバによるビルドは通りません．

- どのような状況下でも絶対に`raise Exception`または`assert False`を利用しないでください．**例外の型を適切に扱ってください**．適切な例外の型がなければ，作業中のモジュール（すなわち，angrであれば`AngrError`, SimuVEXであれば`SimError`, etc）のコア例外をサブクラス化して送出します．適切な場所，適切な型の例外は適切にキャッチされ，適切にハンドルされますが，`AssertionError`と`Exception`は決してハンドルされず，解析を強制終了に追いやることになります．

- タブを避けてください；インデントには代わりにスペースを用いてください．たとえそれが過ちだとしても，スペース4つがデファクトスタンダードです．タブとスペースが混在したおぞましいコードをマージするよりは，最初からスペースを使ったほうが身のためです．

- 長すぎる行の記述を避けてください．いや，別に構わないのですが，長い行にわたる記述を読むのは大変だし，一般的にやめておくべきだということを肝に銘じておいてください．**文字数は120まで**という制限にこだわってみましょう．

- クソ長い関数を避けてください．より小さな機能に分割したほうがよい場合が多いのですから．

- （デバッグ時にアクセスできるよう）プライベートなメンバの定義には`__`よりも`_`を選んでください．*あなた*は与えられた関数を誰もが参照できなければならないとは思わないかもしれませんが，どうか私たちを信頼してください．間違っているのはあなたのほうなんです．

## ドキュメンテーション

コードを文書化してください．すべての*クラス定義*と*パブリックな関数定義*にはいくつかの説明が必要です：
 - 何をするか．
 - パラメータの型と意味．
 - 戻り値．

私たちは[Sphinx](http://www.sphinx-doc.org/en/stable/)を用いてAPIドキュメンテーションを生成しています．Sphinxは関数のパラメータや戻り値，戻り値の型などを自動で文書化するための特別な[見出し語](http://www.sphinx-doc.org/en/stable/domains.html#info-field-lists)をサポートしています．

関数のドキュメンテーション例を示します．そのままdocstringを読み込めるよう，パラメータの説明文は垂直に整列されている状態が理想です．

```python
def prune(self, filter_func=None, from_stash=None, to_stash=None):
    """
    Prune unsatisfiable paths from a stash.

    :param filter_func: Only prune paths that match this filter.
    :param from_stash:  Prune paths from this stash. (default: 'active')
    :param to_stash:    Put pruned paths in this stash. (default: 'pruned')

    :returns:           The resulting PathGroup.
    :rtype:             PathGroup
    """
 ```

この記法の利点は，関数のパラメータが生成されたドキュメント内で明確に区別されることです．しかしながら，この記法はドキュメントを冗長にしかねません．文章的な記述のほうが読みやすい場合もあります．
文書化しようとしている関数やクラスにより適切な形式を選んでください．

 ```python
 def read_bytes(self, addr, n):
    """
    Read `n` bytes at address `addr` in memory and return an array of bytes.
    """
 ```
 
## ユニットテスト

もしプッシュしようとしている新機能にテストケースが同梱されていない場合，その機能は遠からず**壊れるでしょう**．
自分のためにテストケースを書いてください．

私たちは各コミットに対して機能テストとリグレッションテストを実施する内部CIサーバを備えています．
サーバがあなたのテストを実施できるよう，[nosetests](https://nose.readthedocs.org/en/latest/)に準拠したテストコードを書き，適切なリポジトリの`tests`フォルダ内に`test_*.py`として保存してください．
テストファイルは`def test_*():`形式の関数を何個でも含むことができます．
関数はそれぞれテストとして実行され，例外またはアサーションが送出されればテストは失敗します．
よりよいエラーメッセージのために，`nose.tools.assert_*`関数を利用してください．

テストを書くときは既存のテストコードを参考にしてください．
既存のコードの多くは，テストを簡単にパラメータ化するべく，yieldによって`test_*`関数から呼び出し先の関数とその引数のタプルを生成する方法を採っています．
なおテスト関数にはdocstringを追加しないようにしてください．
