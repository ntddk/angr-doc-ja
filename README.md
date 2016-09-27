これは[Angr Documentation](https://docs.angr.io/)の非公式翻訳です．

# 怒る (angry) ために

本書は，angrにまつわるドキュメントの集積です．
これを読めば，あなたはangrのプロとして，バイナリを思うがままに叩きのめせるようになりますよ．

私たちはangrを可能な限り苦痛なく利用できるように取り組んできました――私たちの目的は，ただiPythonを起動して，少ないコマンドを入力するだけで高度なバイナリ解析技術を試せるような，ユーザーフレンドリーなバイナリ解析スイートをつくることにあるのです．
とはいえ，バイナリ解析は複雑で，したがってangrも複雑にならざるを得ません．
そういうわけで，本稿は，系統立った解説を通じて，angrとその設計思想を理解する一助となるべく執筆されました．

## さあ始めよう

インストール手順は[こちら](./INSTALL.md)で読むことができます．

angrの機能を概括的に把握するには，[トップレベルメソッド](./docs/toplevel.md)から始めるか，[概要](./docs/overview.md)を通読するとよいでしょう．

検索可能な本書のHTML版は[ntddk.github.io/angr-doc-ja](http://ntddk.github.io/angr-doc-ja)に掲載されています．さらに，HTML
版APIリファレンスは[angr.io/api-doc](http://angr.io/api-doc/)にあります（英語）．

## angrを引用する

学術的な著作でangrを用いる場合は，元になった論文を引用してください：

```bibtex
@article{shoshitaishvili2016state,
  title={SoK: (State of) The Art of War: Offensive Techniques in Binary Analysis},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Salls, Christopher and Stephens, Nick and Polino, Mario and Dutcher, Andrew and Grosen, John and Feng, Siji and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={IEEE Symposium on Security and Privacy},
  year={2016}
}

@article{stephens2016driller,
  title={Driller: Augmenting Fuzzing Through Selective Symbolic Execution},
  author={Stephens, Nick and Grosen, John and Salls, Christopher and Dutcher, Andrew and Wang, Ruoyu and Corbetta, Jacopo and Shoshitaishvili, Yan and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2016}
}

@article{shoshitaishvili2015firmalice,
  title={Firmalice - Automatic Detection of Authentication Bypass Vulnerabilities in Binary Firmware},
  author={Shoshitaishvili, Yan and Wang, Ruoyu and Hauser, Christophe and Kruegel, Christopher and Vigna, Giovanni},
  booktitle={NDSS},
  year={2015}
}
```

## サポート

angrのヘルプを得たければ，下記の場所で質問するとよいでしょう：

- メーリングリスト： angr@lists.cs.ucsb.edu
- IRCチャンネル： [freenode](https://freenode.net/)の**#angr**
- 適切なgithubリポジトリのissue

## もっと先へ：

angrの内部構造，アルゴリズム，要素技術の一部を解説した[論文][paper]を読めば，内部で起きていることをより理解できます．

[paper]: https://www.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf
