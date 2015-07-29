# PEfile

PEファイルのバイナリを読み込んで情報を表示するCプログラム  
対象PEファイル：実行可能かつ、マシンタイプがI386, 32ビットアーキテクチャ  
* 処理内容
    1. PEファイルをオープン
    2. PEファイルのヘッダを解析＆ファイル出力
    3. ネイティブコードをx86逆アセンブル＆ファイル出力
    4. PEファイルのインポート情報を取得＆ファイル出力
    5. x86逆アセンブル結果にreference情報を付加＆ファイル出力
    6. PEファイルをクローズ  
* 出力ファイル（以下、＊は対象のPEファイル名）
    * ＊_Header.txt：ヘッダー情報
    * ＊_Disasm.txt：reference情報なしのx86逆アセンブル結果
    * ＊_Imports.txt：インポート情報
    * ＊_RefDisasm.txt：reference情報ありのx86逆アセンブル結果
* テスト環境：
    * OS：Windows7
    * ツール：Visual Studio Professional 2013
