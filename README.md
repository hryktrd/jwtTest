# jwtTest

Go + goa(v2)でBasic AuthでBearerToken取得→APIアクセスというサンプルです。

秘密鍵、公開鍵を作成してjwtkey/内に入れる必要があります。

秘密鍵の作り方は
```bash
ssh-keygen -t rsa -b 4096 -f jwt.key
```
として作成してから、公開鍵の方を
```bash
ssh-keygen -f jwt.key.pub -e -m pkcs8 > .jwt.key.pub.pkcs8
```
としてpem化します。
Windowsのcmd上でやったところUTF-16 LEになってしまい、そのまま実行すると読み込んでパースするときにエラーになってしまったため、VSCodeみたいなエディタを使うなどしてUTF-8に直す必要があります。
main.goで秘密鍵を、jwt.goで公開鍵を読み込んでいます。

```bash
go run main.go jwt.go
```
で動作するはずです。