# トリキメサインの公開鍵

株式会社レイニーコードの電子契約サービス「トリキメサイン」が、署名の記録に署名するときに使う鍵の、**公開鍵の一覧**と、**PDF を確かめる方法**です。当社がサービスを終えたあとも、ここにある公開鍵と手順だけで、署名済みの PDF が書き換えられていないかを確かめられます。

- `public-keys.json`:公開鍵の一覧。鍵は消さずに載せ続け、使った期間を書きます。鍵が漏れたときは、漏れたと分かった時刻を書きます
- `verify.mjs`:PDF を確かめるスクリプト(Node.js 20 以上だけで動きます)
- 同じ一覧を、会社のホームページ https://rainy-chord.com/keys/ にも載せています
- `example/`:スクリプトの見本(テスト用の鍵で署名した見本の PDF と、その鍵の一覧)。`node verify.mjs example/example.pdf example/example-keys.json` で試せます

## いちばん簡単な方法

サービスを続けているあいだは、確かめのページ https://sign.rainy-chord.com/verify/ で PDF を選ぶだけで確かめられます(PDF は当社に送られません)。

## スクリプトで確かめる

```bash
node verify.mjs 契約書.pdf
```

`書き換えられていません。` と出れば、次の3つが確かめられています。

1. PDF の中の契約の中身が、署名のときと同じ
2. 署名の記録に、当社の鍵で署名されている
3. 署名した時刻に、その鍵を使っていた(漏れたあとの署名ではない)

## OpenSSL で確かめる(スクリプトを使わない方法)

1. PDF を開くソフト、または poppler の `pdfdetach -saveall 契約書.pdf` で、3つの添付を取り出します
   - `contract.json`:契約の中身(正規化したもの)
   - `signature-record.json`:署名の記録
   - `signature.txt`:当社の署名(Ed25519、base64url)
2. 契約の中身の要約値を、署名の記録と比べます(`contract.json` は正規化した形で添付してあるので、そのまま要約します)
   ```bash
   openssl dgst -sha256 contract.json
   ```
   出てきた値が、`signature-record.json` の `contract_sha256` と同じかを確かめます
3. 署名の記録の `key_id` の公開鍵を、`public-keys.json` から PEM の形にします
   ```bash
   printf '%s=' '<public_key の値>' | tr '_-' '/+' | base64 -d > raw.bin   # 公開鍵(43文字)は、末尾に「=」を1つ足して読む
   ( printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; cat raw.bin ) > pub.der
   openssl pkey -pubin -inform DER -in pub.der -out pub.pem
   ```
4. 署名を確かめます
   ```bash
   (cat signature.txt; printf '==') | tr '_-' '/+' | base64 -d > sig.bin   # 署名(86文字)は、末尾に「==」を足して読む
   openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in signature-record.json -sigfile sig.bin
   ```
   `Signature Verified Successfully` と出れば、署名の記録は当社の鍵で署名されています
5. `public-keys.json` で、署名した時刻(`counterparty.signed_at`)が、その鍵の `valid_from` から `valid_until` のあいだにあり、`compromised_at` より前であることを確かめます

この手順は、2026-10-15 に、トリキメサインで作った PDF と OpenSSL 3.6 で確かめました。

## 知っておいてください

- トリキメサインは、メールのリンクで署名する仕組みで、**本人確認はしていません**。電子署名法3条の推定は働かない前提です
- 当社は、署名の記録(契約の中身や連絡先は含みません)を10年間残します。契約の中身とメールアドレスは、署名から7日で消します

## ライセンス

MIT License(`LICENSE`)。スクリプトと説明は、自由に使い、写し、直してかまいません。

## このリポジトリの更新

鍵を足す・替える・漏れたときは、サービスのリポジトリ(非公開)の `keys/public-keys.json` と同じ内容を、このリポジトリの `public-keys.json` にも PR で入れます。
