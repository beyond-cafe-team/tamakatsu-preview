# メンター管理サーバー

既存の GitHub Pages / さくらへの静的デプロイではデモを配信します。Google認証を有効にするには、このサーバーを別の HTTPS オリジンで稼働させてください。管理用の HTML、画像、API を同一オリジンで配信します。

## 初回設定

1. Python 3.11 以降と Node.js が使えるサーバーにリポジトリを配置し、`admin-server/` で `python3 -m venv .venv`、`.venv/bin/pip install -r requirements.txt` を実行します。Node.js は DB 初期化時に公開プロフィールを読み込むために使います。
2. Google Cloud で OAuth クライアント（ウェブアプリケーション）を作成し、承認済みのリダイレクト URI に `https://管理画面のホスト/auth/google/callback` を登録します。社外のメンターも登録するため、Google Auth Platform の対象ユーザーは外部を使用します。テスト中は参加するアカウントをテストユーザーに追加します。使用するスコープは `openid email` です。
3. サーバーの環境変数に次を設定します。事前に DB 用の永続ディレクトリを作り、サービスユーザーだけに読み書きを許可してください。

| 変数 | 設定内容 |
| --- | --- |
| `TAMA_ADMIN_ORIGIN` | 管理画面の正式な HTTPS オリジン。末尾のスラッシュとパスは省略 |
| `TAMA_GOOGLE_CLIENT_ID` | Google の OAuth クライアント ID |
| `TAMA_GOOGLE_CLIENT_SECRET` | Google の OAuth クライアントシークレット |
| `TAMA_SESSION_KEY` | サーバー用に生成した32文字以上のランダムな値。例として `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` で生成 |
| `TAMA_ADMIN_DB` | リポジトリ外にある永続 SQLite ファイルへの絶対パス |

4. `admin-server/` で `umask 077` を設定し、`.venv/bin/gunicorn --bind 127.0.0.1:8080 'app:create_app()'` を起動します。TLS を終端するリバースプロキシからこのポートに転送してください。稼働側のメールアドレス、招待情報、学生データは DB に保存されるため、管理された保管先でバックアップしてください。

## 招待の操作

- 管理画面の `/mentor-admin/` を開き、`@beyond-cafe.com` の Google Workspace アカウントでログインします。Googleが確認したメールと Workspace ドメインが両方一致した場合に運営管理者になります。
- 新規プロフィールは「メンターを招待」、既存のプロフィールは詳細の「このプロフィールに招待する」から発行します。指定したメールアドレスの本人にリンクを共有してください。
- メンターはリンクを開き、指定された Google アカウントで登録します。招待は7日間・1回限りです。同じプロフィールまたは同じ宛先への再発行で古い招待は失効します。
- 登録後、メンターは同じ Google アカウントでログインできます。自分のプロフィールと担当学生を編集できます。管理者には全担当学生が表示されます。
- DB の初回作成時に公開メンタープロフィールを取り込みます。管理サーバーから公開サイトへの同期、既存デモデータの自動移行、レビュー送信先との接続は未実装です。

## 検証

`admin-server/` で `.venv/bin/python -m unittest -v` を実行すると、Googleの応答を代替した認可・招待のテストが走ります。公開前に、運営と社外メンターの実際のアカウントを用いて HTTPS 上でログインと招待消費を確認してください。
