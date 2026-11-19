package exposure

import (
	"encoding/base64"
	"slices"
	"testing"
)

// encoded writes a text in Base64, as a file that keeps a secret so holds it.
func encoded(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}

// A secret is found in each form an application, a tool or a system keeps
// one in: by the name of its field, by where it stands, or by its shape.
func TestExtractSecretForms(t *testing.T) {
	table := load(t)
	storage := encoded("fakeStorageAccountKeyForTestingOnly")
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"a key that encrypts", `ENCRYPTION_KEY=fakeEncKey0123456789abcdef`, []string{"apikey=fakeEncKey0123456789abcdef (key)"}},
		{"a passphrase", `SSH_PASSPHRASE=fakePassphrase-Example1`, []string{"password=fakePassphrase-Example1"}},
		{"the key base of Rails", `SECRET_KEY_BASE=fakeRailsBase0123456789abcdef`, []string{"apikey=fakeRailsBase0123456789abcdef (key)"}},
		{"an address with a password and no user", `REDIS_URL=redis://:fakeRedisPw123@cache.internal:6379/0`, []string{"device=cache.internal", "password=fakeRedisPw123 for cache.internal"}},
		{"the key of a storage account", `CONN=DefaultEndpointsProtocol=https;AccountName=corpstore;AccountKey=` + storage + `;EndpointSuffix=core.windows.net`,
			[]string{"username=corpstore", "apikey=" + storage + " of corpstore (key)"}},
		{"a setting of web.config", `<add key="ClientSecret" value="fakeXmlSecret~Example123"/>`, []string{"password=fakeXmlSecret~Example123 (secret)"}},
		{"a password of unattend.xml", `<AdministratorPassword><Value>FakeUnattendPw1!</Value><PlainText>true</PlainText></AdministratorPassword>`, []string{"password=FakeUnattendPw1!"}},
		{"a line of .netrc", `machine api.example.net login deploy password fakeNetrcPw123`, []string{"password=fakeNetrcPw123 of deploy for api.example.net", "username=deploy"}},
		{"the auth of a Docker config", `{"auths": {"registry.example.net": {"auth": "` + encoded("deploy:fakeDockerPw123") + `"}}}`, []string{"password=fakeDockerPw123 of deploy", "username=deploy"}},
		{"a line of .pgpass", `db.internal:5432:app:app_rw:fakePgpassPw123`, []string{"device=db.internal", "password=fakePgpassPw123 of app_rw for db.internal", "username=app_rw"}},
		{"an argument of a call", `client = Client(api_key="fakePyApiKey0123456789")`, []string{"apikey=fakePyApiKey0123456789 (key)"}},
		{"a variable of Go", `token := "fakeGoToken0123456789abcd"`, []string{"password=fakeGoToken0123456789abcd (token)"}},
		{"a part of a connection string", `var connectionString = "Server=db.internal;Database=app;User Id=sa;Pwd=fakeCsPw123!;";`,
			[]string{"device=db.internal", "username=sa", "password=fakeCsPw123! of sa for db.internal"}},
		{"a flag that names a secret", `tool login --client-secret fakeCliSecret~Example1 --tenant corp`, []string{"password=fakeCliSecret~Example1 (secret)"}},
		{"a flag that names a key", `tool --api-key fakeFlagKey0123456789 run`, []string{"apikey=fakeFlagKey0123456789 (key)"}},
		{"a literal of kubectl", `kubectl create secret generic db --from-literal=password=fakeLiteralPw123`, []string{"password=fakeLiteralPw123"}},
		{"a parameter of an address", `curl "https://api.example.net/v1/items?token=fakeQueryToken0123456789"`, []string{"password=fakeQueryToken0123456789 (token) for api.example.net"}},
		{"the key of a wireless network", `    Key Content            : FakeWifiPass123`, []string{"password=FakeWifiPass123"}},
		{"a value of the registry", `    DefaultPassword    REG_SZ    FakeWinlogonPw1!`, []string{"password=FakeWinlogonPw1!"}},
		{"a value written to the registry", `reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /t REG_SZ /d FakeRegPw1! /f`, []string{"password=FakeRegPw1!"}},
		{"a line of htpasswd", `deploy:$apr1$fakeSalt$0123456789abcdefghijkl`, []string{"password=$apr1$fakeSalt$0123456789abcdefghijkl of deploy (hash)", "username=deploy"}},
		{"an entry of a PHP array", `    'password' => 'fakePhpPw123!',`, []string{"password=fakePhpPw123!"}},
		{"a constant of PHP", `define( 'DB_PASSWORD', 'fakeWpPw123!' );`, []string{"password=fakeWpPw123! (secret)"}},
		{"a default password", `PASSWORD=changeme`, []string{"password=changeme"}},
		{"the secret of an application of Entra ID, by its shape", `created AbC8Q~abcdefghijklmnopqrstuvwxyzABCDEFGH`,
			[]string{"password=AbC8Q~abcdefghijklmnopqrstuvwxyzABCDEFGH (secret) for Microsoft 365"}},
		{"the signature of a shared access address", `https://corpstore.blob.core.windows.net/c/f.txt?sv=2022-11-02&se=2030-01-01&sp=r&sig=ZmFrZVNhc1NpZ25hdHVyZUZvclRlc3RzT25seTAwMDA%3D`,
			[]string{"apikey=ZmFrZVNhc1NpZ25hdHVyZUZvclRlc3RzT25seTAwMDA%3D (signature) for Microsoft 365"}},
		{"a key of Groq", `created gsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`, []string{"apikey=gsk_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ (key) for Groq"}},
		{"a token of Vault", `created hvs.abcdefghijklmnopqrstuvwxyzABCD`, []string{"apikey=hvs.abcdefghijklmnopqrstuvwxyzABCD (key) for HashiCorp Vault"}},
		{"a token of a Telegram bot", `created 123456789:AAabcdefghijklmnopqrstuvwxyzABCDEFG`, []string{"apikey=123456789:AAabcdefghijklmnopqrstuvwxyzABCDEFG (key) for Telegram"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := brief(table.Extract(tt.text)); !slices.Equal(got, tt.want) {
				t.Errorf("Extract(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

// What stands where a secret would is none: code that fetches one, a
// reference to one, a placeholder, a type, or a field that only ends as one does.
func TestExtractNoSecret(t *testing.T) {
	table := load(t)
	for name, text := range map[string]string{ //nolint:gosec // G101: lines that hold no secret at all
		"a call":                         `token = get_token()`,
		"a read of the environment":      `api_key = os.getenv("API_KEY")`,
		"a prompt":                       `password = input("Password: ")`,
		"an argument of the program":     `secret = args.secret`,
		"a hash that is computed":        `user.password = hash_password(raw)`,
		"a variable of Terraform":        `password = var.db_password`,
		"a header that is cut":           `const token = req.headers.authorization.split(' ')[1];`,
		"a comparison":                   `if password == confirm_password:`,
		"an arrow function":              `items.map(token => token.trim())`,
		"a format string":                `logger.info("token: %s", t)`,
		"a string that is filled in":     `print(f"password={password}")`,
		"a placeholder":                  `API_KEY=your_api_key_here`,
		"a type":                         `token: string`,
		"a state":                        `password: expired`,
		"the name of an option's value":  `  --password PASSWORD   the password to use`,
		"a sentence in a title":          `title: "Reset password: step 1"`,
		"a sentence in a help text":      `help="API key: get one from the dashboard"`,
		"a field that ends in pass":      `{"boarding_pass": "LH400-22A", "underpass": "A40 tunnel"}`,
		"the token of a page of results": `{"nextToken": "eyJsYXN0IjoiYWJjMTIzIn0", "items": []}`,
		"the token of a form":            `{"csrf_token": "f3a9c1d27b5e4c0aa1b2c3d4e5f60718"}`,
		"a password read from the input": `docker login --password-stdin registry.example.net`,
		"an option that takes none":      `pg_dump --no-password --file=out.sql`,
		"an auth that is no credential":  `{"auth": "none"}`,
		"an auth that is required":       `auth: required`,
		"the name of a secret":           `aws secretsmanager get-secret-value --secret-id prod/db`,
		"a time of day":                  `2025-03-01T10:15:00:INFO:started`,
		"a text put together":            `body = "GITHUB_TOKEN=" + token + "\n"`,
		"a value of a list":              `secret := m[8] >= 0`,
		"a value that is built":          `secret = exposure.Kind{Name: "device"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := brief(table.Extract(text)); len(got) != 0 {
				t.Errorf("Extract(%q) = %q, want nothing", text, got)
			}
		})
	}
}
