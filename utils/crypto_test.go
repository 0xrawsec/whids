package utils

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xrawsec/toast"
)

func TestGenerateCert(t *testing.T) {
	tt := toast.FromT(t)

	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "cert.pem")

	_, cert, err := GenerateCert("TestOrg", []string{"localhost"}, time.Hour*24*365)
	tt.CheckErr(err)

	tt.CheckErr(os.WriteFile(certPath, cert, 0777))

	sha256, err := CertSha256(bytes.NewBuffer(cert))
	tt.CheckErr(err)

	sameSha256, err := CertFileSha256(certPath)
	tt.CheckErr(err)

	tt.Assert(sha256 == sameSha256)
}
