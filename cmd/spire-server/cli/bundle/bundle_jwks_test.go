package bundle

import (
	"io/ioutil"
	"path/filepath"

	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
)

const (
	otherDomainJWKS = `{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        },
        {
            "use": "jwt-svid",
            "kty": "EC",
            "kid": "KID",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
        }
    ]
}
`
)

func (s *BundleSuite) TestShowJWKS() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://example.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert1.Raw},
		},
		RefreshHint: 60,
	})

	s.Require().Equal(0, s.showCmd.Run([]string{"-format", formatJWKS}))

	s.Require().Equal(`{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        }
    ],
    "spiffe_refresh_hint": 60
}
`, s.stdout.String())
}

func (s *BundleSuite) TestSetCreatesBundleJWKS() {
	s.stdin.WriteString(otherDomainJWKS)
	s.assertBundleSet("-id", "spiffe://otherdomain.test", "-format", formatJWKS)
}

func (s *BundleSuite) TestSetUpdatesBundleJWKS() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://otherdomain.test",
		RootCas: []*common.Certificate{
			{DerBytes: []byte("BOGUSCERTS")},
		},
	})
	s.stdin.WriteString(otherDomainJWKS)
	s.assertBundleSet("-id", "spiffe://otherdomain.test", "-format", formatJWKS)
}

func (s *BundleSuite) TestSetRequiresIDFlagJWKS() {
	rc := s.setCmd.Run([]string{"-format", formatJWKS})
	s.Require().Equal(1, rc)
	s.Require().Equal("id is required\n", s.stderr.String())
}

func (s *BundleSuite) TestSetCannotLoadBundleFromFileJWKS() {
	rc := s.setCmd.Run([]string{"-id", "spiffe://otherdomain.test", "-path", "/not/a/real/path/to/a/bundle", "-format", formatJWKS})
	s.Require().Equal(1, rc)
	s.Require().Equal("unable to load bundle data: open /not/a/real/path/to/a/bundle: no such file or directory\n", s.stderr.String())
}

func (s *BundleSuite) TestSetCreatesBundleFromFileJWKS() {
	tmpDir := spiretest.TempDir(s.T())

	bundlePath := filepath.Join(tmpDir, "bundle.pem")

	s.Require().NoError(ioutil.WriteFile(bundlePath, []byte(otherDomainJWKS), 0600))
	s.assertBundleSet("-id", "spiffe://otherdomain.test", "-path", bundlePath, "-format", formatJWKS)
}

func (s *BundleSuite) TestListAllJWKS() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain1.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert1.Raw},
		},
		JwtSigningKeys: []*common.PublicKey{
			{Kid: "KID", PkixBytes: s.key1Pkix},
		},
	})
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain2.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert2.Raw},
		},
	})

	s.Require().Equal(0, s.listCmd.Run([]string{"-format", formatJWKS}))

	s.Require().Equal(`****************************************
* spiffe://domain1.test
****************************************
{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHyvsCk5yi+yhSzNu5aquQwvm8a1Wh+qw1fiHAkhDni+wq+g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KKjODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMS50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIA2dO09Xmakw2ekuHKWC4hBhCkpr5qY4bI8YUcXfxg/1AiEA67kMyH7bQnr7OVLUrL+b9ylAdZglS5kKnYigmwDh+/U="
            ]
        },
        {
            "use": "jwt-svid",
            "kty": "EC",
            "kid": "KID",
            "crv": "P-256",
            "x": "fK-wKTnKL7KFLM27lqq5DC-bxrVaH6rDV-IcCSEOeL4",
            "y": "wq-g3TQWxYlV51TCPH030yXsRxvujD4hUUaIQrXk4KI"
        }
    ]
}

****************************************
* spiffe://domain2.test
****************************************
{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "HxVuaUnxgi431G5D3g9hqeaQhEbsyQZXmaas7qsUC_c",
            "y": "SFd_uVlwYNkXrh0219eHUSD4o-4RGXoiMFJKysw5GK4",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4="
            ]
        }
    ]
}
`, s.stdout.String())
}

func (s *BundleSuite) TestListOneJWKS() {
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain1.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert1.Raw},
		},
	})
	s.createBundle(&common.Bundle{
		TrustDomainId: "spiffe://domain2.test",
		RootCas: []*common.Certificate{
			{DerBytes: s.cert2.Raw},
		},
	})

	s.Require().Equal(0, s.listCmd.Run([]string{"-id", "spiffe://domain2.test", "-format", formatJWKS}))

	s.Require().Equal(`{
    "keys": [
        {
            "use": "x509-svid",
            "kty": "EC",
            "crv": "P-256",
            "x": "HxVuaUnxgi431G5D3g9hqeaQhEbsyQZXmaas7qsUC_c",
            "y": "SFd_uVlwYNkXrh0219eHUSD4o-4RGXoiMFJKysw5GK4",
            "x5c": [
                "MIIBKjCB0aADAgECAgEBMAoGCCqGSM49BAMCMAAwIhgPMDAwMTAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowADBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABB8VbmlJ8YIuN9RuQ94PYanmkIRG7MkGV5mmrO6rFAv3SFd/uVlwYNkXrh0219eHUSD4o+4RGXoiMFJKysw5GK6jODA2MA8GA1UdEwEB/wQFMAMBAf8wIwYDVR0RAQH/BBkwF4YVc3BpZmZlOi8vZG9tYWluMi50ZXN0MAoGCCqGSM49BAMCA0gAMEUCIQDMKwYtq+2ZoNyl4udPj7IMYIGX8yuCNRmh7m3d9tvoDgIgbS26wSwDjngGqdiHHL8fTcggdiIqWtxAqBLFrx8zNS4="
            ]
        }
    ]
}
`, s.stdout.String())
}
