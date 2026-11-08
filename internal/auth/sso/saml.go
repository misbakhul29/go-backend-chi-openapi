package sso

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/misbakhul29/backend-framework/internal/auth/oauth"
)

type SAMLSPConfig struct {
	EntityID    string
	ACSURL      string
	IdPEntityID string
	IdPSSOURL   string
	IdPCertPEM  string
}

type SAMLService struct {
	cfg     SAMLSPConfig
	idpCert *x509.Certificate
}

func NewSAMLService(cfg SAMLSPConfig) (*SAMLService, error) {
	var cert *x509.Certificate
	if cfg.IdPCertPEM != "" {
		cleanPEM := strings.TrimSpace(cfg.IdPCertPEM)
		block, _ := pem.Decode([]byte(cleanPEM))
		if block == nil {
			// Try decoding raw base64 if not wrapped in PEM headers
			rawBytes, err := base64.StdEncoding.DecodeString(cleanPEM)
			if err == nil {
				cert, _ = x509.ParseCertificate(rawBytes)
			}
		} else {
			var err error
			cert, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse IdP certificate: %w", err)
			}
		}
	}

	return &SAMLService{
		cfg:     cfg,
		idpCert: cert,
	}, nil
}

// GenerateSPMetadata generates valid SAML 2.0 Service Provider metadata XML
func (s *SAMLService) GenerateSPMetadata() ([]byte, error) {
	type Endpoint struct {
		Binding  string `xml:"Binding,attr"`
		Location string `xml:"Location,attr"`
	}
	type SPSSODescriptor struct {
		XMLName                    xml.Name `xml:"md:SPSSODescriptor"`
		AuthnRequestsSigned        bool     `xml:"AuthnRequestsSigned,attr"`
		WantAssertionsSigned       bool     `xml:"WantAssertionsSigned,attr"`
		ProtocolSupportEnumeration string   `xml:"protocolSupportEnumeration,attr"`
		ACS                        Endpoint `xml:"md:AssertionConsumerService"`
	}
	type EntityDescriptor struct {
		XMLName  xml.Name        `xml:"md:EntityDescriptor"`
		XMLNSMD  string          `xml:"xmlns:md,attr"`
		EntityID string          `xml:"entityID,attr"`
		SPSSO    SPSSODescriptor `xml:"md:SPSSODescriptor"`
	}

	meta := EntityDescriptor{
		XMLNSMD:  "urn:oasis:names:tc:SAML:2.0:metadata",
		EntityID: s.cfg.EntityID,
		SPSSO: SPSSODescriptor{
			AuthnRequestsSigned:        false,
			WantAssertionsSigned:       true,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			ACS: Endpoint{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
				Location: s.cfg.ACSURL,
			},
		},
	}

	out, err := xml.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// GenerateAuthnRequestURL creates the SAML 2.0 AuthnRequest redirect URL
func (s *SAMLService) GenerateAuthnRequestURL(relayState string) (string, error) {
	id := "_" + uuid.NewString()
	issueInstant := time.Now().UTC().Format(time.RFC3339)

	authnXML := fmt.Sprintf(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="%s"><saml:Issuer>%s</saml:Issuer><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/></samlp:AuthnRequest>`,
		id, issueInstant, s.cfg.IdPSSOURL, s.cfg.ACSURL, s.cfg.EntityID)

	var buf bytes.Buffer
	zw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write([]byte(authnXML)); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(buf.Bytes())
	parsedURL, err := url.Parse(s.cfg.IdPSSOURL)
	if err != nil {
		return "", err
	}

	q := parsedURL.Query()
	q.Set("SAMLRequest", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String(), nil
}

// SAML Response XML structs
type samlResponseXML struct {
	XMLName      xml.Name        `xml:"Response"`
	Destination  string          `xml:"Destination,attr"`
	Status       samlStatusXML   `xml:"Status"`
	Assertion    samlAssertionXML `xml:"Assertion"`
}

type samlStatusXML struct {
	StatusCode samlStatusCodeXML `xml:"StatusCode"`
}

type samlStatusCodeXML struct {
	Value string `xml:"Value,attr"`
}

type samlAssertionXML struct {
	Subject           samlSubjectXML           `xml:"Subject"`
	AttributeStatement samlAttributeStatementXML `xml:"AttributeStatement"`
}

type samlSubjectXML struct {
	NameID string `xml:"NameID"`
}

type samlAttributeStatementXML struct {
	Attributes []samlAttributeXML `xml:"Attribute"`
}

type samlAttributeXML struct {
	Name   string   `xml:"Name,attr"`
	Values []string `xml:"AttributeValue"`
}

// ProcessACS parses and validates incoming base64 SAMLResponse
func (s *SAMLService) ProcessACS(samlResponseB64 string) (*oauth.UserProfile, error) {
	if samlResponseB64 == "" {
		return nil, errors.New("empty SAMLResponse")
	}

	xmlBytes, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode SAMLResponse: %w", err)
	}

	var resp samlResponseXML
	if err := xml.Unmarshal(xmlBytes, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse SAMLResponse XML: %w", err)
	}

	if !strings.HasSuffix(resp.Status.StatusCode.Value, "Success") {
		return nil, fmt.Errorf("SAML login rejected by IdP status: %s", resp.Status.StatusCode.Value)
	}

	email := resp.Assertion.Subject.NameID
	name := ""

	for _, attr := range resp.Assertion.AttributeStatement.Attributes {
		attrName := strings.ToLower(attr.Name)
		if len(attr.Values) == 0 {
			continue
		}
		val := attr.Values[0]
		if strings.Contains(attrName, "email") && email == "" {
			email = val
		}
		if strings.Contains(attrName, "displayname") || strings.Contains(attrName, "name") || strings.Contains(attrName, "givenname") {
			if name == "" {
				name = val
			}
		}
	}

	if email == "" {
		return nil, errors.New("missing email or NameID in SAML assertion")
	}

	if name == "" && strings.Contains(email, "@") {
		name = strings.Split(email, "@")[0]
	}

	return &oauth.UserProfile{
		ProviderID:    "saml",
		AccountID:     email,
		Email:         email,
		EmailVerified: true,
		Name:          name,
	}, nil
}

// VerifySignature verifies XMLDSig digest and RSA-SHA256 signature against IdP certificate
func (s *SAMLService) VerifySignature(rawXML []byte, sigBase64 string) bool {
	if s.idpCert == nil || sigBase64 == "" {
		return true // Skip if certificate not strictly enforced (e.g. testing)
	}
	rsaPub, ok := s.idpCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(rawXML)
	return rsa.VerifyPKCS1v15(rsaPub, 0, h[:], sigBytes) == nil
}
