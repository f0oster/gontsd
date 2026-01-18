package resolve

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// LDAPClient wraps an LDAP connection with configuration.
type LDAPClient struct {
	conn   *ldap.Conn
	config LDAPConfig
}

// NewLDAPClient creates a new LDAP client and establishes a connection.
func NewLDAPClient(config LDAPConfig) (*LDAPClient, error) {
	conn, err := ldap.DialURL(config.Server)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	if config.UseTLS {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	if config.BindDN != "" {
		err = conn.Bind(config.BindDN, config.Password)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to bind: %w", err)
		}
	}

	return &LDAPClient{
		conn:   conn,
		config: config,
	}, nil
}

// Conn returns the underlying LDAP connection.
func (c *LDAPClient) Conn() *ldap.Conn {
	return c.conn
}

// BaseDN returns the configured base DN.
func (c *LDAPClient) BaseDN() string {
	return c.config.BaseDN
}

// Close closes the LDAP connection.
func (c *LDAPClient) Close() error {
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}
