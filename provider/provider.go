package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func New(version string) func() *schema.Provider {
	return func() *schema.Provider {
		p := &schema.Provider{
			Schema: map[string]*schema.Schema{
				"url": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("LDAP_URL", ""),
				},
				"use_starttls": {
					Type:        schema.TypeBool,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("LDAP_USE_STARTTLS", false),
				},
				"skip_verify": {
					Type:        schema.TypeBool,
					Optional:    true,
					DefaultFunc: schema.EnvDefaultFunc("LDAP_SKIP_VERIFY", false),
				},
				"bind_user": {
					Type:        schema.TypeString,
					Required:    true,
					DefaultFunc: schema.EnvDefaultFunc("LDAP_BIND_USER", nil),
				},
				"bind_password": {
					Type:        schema.TypeString,
					Required:    true,
					Sensitive:   true,
					DefaultFunc: schema.EnvDefaultFunc("LDAP_BIND_PASSWORD", nil),
				},
			},
			ResourcesMap: map[string]*schema.Resource{
				"ldap_object":            resourceLDAPObject(),
				"ldap_object_attributes": resourceLDAPObjectAttributes(),
			},
			DataSourcesMap: map[string]*schema.Resource{
				"ldap_object": dataLDAPObject(),
			},
			ConfigureContextFunc: providerConfigure,
		}

		return p
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	url := d.Get("url").(string)
	useStartTLS := d.Get("use_starttls").(bool)
	skipVerify := d.Get("skip_verify").(bool)
	tlsConfig := tls.Config{InsecureSkipVerify: skipVerify}
	bindUser := d.Get("bind_user").(string)
	bindPassword := d.Get("bind_password").(string)

	l, err := ldap.DialURL(url, ldap.DialWithTLSConfig(&tlsConfig))
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Failed to connect to ldap server",
			Detail:   fmt.Sprintf("Connecting to ldap server failed with: %v", err),
		})
		return nil, diags
	}
	// TODO: https://github.com/hashicorp/terraform-plugin-sdk/issues/63
	// defer l.Close()

	if useStartTLS {
		err = l.StartTLS(&tlsConfig)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Failed to establish StartTLS session",
				Detail:   fmt.Sprintf("Establishing StartTLS session failed with: %v", err),
			})
			return nil, diags
		}
	}

	err = l.Bind(bindUser, bindPassword)
	if err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Failed to perform bind",
			Detail:   fmt.Sprintf("Binding user failed with: %v", err),
		})
		return nil, diags
	}

	return l, diags
}

func leveledLog(level string) func(format string, v ...interface{}) {
	prefix := fmt.Sprintf("[%s] ", strings.ToUpper(level))
	return func(format string, v ...interface{}) {
		log.Printf(prefix+format, v...)
	}
}

var traceLog = leveledLog("trace")
var debugLog = leveledLog("debug")
var infoLog = leveledLog("info")
var warnLog = leveledLog("warn")
var errorLog = leveledLog("error")
