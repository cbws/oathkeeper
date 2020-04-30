package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/ory/go-convenience/stringslice"
	"github.com/ory/x/httpx"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
)

type AuthenticatorOAuth2IntrospectionConfiguration struct {
	Scopes                      []string                                              `json:"required_scope"`
	Audience                    []string                                              `json:"target_audience"`
	Issuers                     []string                                              `json:"trusted_issuers"`
	PreAuth                     *AuthenticatorOAuth2IntrospectionPreAuthConfiguration `json:"pre_authorization"`
	ScopeStrategy               string                                                `json:"scope_strategy"`
	IntrospectionURL            string                                                `json:"introspection_url"`
	BearerTokenLocation         *helper.BearerTokenLocation                           `json:"token_from"`
	IntrospectionRequestHeaders map[string]string                                     `json:"introspection_request_headers"`
	Retry                       *AuthenticatorOAuth2IntrospectionRetryConfiguration   `json:"retry"`
}

type AuthenticatorOAuth2IntrospectionPreAuthConfiguration struct {
	Enabled      bool     `json:"enabled"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scope        []string `json:"scope"`
	TokenURL     string   `json:"token_url"`
}

type AuthenticatorOAuth2IntrospectionRetryConfiguration struct {
	Timeout string `json:"max_delay"`
	MaxWait string `json:"give_up_after"`
}

type AuthenticatorOAuth2Introspection struct {
	c configuration.Provider

	client *http.Client
	cfg    *AuthenticatorOAuth2IntrospectionConfiguration
}

func NewAuthenticatorOAuth2Introspection(c configuration.Provider) *AuthenticatorOAuth2Introspection {
	var rt http.RoundTripper

	return &AuthenticatorOAuth2Introspection{c: c, client: httpx.NewResilientClientLatencyToleranceSmall(rt)}
}

func (a *AuthenticatorOAuth2Introspection) GetID() string {
	return "oauth2_introspection"
}

type AuthenticatorOAuth2IntrospectionResult struct {
	Active    bool                   `json:"active"`
	Extra     map[string]interface{} `json:"ext"`
	Subject   string                 `json:"sub,omitempty"`
	Username  string                 `json:"username"`
	Audience  []string               `json:"aud"`
	TokenType string                 `json:"token_type"`
	Issuer    string                 `json:"iss"`
	ClientID  string                 `json:"client_id,omitempty"`
	Scope     string                 `json:"scope,omitempty"`
}

func (a *AuthenticatorOAuth2Introspection) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	var i AuthenticatorOAuth2IntrospectionResult
	cf, err := a.Config(config)
	if err != nil {
		return err
	}

	token := helper.BearerTokenFromRequest(r, cf.BearerTokenLocation)
	if token == "" {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	body := url.Values{"token": {token}}

	ss := a.c.ToScopeStrategy(cf.ScopeStrategy, "authenticators.oauth2_introspection.scope_strategy")
	if ss == nil {
		body.Add("scope", strings.Join(cf.Scopes, " "))
	}

	introspectReq, err := http.NewRequest(http.MethodPost, cf.IntrospectionURL, strings.NewReader(body.Encode()))
	if err != nil {
		return errors.WithStack(err)
	}
	for key, value := range cf.IntrospectionRequestHeaders {
		introspectReq.Header.Set(key, value)
	}
	// set/override the content-type header
	introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(introspectReq)
	if err != nil {
		return errors.WithStack(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.Errorf("Introspection returned status code %d but expected %d", resp.StatusCode, http.StatusOK)
	}

	if err := json.NewDecoder(resp.Body).Decode(&i); err != nil {
		return errors.WithStack(err)
	}

	if len(i.TokenType) > 0 && i.TokenType != "access_token" {
		return errors.WithStack(helper.ErrForbidden.WithReason(fmt.Sprintf("Introspected token is not an access token but \"%s\"", i.TokenType)))
	}

	if !i.Active {
		return errors.WithStack(helper.ErrUnauthorized.WithReason("Access token i says token is not active"))
	}

	for _, audience := range cf.Audience {
		if !stringslice.Has(i.Audience, audience) {
			return errors.WithStack(helper.ErrForbidden.WithReason(fmt.Sprintf("Token audience is not intended for target audience %s", audience)))
		}
	}

	if len(cf.Issuers) > 0 {
		if !stringslice.Has(cf.Issuers, i.Issuer) {
			return errors.WithStack(helper.ErrForbidden.WithReason(fmt.Sprintf("Token issuer does not match any trusted issuer")))
		}
	}

	if ss != nil {
		for _, scope := range cf.Scopes {
			if !ss(strings.Split(i.Scope, " "), scope) {
				return errors.WithStack(helper.ErrForbidden.WithReason(fmt.Sprintf("Scope %s was not granted", scope)))
			}
		}
	}

	if len(i.Extra) == 0 {
		i.Extra = map[string]interface{}{}
	}

	i.Extra["username"] = i.Username
	i.Extra["client_id"] = i.ClientID
	i.Extra["scope"] = i.Scope

	session.Subject = i.Subject
	session.Extra = i.Extra

	return nil
}

func (a *AuthenticatorOAuth2Introspection) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorOAuth2Introspection) Config(config json.RawMessage) (*AuthenticatorOAuth2IntrospectionConfiguration, error) {
	if a.cfg != nil {
		log.Printf("Reuse config")

		return a.cfg, nil
	}

	var c AuthenticatorOAuth2IntrospectionConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	var rt http.RoundTripper

	if c.PreAuth != nil && c.PreAuth.Enabled {
		log.Printf("Preauth! %+v", c.PreAuth)
		c2 := &clientcredentials.Config{
			ClientID:     c.PreAuth.ClientID,
			ClientSecret: c.PreAuth.ClientSecret,
			Scopes:       c.PreAuth.Scope,
			TokenURL:     c.PreAuth.TokenURL,
			AuthStyle: oauth2.AuthStyleInParams,
		}
		source := NewNotifyingTokenSource(oauth2.ReuseTokenSource(nil, c2.TokenSource(context.Background())), func(token *oauth2.Token) error {
			log.Printf("New token: %+v (Valid: %t)", token, token.Valid())

			return nil
		})
		rt = &oauth2.Transport{
			Source: source,
		}
	}

	if c.Retry == nil {
		c.Retry = &AuthenticatorOAuth2IntrospectionRetryConfiguration{Timeout: "500ms", MaxWait: "1s"}
	} else {
		if c.Retry.Timeout == "" {
			c.Retry.Timeout = "500ms"
		}
		if c.Retry.MaxWait == "" {
			c.Retry.MaxWait = "1s"
		}
	}
	duration, err := time.ParseDuration(c.Retry.Timeout)
	if err != nil {
		return nil, err
	}
	timeout := time.Millisecond * duration

	maxWait, err := time.ParseDuration(c.Retry.MaxWait)
	if err != nil {
		return nil, err
	}

	a.client = httpx.NewResilientClientLatencyToleranceConfigurable(rt, timeout, maxWait)

	a.cfg = &c

	return &c, nil
}


// TokenNotifyFunc is a function that accepts an oauth2 Token upon refresh, and
// returns an error if it should not be used.
type TokenNotifyFunc func(*oauth2.Token) error

// NotifyingTokenSource is an oauth2.TokenSource that calls a function when a
// new token is obtained.
type NotifyingTokenSource struct {
	f   TokenNotifyFunc
	src oauth2.TokenSource
}

// NewNotifyingTokenSource creates a NotifyingTokenSource from an underlying src
// and calls f when a new token is obtained.
func NewNotifyingTokenSource(src oauth2.TokenSource, f TokenNotifyFunc) *NotifyingTokenSource {
	return &NotifyingTokenSource{f: f, src: src}
}

// Token fetches a new token from the underlying source.
func (s *NotifyingTokenSource) Token() (*oauth2.Token, error) {
	t, err := s.src.Token()
	if err != nil {
		return nil, err
	}
	if s.f == nil {
		return t, nil
	}
	return t, s.f(t)
}
