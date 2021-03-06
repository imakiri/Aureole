package postgresql

import (
	"fmt"
	"net/url"
)

// ConnConfig represents a parsed PostgreSQL connection URL
type ConnConfig struct {
	User     string
	Password string
	Host     string
	Port     string
	Database string
	Options  map[string]string
}

// String reassembles PostgreSQL connection config into a valid connection url
func (connConf ConnConfig) String() (string, error) {
	vv := url.Values{}
	if connConf.Options != nil {
		for k, v := range connConf.Options {
			vv.Set(k, v)
		}
	}

	if connConf.AdapterName() == "" ||
		connConf.User == "" ||
		connConf.Password == "" ||
		connConf.Host == "" ||
		connConf.Port == "" ||
		connConf.Database == "" {
		return "", fmt.Errorf("invalid connection url")
	}

	u := url.URL{
		Scheme:     connConf.AdapterName(),
		User:       url.UserPassword(connConf.User, connConf.Password),
		Host:       fmt.Sprintf("%s:%s", connConf.Host, connConf.Port),
		Path:       connConf.Database,
		ForceQuery: false,
		RawQuery:   vv.Encode(),
	}
	return u.String(), nil
}

// DBName returns the name of the database, that we've connected by this config
func (connConf ConnConfig) DBName() string {
	return connConf.Database
}

// AdapterName return the adapter name, that was used to set up connection
func (connConf ConnConfig) AdapterName() string {
	return AdapterName
}
