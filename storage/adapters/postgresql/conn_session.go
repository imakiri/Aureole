package postgresql

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v4"
	"gouth/storage"
)

// ConnSession represents a postgresql database
type ConnSession struct {
	ctx      context.Context
	conn     *pgx.Conn
	connConf storage.ConnConfig
	// for abstract queries
	relInfo map[storage.CollPair]storage.RelInfo
}

// Open creates connection with postgresql database
func (s *ConnSession) Open() error {
	str, err := s.connConf.String()
	if err != nil {
		return err
	}

	config, err := pgx.ParseConfig(str)
	if err != nil {
		return err
	}

	conn, err := pgx.ConnectConfig(s.ctx, config)
	if err != nil {
		return err
	}

	s.conn = conn
	return nil
}

// ConnConfig returns the connection url that was used to set up the adapter
func (s *ConnSession) GetConfig() storage.ConnConfig {
	return s.connConf
}

// Ping returns an error if the DBMS could not be reached
func (s *ConnSession) Ping() error {
	var o int
	err := s.conn.QueryRow(context.Background(), "select 1").Scan(&o)
	if err != nil {
		return err
	}

	if o != 1 {
		return errors.New("got invalid data")
	}
	return nil
}

// Close terminates the currently active connection to the DBMS
func (s *ConnSession) Close() error {
	return s.conn.Close(s.ctx)
}
