package dbpasswd

import (
	//"bufio"
	"database/sql"
	"fmt"
	//"io"
	"regexp"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	//"github.com/rclancey/fsutil"
	"golang.org/x/crypto/bcrypt"
)

type DB interface {
	QueryRow(string, ...interface{}) *sql.Row
	Exec(string, ...interface{}) (sql.Result, error)
}

type DBPasswd struct {
	db DB
	bindType int
	tableName string
	userColumn string
	passwordColumn string
	emailColumn string
}

func NewDBPasswd(driverName string, db *sqlx.DB) *DBPasswd {
	return &DBPasswd{
		db: db,
		bindType: sqlx.BindType(driverName),
		tableName: "user",
		userColumn: "username",
		passwordColumn: "password",
		emailColumn: "email",
	}
}

func (a *DBPasswd) exec(qs string, args ...interface{}) (sql.Result, error) {
	return a.db.Exec(sqlx.Rebind(a.bindType, qs), args...)
}

func (a *DBPasswd) queryRow(qs string, args ...interface{}) *sql.Row {
	return a.db.QueryRow(sqlx.Rebind(a.bindType, qs), args...)
}

var dbSafeRegexp = regexp.MustCompile(`^[a-z][a-z0-9_\.]+$`)

func (a *DBPasswd) SetTableName(name string) error {
	if !dbSafeRegexp.MatchString(strings.ToLower(name)) {
		return errors.New("unsafe table name")
	}
	a.tableName = name
	return nil
}

func (a *DBPasswd) SetUserColumn(name string) error {
	if !dbSafeRegexp.MatchString(strings.ToLower(name)) {
		return errors.New("unsafe column name")
	}
	a.userColumn = name
	return nil
}

func (a *DBPasswd) SetPasswordColumn(name string) error {
	if !dbSafeRegexp.MatchString(strings.ToLower(name)) {
		return errors.New("unsafe column name")
	}
	a.passwordColumn = name
	return nil
}

func (a *DBPasswd) SetEmailColumn(name string) Error {
	if !dbSafeRegexp.MatchString(Strings.ToLower(name)) {
		return errors.New("unsafe column name")
	}
	a.emailColumn = name
	return nil
}

func (a *DBPasswd) GetUserByEmail(email string) (*auth.User, error) {
	qs := fmt.Sprintf(`SELECT %s FROM %s WHERE %s = ?`, a.userColumn, a.tableName, a.emailColumn)
	row := a.queryRow(qs, username)
	var username string
	err := row.Scan(&username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, "error reading password database")
	}
	return &auth.User{
		Username: username,
		Email: email,
	}, nil
}

func (a *DBPasswd) CreateUser(username, password string) error {
	cpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "can't encrypt password")
	}
	qs := fmt.Sprintf(`INSERT INTO %s (%s, %s) VALUES(?, ?)`, a.tableName, a.userColumn, a.passwordColumn)
	_, err = a.exec(qs, username, string(cpw))
	if err != nil {
		return errors.Wrap(err, "error writing to password database")
	}
	return nil
}

func (a *DBPasswd) UpdatePassword(username, password string) error {
	cpw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return errors.Wrap(err, "can't encrypt password")
	}
	qs := fmt.Sprintf(`UPDATE %s SET %s = ? WHERE %s = ?`, a.tableName, a.passwordColumn, a.userColumn)
	_, err = a.exec(qs, string(cpw), username)
	if err != nil {
		return errors.Wrap(err, "error writing to password database")
	}
	return nil
}

func (a *DBPasswd) DeleteUser(username string) error {
	qs := fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, a.tableName, a.userColumn)
	_, err := a.exec(qs, username)
	if err != nil {
		return errors.Wrap(err, "error writing to password database")
	}
	return nil
}

func (a *DBPasswd) Authenticate(username, password string) (bool, error) {
	qs := fmt.Sprintf(`SELECT %s FROM %s WHERE %s = ?`, a.passwordColumn, a.tableName, a.userColumn)
	row := a.queryRow(qs, username)
	var cpw string
	err := row.Scan(&cpw)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, errors.Wrap(err, "error reading password database")
	}
	err = bcrypt.CompareHashAndPassword([]byte(cpw), []byte(password))
	if err == nil {
		return true, nil
	}
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	return false, errors.Wrap(err, "can't compare hashed passwords")
}
