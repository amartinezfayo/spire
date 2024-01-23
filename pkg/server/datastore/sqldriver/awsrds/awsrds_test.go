package awsrds

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

const (
	fakePostgresDriverName = "aws-rds-postgres-fake"
	fakeMySQLDriverName    = "aws-rds-mysql-fake"
	token                  = "aws-rds-host:1234?Action=connect&DBUser=test_user&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=TESTTESTTESTTESTTEST%2F20240116%2Fus-east-2%2Frds-db%2Faws4_request&X-Amz-Date=20240116T150146Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host&X-Amz-Signature=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" //nolint: gosec // for testing
	mysqlConnString        = "test_user:@tcp(aws-rds-host:1234)/spire?parseTime=true&allowCleartextPasswords=1&tls=true"
	postgresConnString     = "dbname=postgres user=postgres host=the-host sslmode=require"
)

var (
	fakeSQLDriverWrapper = &sqlDriverWrapper{
		sqlDriver:    &fakeSQLDriver{},
		tokenBuilder: &fakeTokenBuilder{},
		tokensMap:    make(tokens),
	}
)

func TestAWSRDS(t *testing.T) {
	testCases := []struct {
		name          string
		config        *Config
		sqlDriver     *fakeSQLDriver
		tokenProvider *fakeTokenBuilder
		authToken     string
		expectedError string
	}{
		{
			name: "with static credentials",
			config: &Config{
				DriverName:      MySQLDriverName,
				ConnString:      mysqlConnString,
				AccessKeyID:     "access-key-id",
				SecretAccessKey: "secret-access-key",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
		},
		{
			name: "mysql - success",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
		},
		{
			name: "mysql - invalid connection string",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: "not-valid!",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "could not parse connection string: invalid DSN: missing the slash separating the database name",
		},
		{
			name: "mysql - password already present",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: "test_user:test-password@tcp(aws-rds-host:1234)/spire?parseTime=true&allowCleartextPasswords=1&tls=true",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "password was provided in the connection string",
		},
		{
			name: "malformed token",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: "invalid;token",
			},
			expectedError: "could not get authorization token: failed to parse authentication token: invalid semicolon separator in query",
		},
		{
			name: "no X-Amz-Date",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: "a&b=c",
			},
			expectedError: "could not get authorization token: malformed token: could not get X-Amz-Date value",
		},
		{
			name: "more than one X-Amz-Date",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: "a&X-Amz-Date=123&X-Amz-Date=123",
			},
			expectedError: "could not get authorization token: malformed token: could not get X-Amz-Date value",
		},
		{
			name: "invalid X-Amz-Date",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: "a&X-Amz-Date=invalid",
			},
			expectedError: "could not get authorization token: failed to parse X-Amz-Date date: parsing time \"invalid\" as \"20060102T150405Z\": cannot parse \"invalid\" as \"2006\"",
		},
		{
			name: "no X-Amz-Expires",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: "a&X-Amz-Date=20240116T150146Z",
			},
			expectedError: "could not get authorization token: malformed token: could not get X-Amz-Expires value",
		},
		{
			name: "more than one X-Amz-Expires",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: "a&X-Amz-Date=20240116T150146Z&X-Amz-Expires=1&X-Amz-Expires=1",
			},
			expectedError: "could not get authorization token: malformed token: could not get X-Amz-Expires value",
		},
		{
			name: "invalid X-Amz-Expires",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: "a&X-Amz-Date=20240116T150146Z&X-Amz-Expires=zz",
			},
			expectedError: "could not get authorization token: failed to parse duration: time: invalid duration \"zzs\"",
		},
		{
			name: "build auth token error",
			config: &Config{
				DriverName: MySQLDriverName,
				ConnString: mysqlConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
				err:       errors.New("ohno"),
			},
			expectedError: "could not get authorization token: failed to build authentication token: ohno",
		},
		{
			name: "postgres - success",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: postgresConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
		},
		{
			name: "postgres - invalid connection string",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: "not-valid!",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "could not parse connection string: cannot parse `not-valid!`: failed to parse as DSN (invalid dsn)",
		},
		{
			name: "postgres - password already present",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: "password=the-password",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "password was provided in the connection string",
		},
		{
			name: "postgres - success",
			config: &Config{
				DriverName: PostgresDriverName,
				ConnString: postgresConnString,
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
		},
		{
			name: "unknown driver",
			config: &Config{
				DriverName: "unknown",
			},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "driver \"unknown\" is not supported",
		},
		{
			name:   "no driver",
			config: &Config{},
			tokenProvider: &fakeTokenBuilder{
				authToken: token,
			},
			expectedError: "missing driver name",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			dsn, err := testCase.config.FormatDSN()
			require.NoError(t, err)

			fakeSQLDriverWrapper.tokenBuilder = testCase.tokenProvider

			db, err := gorm.Open(fakeMySQLDriverName, dsn)
			if testCase.expectedError != "" {
				require.EqualError(t, err, testCase.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, db)
		})
	}
}

func TestCacheToken(t *testing.T) {
	config := &Config{
		DriverName: MySQLDriverName,
		ConnString: mysqlConnString,
	}
	dsn, err := config.FormatDSN()
	require.NoError(t, err)

	now := time.Now().UTC()
	nowString := now.Format(iso8601BasicFormat)

	// Set a first token to be always returned by the token builder.
	firstToken := fmt.Sprintf("X-Amz-Date=%s&X-Amz-Expires=900&X-Amz-Signature=first-token", nowString)
	fakeSQLDriverWrapper.tokenBuilder = &fakeTokenBuilder{
		authToken: firstToken,
	}
	fakeSQLDriverWrapper.tokensMap = make(tokens)

	// There should be no token for this dsn yet.
	require.Empty(t, fakeSQLDriverWrapper.tokensMap[dsn])

	// Calling to Open should map firstToken to the dsn.
	db, err := gorm.Open(fakeMySQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	// Retrieve the token.
	token, err := fakeSQLDriverWrapper.tokensMap[dsn].getAWSAuthToken(context.Background(), config, fakeSQLDriverWrapper.tokenBuilder)
	require.NoError(t, err)

	// The token retrieved should be the same firstToken.
	require.Equal(t, firstToken, token)

	// We will now test that we don't call the token builder if we have a valid
	// token (not expired) that we can use. For that, we start by setting a new
	// token that will be returned by the token builder when getAWSAuthToken is
	// called.
	newToken := fmt.Sprintf("X-Amz-Date=%s&X-Amz-Expires=900&X-Amz-Signature=second-token", nowString)
	fakeSQLDriverWrapper.tokenBuilder = &fakeTokenBuilder{
		authToken: newToken,
	}

	// Call Open again, the cached token should be used.
	db, err = gorm.Open(fakeMySQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	// Retrieve the token.
	token, err = fakeSQLDriverWrapper.tokensMap[dsn].getAWSAuthToken(context.Background(), config, fakeSQLDriverWrapper.tokenBuilder)
	require.NoError(t, err)

	// The token retrieved should be the cached firstToken.
	require.Equal(t, firstToken, token)

	// We will now make firstToken to expire, so we can test that the token
	// builder is called to get a new token when the current token has expired.
	// For that, we advance the clock one hour.
	fakeSQLDriverWrapper.tokensMap[dsn].setNowFunc(func() time.Time { return now.Add(time.Hour) })

	// Call Open again, the new token should be used.
	db, err = gorm.Open(fakeMySQLDriverName, dsn)
	require.NoError(t, err)
	require.NotNil(t, db)

	// Retrieve the token.
	token, err = fakeSQLDriverWrapper.tokensMap[dsn].getAWSAuthToken(context.Background(), config, fakeSQLDriverWrapper.tokenBuilder)
	require.NoError(t, err)

	// The token retrieved should be the new token.
	require.Equal(t, newToken, token)
}

func TestFormatDSN(t *testing.T) {
	config := &Config{
		Region:          "region",
		AccessKeyID:     "access-key-id",
		SecretAccessKey: "secret-access-key",
		Endpoint:        "endpoint",
		DbUser:          "dbUser",
		DriverName:      "driver-name",
		ConnString:      "connection-string",
	}

	dsn, err := config.FormatDSN()
	require.NoError(t, err)
	require.Equal(t, "{\"region\":\"region\",\"access_key_id\":\"access-key-id\",\"secret_access_key\":\"secret-access-key\",\"endpoint\":\"endpoint\",\"dbuser\":\"dbUser\",\"driver_name\":\"driver-name\",\"conn_string\":\"connection-string\"}", dsn)
}

type fakeTokenBuilder struct {
	authToken string
	err       error
}

func (a *fakeTokenBuilder) buildAuthToken(context.Context, string, string, string, aws.CredentialsProvider, ...func(*auth.BuildAuthTokenOptions)) (string, error) {
	return a.authToken, a.err
}

type fakeSQLDriver struct {
	err error
}

func (d *fakeSQLDriver) Open(string) (driver.Conn, error) {
	return nil, d.err
}

func init() {
	sql.Register(fakePostgresDriverName, fakeSQLDriverWrapper)
	sql.Register(fakeMySQLDriverName, fakeSQLDriverWrapper)
}
