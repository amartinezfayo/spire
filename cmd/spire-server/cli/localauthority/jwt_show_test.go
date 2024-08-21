package localauthority_test

import (
	"fmt"
	"testing"

	"github.com/gogo/status"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	"github.com/spiffe/spire/cmd/spire-server/cli/common"
	"github.com/spiffe/spire/cmd/spire-server/cli/localauthority"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func TestJWTShowHelp(t *testing.T) {
	test := setupTest(t, localauthority.NewJWTShowCommandWithEnv)

	test.client.Help()
	require.Equal(t, jwtShowUsage, test.stderr.String())
}

func TestJWTShowSynopsys(t *testing.T) {
	test := setupTest(t, localauthority.NewJWTShowCommandWithEnv)
	require.Equal(t, "Shows the local JWT authorities", test.client.Synopsis())
}

func TestJWTShow(t *testing.T) {
	for _, tt := range []struct {
		name               string
		args               []string
		expectReturnCode   int
		expectStdoutPretty string
		expectStdoutJSON   string
		expectStderr       string
		serverErr          error

		active,
		prepared,
		old *localauthorityv1.AuthorityState
	}{
		{
			name:             "success",
			expectReturnCode: 0,
			active: &localauthorityv1.AuthorityState{
				AuthorityId: "active-id",
				ExpiresAt:   1001,
			},
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
			old: &localauthorityv1.AuthorityState{
				AuthorityId: "old-id",
				ExpiresAt:   1003,
			},
			expectStdoutPretty: "Active JWT authority:\n  Authority ID: active-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n\nPrepared JWT authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n\nOld JWT authority:\n  Authority ID: old-id\n  Expires at: 1970-01-01 00:16:43 +0000 UTC\n",
			expectStdoutJSON:   `{"active":{"authority_id":"active-id","expires_at":"1001"},"prepared":{"authority_id":"prepared-id","expires_at":"1002"},"old":{"authority_id":"old-id","expires_at":"1003"}}`,
		},
		{
			name:             "success - no active",
			expectReturnCode: 0,
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
			old: &localauthorityv1.AuthorityState{
				AuthorityId: "old-id",
				ExpiresAt:   1003,
			},
			expectStdoutPretty: "Active JWT authority:\n  No active JWT authority found\n\nPrepared JWT authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n\nOld JWT authority:\n  Authority ID: old-id\n  Expires at: 1970-01-01 00:16:43 +0000 UTC\n",
			expectStdoutJSON:   `{"prepared":{"authority_id":"prepared-id","expires_at":"1002"},"old":{"authority_id":"old-id","expires_at":"1003"}}`,
		},
		{
			name:             "success - no prepared",
			expectReturnCode: 0,
			active: &localauthorityv1.AuthorityState{
				AuthorityId: "active-id",
				ExpiresAt:   1001,
			},
			old: &localauthorityv1.AuthorityState{
				AuthorityId: "old-id",
				ExpiresAt:   1003,
			},
			expectStdoutPretty: "Active JWT authority:\n  Authority ID: active-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n\nPrepared JWT authority:\n  No prepared JWT authority found\n\nOld JWT authority:\n  Authority ID: old-id\n  Expires at: 1970-01-01 00:16:43 +0000 UTC\n",
			expectStdoutJSON:   `{"active":{"authority_id":"active-id","expires_at":"1001"},"old":{"authority_id":"old-id","expires_at":"1003"}}`,
		},
		{
			name:             "success - no old",
			expectReturnCode: 0,
			active: &localauthorityv1.AuthorityState{
				AuthorityId: "active-id",
				ExpiresAt:   1001,
			},
			prepared: &localauthorityv1.AuthorityState{
				AuthorityId: "prepared-id",
				ExpiresAt:   1002,
			},
			expectStdoutPretty: "Active JWT authority:\n  Authority ID: active-id\n  Expires at: 1970-01-01 00:16:41 +0000 UTC\n\nPrepared JWT authority:\n  Authority ID: prepared-id\n  Expires at: 1970-01-01 00:16:42 +0000 UTC\n\nOld JWT authority:\n  No old JWT authority found\n",
			expectStdoutJSON:   `{"active":{"authority_id":"active-id","expires_at":"1001"},"prepared":{"authority_id":"prepared-id","expires_at":"1002"}}`,
		},
		{
			name:             "wrong UDS path",
			args:             []string{common.AddrArg, common.AddrValue},
			expectReturnCode: 1,
			expectStderr:     common.AddrError,
		},
		{
			name:             "server error",
			serverErr:        status.Error(codes.Internal, "internal server error"),
			expectReturnCode: 1,
			expectStderr:     "Error: rpc error: code = Internal desc = internal server error\n",
		},
	} {
		for _, format := range availableFormats {
			t.Run(fmt.Sprintf("%s using %s format", tt.name, format), func(t *testing.T) {
				test := setupTest(t, localauthority.NewJWTShowCommandWithEnv)
				test.server.activeJWT = tt.active
				test.server.preparedJWT = tt.prepared
				test.server.oldJWT = tt.old
				test.server.err = tt.serverErr
				args := tt.args
				args = append(args, "-output", format)

				returnCode := test.client.Run(append(test.args, args...))

				requireOutputBasedOnFormat(t, format, test.stdout.String(), tt.expectStdoutPretty, tt.expectStdoutJSON)
				require.Equal(t, tt.expectStderr, test.stderr.String())
				require.Equal(t, tt.expectReturnCode, returnCode)
			})
		}
	}
}
