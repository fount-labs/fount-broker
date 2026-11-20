package coordinator_test

import (
	"testing"

	"github.com/fount-labs/fount-broker/internal/coordinator"
	"github.com/fount-labs/fount-broker/internal/s3bucket"
	"github.com/fount-labs/fount-broker/internal/s3bucket/s3buckettest"
)

// The restore drill (docs/backups.md) through the S3 client, its SigV4
// requests, write-once Puts and paged Lists, against a bucket over HTTP.
func TestTheRestoreRunbookDrill(t *testing.T) {
	fake, srv := s3buckettest.Start(t, "AKIDDRILL")
	bucket, err := s3bucket.New(s3bucket.Config{Endpoint: srv.URL, Region: "us-east-1", AccessKeyID: "AKIDDRILL", SecretAccessKey: "drill-secret"})
	if err != nil {
		t.Fatal(err)
	}
	coordinator.RestoreRunbookDrill(t, bucket)
	if fake.Len() == 0 {
		t.Fatal("nothing reached the bucket")
	}
}
