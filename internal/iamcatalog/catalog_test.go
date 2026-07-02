package iamcatalog_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/terraform-provider-iamencode/internal/iamcatalog"
)

// newFakeServer wires up an index plus per-service handlers that record how
// many times each path was hit, so tests can assert caching/singleflight.
type fakeServer struct {
	server *httptest.Server
	hits   sync.Map // path -> *atomic.Int64
}

func newFakeServer(t *testing.T, services map[string][]string) *fakeServer {
	t.Helper()
	fs := &fakeServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fs.bump(r.URL.Path)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "[")
		first := true
		for prefix := range services {
			if !first {
				fmt.Fprint(w, ",")
			}
			first = false
			fmt.Fprintf(w, `{"service":%q,"url":%q}`, prefix, fs.server.URL+"/v1/"+prefix+"/"+prefix+".json")
		}
		fmt.Fprint(w, "]")
	})
	for prefix, actions := range services {
		path := "/v1/" + prefix + "/" + prefix + ".json"
		acts := actions
		name := prefix
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			fs.bump(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"Name":%q,"Actions":[`, name)
			for i, a := range acts {
				if i > 0 {
					fmt.Fprint(w, ",")
				}
				fmt.Fprintf(w, `{"Name":%q}`, a)
			}
			fmt.Fprint(w, "]}")
		})
	}
	fs.server = httptest.NewServer(mux)
	t.Cleanup(fs.server.Close)
	return fs
}

// fakeServiceData lets newFakeServerWithKeys describe a richer service shape
// (per-action condition keys + per-action resource types + service-level keys
// + resource type ARN templates) for the checkConditions / checkResources
// tests. Every field is optional; absent or empty maps serialize as empty
// JSON arrays, which the catalog parser handles identically to truly absent.
type fakeServiceData struct {
	actions            map[string][]string            // action -> ActionConditionKeys
	actionResources    map[string][]string            // action -> list of Resources[].Name
	actionResourceKeys map[string]map[string][]string // action -> resource type -> Actions[].Resources[].ConditionKeys
	svcConditionKeys   []string                       // service-level ConditionKeys[] names
	svcKeyTypes        map[string]string              // optional: key name -> declared type (e.g. "Numeric")
	resources          map[string][]string            // resource type -> ARN format templates
	resourceKeys       map[string][]string            // resource type -> top-level Resources[].ConditionKeys
}

func newFakeServerWithKeys(t *testing.T, services map[string]fakeServiceData) *fakeServer {
	t.Helper()
	fs := &fakeServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fs.bump(r.URL.Path)
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "[")
		first := true
		for prefix := range services {
			if !first {
				fmt.Fprint(w, ",")
			}
			first = false
			fmt.Fprintf(w, `{"service":%q,"url":%q}`, prefix, fs.server.URL+"/v1/"+prefix+"/"+prefix+".json")
		}
		fmt.Fprint(w, "]")
	})
	for prefix, data := range services {
		path := "/v1/" + prefix + "/" + prefix + ".json"
		name := prefix
		d := data
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			fs.bump(r.URL.Path)
			fmt.Fprintf(w, `{"Name":%q,"Actions":[`, name)
			i := 0
			for action, keys := range d.actions {
				if i > 0 {
					fmt.Fprint(w, ",")
				}
				i++
				fmt.Fprintf(w, `{"Name":%q,"ActionConditionKeys":[`, action)
				for j, k := range keys {
					if j > 0 {
						fmt.Fprint(w, ",")
					}
					fmt.Fprintf(w, "%q", k)
				}
				fmt.Fprint(w, `],"Resources":[`)
				for j, rt := range d.actionResources[action] {
					if j > 0 {
						fmt.Fprint(w, ",")
					}
					fmt.Fprintf(w, `{"Name":%q,"ConditionKeys":[`, rt)
					for k, ck := range d.actionResourceKeys[action][rt] {
						if k > 0 {
							fmt.Fprint(w, ",")
						}
						fmt.Fprintf(w, "%q", ck)
					}
					fmt.Fprint(w, "]}")
				}
				fmt.Fprint(w, "]}")
			}
			fmt.Fprint(w, `],"ConditionKeys":[`)
			for j, k := range d.svcConditionKeys {
				if j > 0 {
					fmt.Fprint(w, ",")
				}
				if t, ok := d.svcKeyTypes[k]; ok {
					fmt.Fprintf(w, `{"Name":%q,"Types":[%q]}`, k, t)
				} else {
					fmt.Fprintf(w, `{"Name":%q}`, k)
				}
			}
			fmt.Fprint(w, `],"Resources":[`)
			j := 0
			for rtype, formats := range d.resources {
				if j > 0 {
					fmt.Fprint(w, ",")
				}
				j++
				fmt.Fprintf(w, `{"Name":%q,"ARNFormats":[`, rtype)
				for k, f := range formats {
					if k > 0 {
						fmt.Fprint(w, ",")
					}
					fmt.Fprintf(w, "%q", f)
				}
				fmt.Fprint(w, `],"ConditionKeys":[`)
				for k, ck := range d.resourceKeys[rtype] {
					if k > 0 {
						fmt.Fprint(w, ",")
					}
					fmt.Fprintf(w, "%q", ck)
				}
				fmt.Fprint(w, "]}")
			}
			fmt.Fprint(w, "]}")
		})
	}
	fs.server = httptest.NewServer(mux)
	t.Cleanup(fs.server.Close)
	return fs
}

func (fs *fakeServer) bump(path string) {
	v, _ := fs.hits.LoadOrStore(path, new(atomic.Int64))
	v.(*atomic.Int64).Add(1)
}

func (fs *fakeServer) count(path string) int64 {
	v, ok := fs.hits.Load(path)
	if !ok {
		return 0
	}
	return v.(*atomic.Int64).Load()
}

// fastRetries shrinks the retry backoff so tests that exercise the retry
// path do not sleep for real. Restored on cleanup.
func fastRetries(t *testing.T) {
	t.Helper()
	t.Cleanup(iamcatalog.SetRetryBaseDelay(time.Millisecond))
}

func TestCatalog_Lookup_OK(t *testing.T) {
	fs := newFakeServer(t, map[string][]string{
		"s3": {"GetObject", "PutObject", "ListBucket"},
	})
	c := iamcatalog.New(fs.server.URL)
	svc, err := c.Lookup(context.Background(), "s3")
	require.NoError(t, err)
	assert.True(t, svc.HasAction("GetObject"))
	assert.True(t, svc.HasAction("getobject"), "matching should be case-insensitive")
	assert.False(t, svc.HasAction("Frobnicate"))
}

func TestCatalog_Lookup_CachesResult(t *testing.T) {
	fs := newFakeServer(t, map[string][]string{"s3": {"GetObject"}})
	c := iamcatalog.New(fs.server.URL)
	for range 5 {
		_, err := c.Lookup(context.Background(), "s3")
		require.NoError(t, err)
	}
	assert.Equal(t, int64(1), fs.count("/"), "index fetched once")
	assert.Equal(t, int64(1), fs.count("/v1/s3/s3.json"), "service fetched once")
}

func TestCatalog_Lookup_UnknownServicePrefix(t *testing.T) {
	fs := newFakeServer(t, map[string][]string{"s3": {"GetObject"}})
	c := iamcatalog.New(fs.server.URL)
	_, err := c.Lookup(context.Background(), "s3xx")
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnknownService)
}

func TestCatalog_Lookup_CaseInsensitivePrefix(t *testing.T) {
	fs := newFakeServer(t, map[string][]string{"s3": {"GetObject"}})
	c := iamcatalog.New(fs.server.URL)
	svc, err := c.Lookup(context.Background(), "S3")
	require.NoError(t, err)
	assert.True(t, svc.HasAction("GetObject"))
}

func TestCatalog_Lookup_IndexUnavailable(t *testing.T) {
	fastRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := iamcatalog.New(srv.URL)
	_, err := c.Lookup(context.Background(), "s3")
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
}

func TestCatalog_Lookup_ServiceJSONUnavailable(t *testing.T) {
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `[{"service":"s3","url":%q}]`, srv.URL+"/v1/s3/s3.json")
	})
	mux.HandleFunc("/v1/s3/s3.json", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	})
	c := iamcatalog.New(srv.URL)
	_, err := c.Lookup(context.Background(), "s3")
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
}

func TestCatalog_Lookup_RetriesTransientIndexError(t *testing.T) {
	// A 503 from the index is retried with backoff within the same Lookup;
	// once the endpoint recovers, the call succeeds without surfacing an error.
	fastRetries(t)
	var indexHits atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		if indexHits.Add(1) < iamcatalog.MaxFetchAttempts {
			http.Error(w, "throttled", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `[{"service":"s3","url":%q}]`, srv.URL+"/v1/s3/s3.json")
	})
	mux.HandleFunc("/v1/s3/s3.json", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"Name":"s3","Actions":[{"Name":"GetObject"}]}`)
	})
	c := iamcatalog.New(srv.URL)
	svc, err := c.Lookup(context.Background(), "s3")
	require.NoError(t, err)
	assert.True(t, svc.HasAction("GetObject"))
	assert.Equal(t, int64(iamcatalog.MaxFetchAttempts), indexHits.Load())
}

func TestCatalog_Lookup_RetriesTransientServiceError(t *testing.T) {
	// Same as above but for the per-service fetch: two 503s, then success.
	fastRetries(t)
	var svcHits atomic.Int64
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `[{"service":"s3","url":%q}]`, srv.URL+"/v1/s3/s3.json")
	})
	mux.HandleFunc("/v1/s3/s3.json", func(w http.ResponseWriter, _ *http.Request) {
		if svcHits.Add(1) < iamcatalog.MaxFetchAttempts {
			http.Error(w, "throttled", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, `{"Name":"s3","Actions":[{"Name":"GetObject"}]}`)
	})
	c := iamcatalog.New(srv.URL)
	svc, err := c.Lookup(context.Background(), "s3")
	require.NoError(t, err)
	assert.True(t, svc.HasAction("GetObject"))
	assert.Equal(t, int64(iamcatalog.MaxFetchAttempts), svcHits.Load())
}

func TestCatalog_Lookup_RetryGivesUpAfterMaxAttempts(t *testing.T) {
	// A persistent 503 exhausts the retry budget and surfaces ErrUnavailable;
	// the endpoint is hit exactly maxFetchAttempts times, not forever.
	fastRetries(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	c := iamcatalog.New(srv.URL)
	_, err := c.Lookup(context.Background(), "s3")
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
	assert.Equal(t, int64(iamcatalog.MaxFetchAttempts), hits.Load())
}

func TestCatalog_Lookup_NoRetryOnNonTransientStatus(t *testing.T) {
	// 4xx statuses other than 429 reflect a real mismatch (wrong URL, gone
	// resource), not a blip; they must fail on the first attempt.
	fastRetries(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	c := iamcatalog.New(srv.URL)
	_, err := c.Lookup(context.Background(), "s3")
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
	assert.Equal(t, int64(1), hits.Load(), "non-transient status must not be retried")
}

func TestCatalog_Lookup_IndexErrorIsSticky(t *testing.T) {
	// The retry budget for a transient failure is spent inside the first
	// fetch (maxFetchAttempts tries with backoff). Once exhausted, the failure
	// latches: subsequent Lookups must not refetch, since that would
	// repeatedly stall every plan when the endpoint is down for good.
	fastRetries(t)
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := iamcatalog.New(srv.URL)
	for range 3 {
		_, err := c.Lookup(context.Background(), "s3")
		assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
	}
	assert.Equal(t, int64(iamcatalog.MaxFetchAttempts), hits.Load(),
		"one round of retries on the first Lookup, then the failure latches")
}

func TestCatalog_Lookup_ConcurrentSingleflight(t *testing.T) {
	// Block the service handler so 20 parallel callers pile up on the same
	// in-flight fetch. singleflight should coalesce them into one request.
	release := make(chan struct{})
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	var svcHits atomic.Int64
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `[{"service":"s3","url":%q}]`, srv.URL+"/v1/s3/s3.json")
	})
	mux.HandleFunc("/v1/s3/s3.json", func(w http.ResponseWriter, _ *http.Request) {
		svcHits.Add(1)
		<-release
		fmt.Fprint(w, `{"Name":"s3","Actions":[{"Name":"GetObject"}]}`)
	})
	c := iamcatalog.New(srv.URL)

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make([]error, n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.Lookup(context.Background(), "s3")
		}(i)
	}
	// Give the goroutines a moment to all hit Lookup before releasing.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	for _, e := range errs {
		require.NoError(t, e)
	}
	assert.Equal(t, int64(1), svcHits.Load(), "all 20 concurrent lookups coalesced into one fetch")
}

func TestCatalog_New_EmptyEndpointFallsBack(t *testing.T) {
	c := iamcatalog.New("")
	assert.Equal(t, iamcatalog.DefaultEndpoint, c.Endpoint())
}

func TestCatalog_New_TrimsTrailingSlash(t *testing.T) {
	c := iamcatalog.New("https://example.test/")
	assert.Equal(t, "https://example.test", c.Endpoint())
}

func TestCatalog_Lookup_CallerCancel_DoesNotPoisonCache(t *testing.T) {
	// Under singleflight, the first caller's ctx used to be threaded into the
	// HTTP fetch. Canceling that ctx would make every coalesced caller see the
	// failure, and it would be cached forever. The fix routes the fetch through
	// a fresh context.Background(); this test asserts the contract by
	// canceling the first caller mid-flight and verifying a fresh Lookup still
	// succeeds.
	release := make(chan struct{})
	handlerEntered := make(chan struct{})
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `[{"service":"s3","url":%q}]`, srv.URL+"/v1/s3/s3.json")
	})
	mux.HandleFunc("/v1/s3/s3.json", func(w http.ResponseWriter, _ *http.Request) {
		close(handlerEntered)
		<-release
		fmt.Fprint(w, `{"Name":"s3","Actions":[{"Name":"GetObject"}]}`)
	})
	c := iamcatalog.New(srv.URL)

	ctxA, cancelA := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = c.Lookup(ctxA, "s3")
		close(done)
	}()
	<-handlerEntered
	cancelA()      // would have killed the fetch under the old code
	close(release) // let the handler complete
	<-done

	svc, err := c.Lookup(context.Background(), "s3")
	require.NoError(t, err)
	assert.True(t, svc.HasAction("GetObject"))
}

func TestCatalog_Lookup_RejectsOversizedResponse(t *testing.T) {
	// IAMENCODE_SERVICEREF_ENDPOINT is user-configurable, so the fetcher must
	// not allow a hostile endpoint to balloon memory. io.LimitReader truncates
	// the response at maxResponseBytes; json.Decode then fails on the
	// incomplete payload and we surface ErrUnavailable.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `[{"service":"s3","url":%q}]`, srv.URL+"/v1/s3/s3.json")
	})
	mux.HandleFunc("/v1/s3/s3.json", func(w http.ResponseWriter, _ *http.Request) {
		// Opens a JSON array, then floods the reader past the limit with
		// padding that is also valid JSON whitespace, so decoding finishes
		// (without seeing the closing bracket) with unexpected EOF.
		_, _ = w.Write([]byte("["))
		junk := bytes.Repeat([]byte(" "), 1<<20)
		for range iamcatalog.MaxResponseBytes/len(junk) + 2 {
			_, _ = w.Write(junk)
		}
	})
	c := iamcatalog.New(srv.URL)
	_, err := c.Lookup(context.Background(), "s3")
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
}

func TestService_HasAction_NilReceiver(t *testing.T) {
	// Nil-safe so callers can chain Lookup() -> svc.HasAction()
	// without a separate nil check after a successful return.
	var s *iamcatalog.Service
	assert.False(t, s.HasAction("anything"))
}

func TestCatalog_Lookup_InvalidURLInIndex(t *testing.T) {
	// If AWS ever serves a malformed URL in the index, the per-service fetch
	// must surface as ErrUnavailable, not panic.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		// Control character in URL: http.NewRequestWithContext rejects it.
		fmt.Fprintf(w, `[{"service":"s3","url":"http://example%c.test/"}]`, 0x01)
	})
	c := iamcatalog.New(srv.URL)
	_, err := c.Lookup(context.Background(), "s3")
	require.Error(t, err)
	assert.ErrorIs(t, err, iamcatalog.ErrUnavailable)
}

func TestErrors_AreDistinct(t *testing.T) {
	// Sanity: the sentinel errors must not alias each other; callers switch
	// on them to decide between "fail" and "skip".
	assert.False(t, errors.Is(iamcatalog.ErrUnknownService, iamcatalog.ErrUnavailable))
}
