package statsd

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// bufferedMetricContexts represent the contexts for Histograms, Distributions
// and Timing. Since those 3 metric types behave the same way and are sampled
// with the same type they're represented by the same class.
type bufferedMetricContexts struct {
	nbContext uint64
	mutex     sync.RWMutex
	values    bufferedMetricMap
	newMetric func(string, float64, string, float64, Cardinality) *bufferedMetric

	// Each bufferedMetricContexts uses its own random source and random
	// lock to prevent goroutines from contending for the lock on the
	// "math/rand" package-global random source (e.g. calls like
	// "rand.Float64()" must acquire a shared lock to get the next
	// pseudorandom number).
	random     *rand.Rand
	randomLock sync.Mutex
}

func newBufferedContexts(newMetric func(string, float64, string, int64, float64, Cardinality) *bufferedMetric, maxSamples int64) bufferedMetricContexts {
	return bufferedMetricContexts{
		values: bufferedMetricMap{},
		newMetric: func(name string, value float64, stringTags string, rate float64, cardinality Cardinality) *bufferedMetric {
			return newMetric(name, value, stringTags, maxSamples, rate, cardinality)
		},
		// Note that calling "time.Now().UnixNano()" repeatedly quickly may return
		// very similar values. That's fine for seeding the worker-specific random
		// source because we just need an evenly distributed stream of float values.
		// Do not use this random source for cryptographic randomness.
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (bc *bufferedMetricContexts) flush(metrics []metric) []metric {
	bc.mutex.Lock()
	values := bc.values
	bc.values = bufferedMetricMap{}
	bc.mutex.Unlock()

	for _, d := range values {
		d.Lock()
		metrics = append(metrics, d.flushUnsafe())
		d.Unlock()
	}
	atomic.AddUint64(&bc.nbContext, uint64(len(values)))
	return metrics
}

func (bc *bufferedMetricContexts) sample(name string, value float64, tags []string, rate float64, cardinality Cardinality) error {
	// For user-sampled metrics, return early when the sample is dropped. If we
	// keep it, the metric stores the first observed sampling rate. This matches
	// the existing behavior; correcting it would require tracking later rates
	// without adding contention on this hot path.
	// TODO: change this behavior in the future, probably by introducing
	// thread-local storage and lockless structures. If this early return is
	// removed, also remove the observed sampling rate in bufferedMetric and fix
	// bufferedMetric.flushUnsafe.
	if rate < 1 && !shouldSample(rate, bc.random, &bc.randomLock) {
		return nil
	}

	if len(tags) == 0 && cardinality == CardinalityNotSet {
		bc.mutex.RLock()
		v := bc.values[name]
		bc.mutex.RUnlock()
		if v != nil {
			v.maybeKeepSample(value, bc.random, &bc.randomLock)
			return nil
		}

		// Create it if it wasn't found
		bc.mutex.Lock()
		// It might have been created by another goroutine since last call
		v = bc.values[name]
		if v == nil {
			// If we might keep a sample that we should have skipped, but that should not drastically affect performances.
			bc.values[name] = bc.newMetric(name, value, "", rate, cardinality)
			// We added a new value, we need to unlock the mutex and quit
			bc.mutex.Unlock()
			return nil
		}
		bc.mutex.Unlock()

		// Now we can keep the sample.
		v.maybeKeepSample(value, bc.random, &bc.randomLock)

		return nil
	}

	cardString := cardinality.String()
	contextLen := getContextLength(name, tags, cardString)
	if contextLen <= smallContextBufferSize {
		var contextBuffer [smallContextBufferSize]byte
		return bc.sampleWithContextBuffer(contextBuffer[:0], name, value, tags, rate, cardinality, cardString)
	}
	return bc.sampleWithLargeContextBuffer(contextLen, name, value, tags, rate, cardinality, cardString)
}

// sampleWithLargeContextBuffer keeps the 4 KiB stack array out of sample's
// frame so the common small-context path is not penalized by the larger frame.
func (bc *bufferedMetricContexts) sampleWithLargeContextBuffer(contextLen int, name string, value float64, tags []string, rate float64, cardinality Cardinality, cardString string) error {
	if contextLen <= largeContextBufferSize {
		var contextBuffer [largeContextBufferSize]byte
		return bc.sampleWithContextBuffer(contextBuffer[:0], name, value, tags, rate, cardinality, cardString)
	}
	return bc.sampleWithContextBuffer(make([]byte, 0, contextLen), name, value, tags, rate, cardinality, cardString)
}

func (bc *bufferedMetricContexts) sampleWithContextBuffer(contextBuffer []byte, name string, value float64, tags []string, rate float64, cardinality Cardinality, cardString string) error {
	contextBuffer, tagsStart := appendContext(contextBuffer, name, tags, cardString)
	var v *bufferedMetric

	bc.mutex.RLock()
	v, _ = bc.values[string(contextBuffer)]
	bc.mutex.RUnlock()

	// Create it if it wasn't found
	if v == nil {
		bc.mutex.Lock()
		// It might have been created by another goroutine since last call
		v, _ = bc.values[string(contextBuffer)]
		if v == nil {
			// If we might keep a sample that we should have skipped, but that should not drastically affect performances.
			context := string(contextBuffer)
			stringTags := ""
			if tagsStart >= 0 {
				stringTags = context[tagsStart:]
			}
			bc.values[context] = bc.newMetric(name, value, stringTags, rate, cardinality)
			// We added a new value, we need to unlock the mutex and quit
			bc.mutex.Unlock()
			return nil
		}
		bc.mutex.Unlock()
	}

	// Now we can keep the sample.
	v.maybeKeepSample(value, bc.random, &bc.randomLock)

	return nil
}

func (bc *bufferedMetricContexts) getNbContext() uint64 {
	return atomic.LoadUint64(&bc.nbContext)
}
