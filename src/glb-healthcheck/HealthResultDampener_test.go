package main

import "testing"

func performDampenedTest(t *testing.T, countBeforeHealthy int, countBeforeFailed int, src []bool, expected []bool) {
	dummy := make(HealthResultStream)
	go func() {
		for _, v := range src {
			dummy <- HealthResult{Healthy: v}
		}
		close(dummy)
	}()

	dampened := DampenedResultStream(dummy, countBeforeHealthy, countBeforeFailed)
	for i, exp := range expected {
		actual := <-dampened
		if actual.Healthy != exp {
			t.Errorf("Expected %v at index %d, got %v", exp, i, actual)
		}
	}
}

func TestDampenedResultStreamNoDampening(t *testing.T) {
	src_stream := []bool{true, false, true, false, true, false}
	out_stream := []bool{true, false, true, false, true, false}

	performDampenedTest(t, 1, 1, src_stream, out_stream)
}

func TestDampenedResultStreamImmediateHealthySlowFailure(t *testing.T) {
	src_stream := []bool{false, false, true, false, true, false, false, false, false, false, true, false}
	out_stream := []bool{false, false, true, true, true, true, true, false, false, false, true, true}

	performDampenedTest(t, 1, 3, src_stream, out_stream)
}

func TestDampenedResultStreamImmediateFailureSlowHealth(t *testing.T) {
	src_stream := []bool{true, true, false, true, false, true, true, true, true, true, false, true}
	out_stream := []bool{true, true, false, false, false, false, false, true, true, true, false, false}

	performDampenedTest(t, 3, 1, src_stream, out_stream)
}

func TestDampenedResultStreamSlowFailureSlowHealth(t *testing.T) {
	src_stream := []bool{false, false, true, false, true, false, false, false, false, false, true, false, true, true, true, true, true}
	out_stream := []bool{false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, true, true}

	performDampenedTest(t, 3, 3, src_stream, out_stream)

	src_stream = []bool{true, true, false, true, false, true, true, true, true, true, false, true, false, false, false, false, false}
	out_stream = []bool{true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, false, false}

	performDampenedTest(t, 3, 3, src_stream, out_stream)
}
