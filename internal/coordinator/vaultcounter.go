package coordinator

import (
	"context"
	"errors"
	"fmt"

	"github.com/fount-labs/fount-mail-vault/wire"
)

// WireCounter is the VaultCounter of the Cloud vault pair, POST
// /coordinator/counter (fount-mail-vault docs/COORDINATOR-COUNTER.md). Every
// answer it acts on is signed by the generation authority over its own
// fresh nonce, so nobody between it and the vaults can fake a count or a
// refusal; anything unsigned is the vaults being unavailable, which the
// caller retries.
type WireCounter struct {
	Client *wire.CounterClient
	// Gen is this process's generation, whose key signs its swaps; nil in a
	// restore dry run, which only loads.
	Gen *FixedGeneration
}

func (c *WireCounter) Load(ctx context.Context) (VaultCount, error) {
	st, err := c.Client.Load(ctx)
	if err != nil {
		return VaultCount{}, counterError(err)
	}
	return VaultCount{Generation: st.Generation, Count: st.Count}, nil
}

func (c *WireCounter) CompareAndSwap(ctx context.Context, generation, prev, next uint64) error {
	if c.Gen == nil {
		return errors.New("a restore dry run has no generation, so it moves no count")
	}
	if generation != c.Gen.G.Number {
		return fmt.Errorf("a swap under generation %d from generation %d's process", generation, c.Gen.G.Number)
	}
	_, err := c.Client.CompareAndSwap(ctx, c.Gen.G.Key, generation, prev, next)
	return counterError(err)
}

// counterError gives a signed refusal its meaning here, which retires the
// coordinator; anything else stays an error to retry.
func counterError(err error) error {
	var refusal *wire.CounterRefusal
	switch {
	case err == nil:
		return nil
	case !errors.As(err, &refusal):
		return err
	case errors.Is(err, wire.ErrCounterCount):
		return fmt.Errorf("%w: %v", ErrVaultCount, err)
	default:
		return fmt.Errorf("%w: %v", ErrVaultGeneration, err)
	}
}
