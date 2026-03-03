package dispatchers

import (
	"context"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/breakers"
	"github.com/stretchr/testify/assert"
)

func TestSequential_WithNilBreaker_DispatchesAllPolicies(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1", "p2", "p3"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "config", 42)

	var collected int
	collector := &countCollector{n: &collected}

	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, _ string, _ int) bool { return true })
	}

	factory := Sequential(evaluator, nil)
	assert.NotNil(t, factory)

	dispatcher := factory(ctx, fctx, collector)
	assert.NotNil(t, dispatcher)

	dispatcher.Dispatch(ctx, 42)
	assert.Equal(t, 3, collected, "nil breaker should not break; all 3 policies dispatched")
}

func TestSequential_WithNeverBreaker_DispatchesAllPolicies(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"a", "b"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "data", 0)

	var collected int
	collector := &countCollector{n: &collected}

	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, _ string, _ int) bool { return false })
	}
	breaker := breakers.NeverFactory[string, string, int, bool]()

	factory := Sequential(evaluator, breaker)
	dispatcher := factory(ctx, fctx, collector)

	dispatcher.Dispatch(ctx, 0)
	assert.Equal(t, 2, collected)
}

func TestSequential_WithBreakingBreaker_StopsEarly(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1", "p2", "p3"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "config", 10)

	var collected int
	collector := &countCollector{n: &collected}

	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, _ string, in int) bool { return in > 0 })
	}
	// Break after first collect (break when out is true; we'll make evaluator return true on first call)
	breaker := func(context.Context, core.FactoryContext[string, string, int]) core.Breaker[string, int, bool] {
		return core.MakeBreakerFunc(func(_ context.Context, _ string, _ int, out bool) bool { return out })
	}

	factory := Sequential(evaluator, breaker)
	dispatcher := factory(ctx, fctx, collector)

	dispatcher.Dispatch(ctx, 10)
	assert.Equal(t, 1, collected, "breaker returns true after first out=true; should stop after 1 collect")
}

func TestSequential_CollectorReceivesEvaluatorOutput(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1", "p2"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "config", 7)

	var items []collectItem
	collector := &sliceCollector{items: &items}

	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, policy string, in int) bool {
			return policy == "p1" && in == 7
		})
	}

	factory := Sequential(evaluator, nil)
	dispatcher := factory(ctx, fctx, collector)
	dispatcher.Dispatch(ctx, 7)

	assert.Len(t, items, 2)
	assert.Equal(t, "p1", items[0].policy)
	assert.Equal(t, 7, items[0].in)
	assert.True(t, items[0].out)
	assert.Equal(t, "p2", items[1].policy)
	assert.Equal(t, 7, items[1].in)
	assert.False(t, items[1].out)
}

func TestSequential_EmptyPolicies_CollectsNothing(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "config", 0)

	var collected int
	collector := &countCollector{n: &collected}

	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, _ string, _ int) bool { return true })
	}

	factory := Sequential(evaluator, nil)
	dispatcher := factory(ctx, fctx, collector)
	dispatcher.Dispatch(ctx, 0)

	assert.Equal(t, 0, collected)
}

type countCollector struct {
	n *int
}

func (c *countCollector) Collect(_ context.Context, _ string, _ int, _ bool) {
	*c.n++
}

type collectItem struct {
	policy string
	in     int
	out    bool
}

type sliceCollector struct {
	items *[]collectItem
}

func (c *sliceCollector) Collect(_ context.Context, policy string, in int, out bool) {
	*c.items = append(*c.items, collectItem{policy, in, out})
}
