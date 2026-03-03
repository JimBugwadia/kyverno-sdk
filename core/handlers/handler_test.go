package handlers

import (
	"context"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestHandler_ReturnsNonNilFactory(t *testing.T) {
	dispatcher := func(context.Context, core.FactoryContext[string, string, int], core.Collector[string, int, bool]) core.Dispatcher[int] {
		return core.MakeDispatcherFunc(func(context.Context, int) {})
	}
	resulter := func(context.Context, core.FactoryContext[string, string, int]) core.Resulter[string, int, bool, string] {
		return &fixedResulter{result: "ok"}
	}
	factory := Handler(dispatcher, resulter)
	assert.NotNil(t, factory)
}

func TestHandler_Handle_InvokesDispatcherThenReturnsResulterResult(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "data", 0)

	var dispatchedWith *int
	dispatcher := func(context.Context, core.FactoryContext[string, string, int], core.Collector[string, int, bool]) core.Dispatcher[int] {
		return core.MakeDispatcherFunc(func(_ context.Context, in int) {
			dispatchedWith = &in
		})
	}
	resulter := func(context.Context, core.FactoryContext[string, string, int]) core.Resulter[string, int, bool, string] {
		return &fixedResulter{result: "done"}
	}

	factory := Handler(dispatcher, resulter)
	handler := factory(ctx, fctx)
	assert.NotNil(t, handler)

	got := handler.Handle(ctx, 42)
	assert.Equal(t, "done", got)
	assert.NotNil(t, dispatchedWith)
	assert.Equal(t, 42, *dispatchedWith)
}

func TestHandler_Handle_ResultReflectsDispatchedCollects(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1", "p2"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "config", 0)

	// Dispatcher that calls collector.Collect for two "policies" with fixed outputs
	dispatcher := func(_ context.Context, _ core.FactoryContext[string, string, int], collector core.Collector[string, int, bool]) core.Dispatcher[int] {
		return core.MakeDispatcherFunc(func(_ context.Context, in int) {
			collector.Collect(ctx, "p1", in, true)
			collector.Collect(ctx, "p2", in, false)
		})
	}
	// Resulter that collects (policy, in, out) and returns them as a slice
	resulterFactory := func(context.Context, core.FactoryContext[string, string, int]) core.Resulter[string, int, bool, []collectItem] {
		return &sliceResulter{items: []collectItem{}}
	}

	factory := Handler(dispatcher, resulterFactory)
	handler := factory(ctx, fctx)

	result := handler.Handle(ctx, 99)
	assert.Len(t, result, 2)
	assert.Equal(t, "p1", result[0].Policy)
	assert.Equal(t, 99, result[0].In)
	assert.True(t, result[0].Out)
	assert.Equal(t, "p2", result[1].Policy)
	assert.Equal(t, 99, result[1].In)
	assert.False(t, result[1].Out)
}

type fixedResulter struct {
	result string
}

func (r *fixedResulter) Collect(_ context.Context, _ string, _ int, _ bool) {}

func (r *fixedResulter) Result() string {
	return r.result
}

type collectItem struct {
	Policy string
	In     int
	Out    bool
}

type sliceResulter struct {
	items []collectItem
}

func (r *sliceResulter) Collect(_ context.Context, policy string, in int, out bool) {
	r.items = append(r.items, collectItem{Policy: policy, In: in, Out: out})
}

func (r *sliceResulter) Result() []collectItem {
	return r.items
}
