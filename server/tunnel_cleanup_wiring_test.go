package server

import (
	"context"
	"reflect"
	"testing"
)

// 资源生命周期专项:任务停止路径(Engine.StopTask,删除/归档共用)必须按任务
// 回收隧道(tunnel.Manager.Cleanup 此前零调用方,是最大缺口)。
func TestStopTaskCleansUpTunnels(t *testing.T) {
	m := &Manager{}
	var cleaned []int64
	closeAll := false
	m.SetTunnelHooks(
		func(ctx context.Context, taskID int64) { cleaned = append(cleaned, taskID) },
		func(ctx context.Context) { closeAll = true },
	)
	e := NewEngine(m)
	e.StopTask("42")
	if !reflect.DeepEqual(cleaned, []int64{42}) {
		t.Fatalf("StopTask 应按任务回收隧道一次,实际 cleaned=%v", cleaned)
	}
	if closeAll {
		t.Fatal("StopTask 只收本任务,不应触发全量 Close")
	}

	// 幂等:再次 StopTask 再收一次(底层 tunnel.Cleanup 对 stopped 行跳过)。
	e.StopTask("42")
	if !reflect.DeepEqual(cleaned, []int64{42, 42}) {
		t.Fatalf("重复 StopTask 应重复尝试回收(幂等),实际 cleaned=%v", cleaned)
	}
}

// 非数字 taskID(防御):不解析成功就不回收,也不 panic。
func TestStopTaskNonNumericIDSkipsTunnelCleanup(t *testing.T) {
	m := &Manager{}
	calls := 0
	m.SetTunnelHooks(func(ctx context.Context, taskID int64) { calls++ }, nil)
	e := NewEngine(m)
	e.StopTask("not-a-number")
	if calls != 0 {
		t.Fatalf("非数字 taskID 不应触发隧道回收,实际 %d 次", calls)
	}
}

// 未注入钩子(隧道子系统未启用,如 DB 未就绪)时 StopTask 正常工作。
func TestStopTaskWithoutTunnelHooks(t *testing.T) {
	e := NewEngine(&Manager{})
	e.StopTask("7") // 不 panic 即通过
}
