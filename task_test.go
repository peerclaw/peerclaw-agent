package agent

import (
	"testing"

	"github.com/peerclaw/peerclaw-core/envelope"
	"github.com/peerclaw/peerclaw-core/protocol"
)

func TestTaskTracker_Submit(t *testing.T) {
	tt := NewTaskTracker()
	env := envelope.New("alice", "bob", protocol.ProtocolA2A, []byte("hello"))

	task := tt.Submit(env)

	if task.State != TaskSubmitted {
		t.Errorf("expected state submitted, got %s", task.State)
	}
	if task.TraceID != env.TraceID {
		t.Error("expected task TraceID to match envelope TraceID")
	}
	if task.AgentID != "bob" {
		t.Errorf("expected AgentID bob, got %s", task.AgentID)
	}
	if task.Request != env {
		t.Error("expected task Request to reference the envelope")
	}
	if task.Response != nil {
		t.Error("expected nil Response on submit")
	}
	if task.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestTaskTracker_Update(t *testing.T) {
	tt := NewTaskTracker()
	env := envelope.New("alice", "bob", protocol.ProtocolA2A, []byte("hello"))
	tt.Submit(env)

	resp := envelope.NewResponse(env, []byte("world"))
	tt.Update(env.TraceID, TaskCompleted, resp)

	task, ok := tt.Get(env.TraceID)
	if !ok {
		t.Fatal("expected task to exist")
	}
	if task.State != TaskCompleted {
		t.Errorf("expected state completed, got %s", task.State)
	}
	if task.Response != resp {
		t.Error("expected task Response to reference the response envelope")
	}
	if !task.UpdatedAt.After(task.CreatedAt) || task.UpdatedAt.Equal(task.CreatedAt) {
		// UpdatedAt should be >= CreatedAt
	}
}

func TestTaskTracker_Update_StateTransitions(t *testing.T) {
	tt := NewTaskTracker()
	env := envelope.New("alice", "bob", protocol.ProtocolA2A, []byte("hello"))
	tt.Submit(env)

	tt.Update(env.TraceID, TaskWorking, nil)
	task, _ := tt.Get(env.TraceID)
	if task.State != TaskWorking {
		t.Errorf("expected state working, got %s", task.State)
	}

	tt.Update(env.TraceID, TaskInputRequired, nil)
	task, _ = tt.Get(env.TraceID)
	if task.State != TaskInputRequired {
		t.Errorf("expected state input_required, got %s", task.State)
	}

	tt.Update(env.TraceID, TaskFailed, nil)
	task, _ = tt.Get(env.TraceID)
	if task.State != TaskFailed {
		t.Errorf("expected state failed, got %s", task.State)
	}
}

func TestTaskTracker_Get(t *testing.T) {
	tt := NewTaskTracker()

	// Non-existent task.
	_, ok := tt.Get("nonexistent")
	if ok {
		t.Error("expected ok=false for nonexistent task")
	}

	// Existing task.
	env := envelope.New("alice", "bob", protocol.ProtocolA2A, []byte("hello"))
	tt.Submit(env)

	task, ok := tt.Get(env.TraceID)
	if !ok {
		t.Error("expected ok=true for existing task")
	}
	if task.TraceID != env.TraceID {
		t.Error("expected matching TraceID")
	}
}

func TestTaskTracker_List(t *testing.T) {
	tt := NewTaskTracker()

	// Empty list.
	if len(tt.List()) != 0 {
		t.Error("expected empty list")
	}

	// Add tasks.
	env1 := envelope.New("alice", "bob", protocol.ProtocolA2A, []byte("1"))
	env2 := envelope.New("alice", "charlie", protocol.ProtocolA2A, []byte("2"))
	tt.Submit(env1)
	tt.Submit(env2)

	tasks := tt.List()
	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}
}

func TestTaskTracker_Remove(t *testing.T) {
	tt := NewTaskTracker()
	env := envelope.New("alice", "bob", protocol.ProtocolA2A, []byte("hello"))
	tt.Submit(env)

	tt.Remove(env.TraceID)

	_, ok := tt.Get(env.TraceID)
	if ok {
		t.Error("expected task to be removed")
	}
}

func TestTaskTracker_Update_Nonexistent(t *testing.T) {
	tt := NewTaskTracker()
	// Should not panic.
	tt.Update("nonexistent", TaskCompleted, nil)
}
