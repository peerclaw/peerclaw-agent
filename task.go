package agent

import (
	"sync"
	"time"

	"github.com/peerclaw/peerclaw-core/envelope"
)

// TaskState represents the lifecycle state of an A2A task.
type TaskState string

const (
	TaskSubmitted     TaskState = "submitted"
	TaskWorking       TaskState = "working"
	TaskCompleted     TaskState = "completed"
	TaskFailed        TaskState = "failed"
	TaskCanceled      TaskState = "canceled"
	TaskInputRequired TaskState = "input_required"
)

// Task maps an Envelope request-response exchange to an A2A task lifecycle.
type Task struct {
	ID        string
	TraceID   string
	AgentID   string // destination agent
	State     TaskState
	Request   *envelope.Envelope
	Response  *envelope.Envelope // terminal response (nil until completed/failed)
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TaskTracker manages the lifecycle of tasks keyed by TraceID.
type TaskTracker struct {
	mu    sync.RWMutex
	tasks map[string]*Task
}

// NewTaskTracker creates an empty TaskTracker.
func NewTaskTracker() *TaskTracker {
	return &TaskTracker{
		tasks: make(map[string]*Task),
	}
}

// Submit creates a new task in Submitted state from an outgoing request envelope.
func (tt *TaskTracker) Submit(env *envelope.Envelope) *Task {
	now := time.Now()
	t := &Task{
		ID:        env.ID,
		TraceID:   env.TraceID,
		AgentID:   env.Destination,
		State:     TaskSubmitted,
		Request:   env,
		CreatedAt: now,
		UpdatedAt: now,
	}
	tt.mu.Lock()
	tt.tasks[env.TraceID] = t
	tt.mu.Unlock()
	return t
}

// Update transitions a task to a new state with an optional response envelope.
func (tt *TaskTracker) Update(traceID string, state TaskState, resp *envelope.Envelope) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	t, ok := tt.tasks[traceID]
	if !ok {
		return
	}
	t.State = state
	t.UpdatedAt = time.Now()
	if resp != nil {
		t.Response = resp
	}
}

// Get returns a task by its TraceID.
func (tt *TaskTracker) Get(traceID string) (*Task, bool) {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	t, ok := tt.tasks[traceID]
	return t, ok
}

// List returns all tracked tasks.
func (tt *TaskTracker) List() []*Task {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	tasks := make([]*Task, 0, len(tt.tasks))
	for _, t := range tt.tasks {
		tasks = append(tasks, t)
	}
	return tasks
}

// Remove deletes a task by its TraceID.
func (tt *TaskTracker) Remove(traceID string) {
	tt.mu.Lock()
	delete(tt.tasks, traceID)
	tt.mu.Unlock()
}
