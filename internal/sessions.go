package internal

import "context"

type Session struct{}

type SessionStore interface {
	Create(ctx context.Context, session *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	Update(ctx context.Context, session *Session) error
	Delete(ctx context.Context, id string) error
	DeleteAllForUser(ctx context.Context, userID string) error
}
