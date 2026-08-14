package auth

import (
	"context"

	"github.com/misbakhul29/backend-framework/pkg/db"
	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"gorm.io/gorm"
)

type AuthRepository interface {
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetAccountByUserIDAndProvider(ctx context.Context, userID string, providerID string) (*models.Account, error)
	CreateUser(ctx context.Context, user *models.User) error
	CreateAccount(ctx context.Context, account *models.Account) error
	CreateSession(ctx context.Context, session *models.Session) error
	DeleteSession(ctx context.Context, sessionID string) error
}

type AuthRepositoryImpl struct {
	db *gorm.DB
}

func NewRepository(dbClient *gorm.DB) *AuthRepositoryImpl {
	return &AuthRepositoryImpl{db: dbClient}
}

func (r *AuthRepositoryImpl) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("email = ?", email).First(&user).Error
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("id = ?", id).First(&user).Error
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) GetAccountByUserIDAndProvider(ctx context.Context, userID string, providerID string) (*models.Account, error) {
	var account models.Account
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("user_id = ? AND provider_id = ?", userID, providerID).First(&account).Error
	})
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *AuthRepositoryImpl) CreateUser(ctx context.Context, user *models.User) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(user).Error
	})
}

func (r *AuthRepositoryImpl) CreateAccount(ctx context.Context, account *models.Account) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(account).Error
	})
}

func (r *AuthRepositoryImpl) CreateSession(ctx context.Context, session *models.Session) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Create(session).Error
	})
}

func (r *AuthRepositoryImpl) DeleteSession(ctx context.Context, sessionID string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Delete(&models.Session{}, "id = ?", sessionID).Error
	})
}
