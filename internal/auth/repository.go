package auth

import (
	"context"

	"github.com/misbakhul29/backend-framework/pkg/db/models"
	"gorm.io/gorm"
)

type AuthRepository interface {
	GetUserByEmail(ctx context.Context, tx *gorm.DB, email string) (*models.User, error)
	GetUserByID(ctx context.Context, tx *gorm.DB, id string) (*models.User, error)
	GetAccountByUserIDAndProvider(ctx context.Context, tx *gorm.DB, userID string, providerID string) (*models.Account, error)
	CreateUser(ctx context.Context, tx *gorm.DB, user *models.User) error
	CreateAccount(ctx context.Context, tx *gorm.DB, account *models.Account) error
	CreateSession(ctx context.Context, tx *gorm.DB, session *models.Session) error
}

type AuthRepositoryImpl struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *AuthRepositoryImpl {
	return &AuthRepositoryImpl{db: db}
}

func (r *AuthRepositoryImpl) getDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx.WithContext(ctx)
	}
	return r.db.WithContext(ctx)
}

func (r *AuthRepositoryImpl) GetUserByEmail(ctx context.Context, tx *gorm.DB, email string) (*models.User, error) {
	var user models.User
	err := r.getDB(ctx, tx).Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) GetUserByID(ctx context.Context, tx *gorm.DB, id string) (*models.User, error) {
	var user models.User
	err := r.getDB(ctx, tx).Where("id = ?", id).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *AuthRepositoryImpl) GetAccountByUserIDAndProvider(ctx context.Context, tx *gorm.DB, userID string, providerID string) (*models.Account, error) {
	var account models.Account
	err := r.getDB(ctx, tx).Where("user_id = ? AND provider_id = ?", userID, providerID).First(&account).Error
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *AuthRepositoryImpl) CreateUser(ctx context.Context, tx *gorm.DB, user *models.User) error {
	return r.getDB(ctx, tx).Create(user).Error
}

func (r *AuthRepositoryImpl) CreateAccount(ctx context.Context, tx *gorm.DB, account *models.Account) error {
	return r.getDB(ctx, tx).Create(account).Error
}

func (r *AuthRepositoryImpl) CreateSession(ctx context.Context, tx *gorm.DB, session *models.Session) error {
	return r.getDB(ctx, tx).Create(session).Error
}
