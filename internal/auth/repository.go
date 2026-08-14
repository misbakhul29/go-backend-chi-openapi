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
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
	UpdateUserRole(ctx context.Context, userID string, roleName string) error
	GetRoleByName(ctx context.Context, name string) (*models.Role, error)
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

func (r *AuthRepositoryImpl) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	var permissions []string
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		var user models.User
		if err := tx.Preload("Roles.Permissions").Where("id = ?", userID).First(&user).Error; err != nil {
			return err
		}
		seen := make(map[string]bool)
		for _, role := range user.Roles {
			for _, perm := range role.Permissions {
				if !seen[perm.Code] {
					seen[perm.Code] = true
					permissions = append(permissions, perm.Code)
				}
			}
		}
		return nil
	})
	return permissions, err
}

func (r *AuthRepositoryImpl) UpdateUserRole(ctx context.Context, userID string, roleName string) error {
	return db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		var user models.User
		if err := tx.Where("id = ?", userID).First(&user).Error; err != nil {
			return err
		}
		var role models.Role
		if err := tx.Where("name = ?", roleName).First(&role).Error; err != nil {
			return err
		}
		return tx.Model(&user).Association("Roles").Replace([]models.Role{role})
	})
}

func (r *AuthRepositoryImpl) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	err := db.WithTx(ctx, r.db, func(txCtx context.Context, tx *gorm.DB) error {
		return tx.Where("name = ?", name).First(&role).Error
	})
	if err != nil {
		return nil, err
	}
	return &role, nil
}
